#!/usr/bin/env python3
"""
Air Alert Radar Hub - Backend Microservice (Multi-User, Persistent Target Tracking & Official Sirens)
Features:
- Multi-user isolation: Each user has their own API key and independent 5 slots.
- Both Home Assistant and ESP32 use the same user API key.
- Persistent Target Tracking: Targets tracked by original crypto UUID (~Zey...).
- Flight Path & Heat Trail: Keeps trajectory history and computes extrapolated forward cone (5/10/15 min).
- Track Crossing Safe: Multiple targets in the same area never swap or merge.
- Official Sirens Integration: Direct ingestion of /api/v2/data/mapUpdate (Oblasts, Raions, MiG-31K, Artillery).
- Offline Point-in-Polygon Oblast Detector (Ray-casting 2D).
- Built-in Dark Mode Web Admin Dashboard at /admin.
- Persistent JSON storage for Docker volume (/app/data/hub_config.json).
- Native ChaCha20 / XorShift Pure-Python decoder (32-bit ARMv7 compatible).
- Failover support for Neptun.in.ua.
"""

import asyncio
import base64
import http.cookiejar
import inspect
import json
import logging
import math
import os
import random
import re
import secrets
import struct
import sys
import time
import urllib.request
from aiohttp import web, WSMsgType
from oblast_detector import OblastDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("AirAlertHub")

# --- КОНФИГУРАЦИЯ ---
PORT = int(os.environ.get("PORT", 8088))
ADMIN_SECRET_KEY = os.environ.get("ADMIN_SECRET_KEY", "admin_super_secret_master_key_123").strip()
if not ADMIN_SECRET_KEY:
    ADMIN_SECRET_KEY = "admin_super_secret_master_key_123"
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
CONFIG_FILE = os.path.join(DATA_DIR, "hub_config.json")
DANGER_RADIUS_KM = float(os.environ.get("DANGER_RADIUS_KM", 35.0))
UPSTREAM_PROXY = os.environ.get("UPSTREAM_PROXY", "").strip()
oblast_detector = OblastDetector()

def mask_proxy(p_url: str) -> str:
    if not p_url: return "Прямое подключение (Без прокси)"
    try:
        import urllib.parse
        parsed = urllib.parse.urlsplit(p_url)
        host = parsed.hostname or parsed.netloc
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{host}{port}"
    except Exception: return "Настроен прокси"

# =====================================================================
# ХРАНИЛИЩЕ КОНФИГУРАЦИИ И ПОЛЬЗОВАТЕЛЕЙ (PERSISTENCE)
# =====================================================================

DEFAULT_USER_SLOTS = {}

DEFAULT_USER_SETTINGS = {
    "danger_radius_km": DANGER_RADIUS_KM, # 35.0 км по умолчанию
    "alert_threat": True,       # Физическая цель в зоне опасности (< danger_radius_km)
    "alert_siren": True,        # Официальная сирена в области выбранного слота
    "alert_mig": False,         # Взлет МиГ-31К / баллистическая угроза по всей стране
    "alert_artillery": False    # Артобстрел / РСЗО в районе выбранного слота
}

class StorageManager:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = {"users": {}}
        self.load()

    def _normalize_user(self, user: dict):
        """Гарантирует наличие словаря слотов, индивидуальных зон опасности и настроек алертов."""
        if "slots" not in user or not isinstance(user["slots"], dict):
            user["slots"] = {}
        if "settings" not in user or not isinstance(user["settings"], dict):
            user["settings"] = json.loads(json.dumps(DEFAULT_USER_SETTINGS))
        else:
            for k, v in DEFAULT_USER_SETTINGS.items():
                if k not in user["settings"]:
                    user["settings"][k] = v

        def_r = float(user["settings"].get("danger_radius_km", DANGER_RADIUS_KM))
        for slot in user["slots"].values():
            if "danger_radius_km" not in slot:
                slot["danger_radius_km"] = def_r

    def load(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        loaded = False
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
                    if "users" not in self.data or not isinstance(self.data["users"], dict):
                        self.data = {"users": {}}
                    logger.info(f"Загружено пользователей из базы: {len(self.data.get('users', {}))}")
                    loaded = True
            except Exception as e:
                logger.error(f"Ошибка чтения {self.filepath}: {e}")

        if not loaded:
            # ЧИСТАЯ БАЗА: никаких заготовок, при открытии всё пусто!
            self.data = {"users": {}}

        # Нормализация всех пользователей
        for u in self.data.get("users", {}).values():
            self._normalize_user(u)

        # Гарантия сохранения ключей из переменной окружения INITIAL_USERS (если задана)
        # Формат: "Муж:ak_my_key1,Жена:ak_my_key2"
        init_users_env = os.environ.get("INITIAL_USERS", "").strip()
        if init_users_env:
            for pair in init_users_env.split(","):
                if ":" in pair:
                    p_name, p_key = pair.split(":", 1)
                    p_name = p_name.strip()
                    p_key = p_key.strip()
                    if p_key and p_key not in self.data.setdefault("users", {}):
                        self.data["users"][p_key] = {
                            "id": f"usr_{secrets.token_hex(4)}",
                            "api_key": p_key,
                            "owner": p_name,
                            "enabled": True,
                            "created_at": int(time.time()),
                            "last_used_at": 0,
                            "slots": {},
                            "settings": json.loads(json.dumps(DEFAULT_USER_SETTINGS))
                        }
                        logger.info(f"Добавлен ключ из INITIAL_USERS: {p_name} ({p_key})")

        self.save()

    def save(self):
        tmp_file = self.filepath + f".tmp.{os.getpid()}"
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_file, self.filepath)
        except Exception as e:
            logger.error(f"Ошибка сохранения {self.filepath}: {e}")
            if os.path.exists(tmp_file):
                try: os.remove(tmp_file)
                except Exception: pass

    def get_user_by_key(self, api_key: str):
        user = self.data["users"].get(api_key)
        if user and user.get("enabled", True):
            self._normalize_user(user)
            user["last_used_at"] = int(time.time())
            return user
        return None

    def create_user(self, owner_name: str, custom_key: str = None) -> dict:
        key = custom_key.strip() if custom_key else f"ak_{secrets.token_hex(12)}"
        user_id = f"usr_{secrets.token_hex(4)}"
        new_user = {
            "id": user_id,
            "api_key": key,
            "owner": owner_name,
            "enabled": True,
            "created_at": int(time.time()),
            "last_used_at": 0,
            "slots": {},
            "settings": json.loads(json.dumps(DEFAULT_USER_SETTINGS))
        }
        self.data["users"][key] = new_user
        self.save()
        return new_user

    def update_user(self, api_key: str, owner_name: str = None, enabled: bool = None) -> bool:
        user = self.data["users"].get(api_key)
        if not user: return False
        if owner_name is not None: user["owner"] = owner_name
        if enabled is not None: user["enabled"] = bool(enabled)
        self.save()
        return True

    def update_user_settings(self, api_key: str, settings_update: dict) -> dict:
        user = self.data["users"].get(api_key)
        if not user: return None
        self._normalize_user(user)
        s = user["settings"]
        radius_val = None
        if "danger_radius_km" in settings_update:
            try:
                val = float(settings_update["danger_radius_km"])
                if 1.0 <= val <= 500.0:
                    s["danger_radius_km"] = round(val, 1)
                    radius_val = round(val, 1)
            except (ValueError, TypeError):
                pass
        if "alert_threat" in settings_update:
            s["alert_threat"] = bool(settings_update["alert_threat"])
        if "alert_siren" in settings_update:
            s["alert_siren"] = bool(settings_update["alert_siren"])
        if "alert_mig" in settings_update:
            s["alert_mig"] = bool(settings_update["alert_mig"])
        if "alert_artillery" in settings_update:
            s["alert_artillery"] = bool(settings_update["alert_artillery"])

        # Опционально: применить радиус ко всем слотам этого пользователя
        if radius_val is not None and settings_update.get("apply_to_all_slots"):
            for slot in user["slots"].values():
                slot["danger_radius_km"] = radius_val

        self.save()
        return s

    def delete_user(self, api_key: str) -> bool:
        if api_key in self.data["users"]:
            del self.data["users"][api_key]
            self.save()
            return True
        return False

    def create_slot(self, api_key: str, name: str, lat: float, lon: float, danger_radius_km: float = None, slot_type: str = "static", custom_id: str = None) -> tuple:
        user = self.data["users"].get(api_key)
        if not user: return None, "user_not_found"
        self._normalize_user(user)

        if len(user["slots"]) >= 5:
            return None, "limit_reached"

        # Находим свободный ID слота от "1" до "5"
        if custom_id and str(custom_id) in ("1", "2", "3", "4", "5") and str(custom_id) not in user["slots"]:
            s_id = str(custom_id)
        else:
            s_id = None
            for sid in ("1", "2", "3", "4", "5"):
                if sid not in user["slots"]:
                    s_id = sid
                    break
        if not s_id:
            return None, "limit_reached"

        def_r = float(user["settings"].get("danger_radius_km", DANGER_RADIUS_KM))
        r_val = def_r
        if danger_radius_km is not None:
            try:
                v = float(danger_radius_km)
                if 1.0 <= v <= 500.0:
                    r_val = round(v, 1)
            except (ValueError, TypeError): pass

        new_slot = {
            "id": s_id,
            "name": name.strip() if (name and name.strip()) else f"Точка #{s_id}",
            "lat": float(lat),
            "lon": float(lon),
            "type": slot_type if slot_type in ("static", "dynamic") else "static",
            "danger_radius_km": r_val
        }
        if new_slot["type"] == "dynamic":
            new_slot["updated_at"] = int(time.time())
            new_slot["accuracy_m"] = 0.0

        user["slots"][s_id] = new_slot
        self.save()
        return new_slot, "created"

    def delete_slot(self, api_key: str, slot_id: str) -> bool:
        user = self.data["users"].get(api_key)
        if not user or str(slot_id) not in user.get("slots", {}):
            return False
        del user["slots"][str(slot_id)]
        self.save()
        return True

    def update_slot(self, api_key: str, slot_id: str, name: str = None, lat: float = None, lon: float = None, danger_radius_km: float = None) -> dict:
        user = self.data["users"].get(api_key)
        if not user or str(slot_id) not in user.get("slots", {}):
            return None
        self._normalize_user(user)
        slot = user["slots"][str(slot_id)]
        if name: slot["name"] = name.strip()
        if lat is not None: slot["lat"] = float(lat)
        if lon is not None: slot["lon"] = float(lon)
        if danger_radius_km is not None:
            try:
                val = float(danger_radius_km)
                if 1.0 <= val <= 500.0:
                    slot["danger_radius_km"] = round(val, 1)
            except (ValueError, TypeError):
                pass
        self.save()
        return slot

    def update_dynamic_slot(self, api_key: str, lat: float, lon: float, name: str = None, accuracy_m: float = 0.0, danger_radius_km: float = None) -> dict:
        user = self.data["users"].get(api_key)
        if not user: return None
        self._normalize_user(user)

        dyn_slot = None
        for s in user["slots"].values():
            if s.get("type") == "dynamic":
                dyn_slot = s
                break

        if not dyn_slot:
            if len(user["slots"]) >= 5:
                if "5" in user["slots"]:
                    dyn_slot = user["slots"]["5"]
                    dyn_slot["type"] = "dynamic"
                else:
                    return None
            else:
                for sid in ("5", "1", "2", "3", "4"):
                    if sid not in user["slots"]:
                        s_id = sid
                        break
                dyn_slot = {
                    "id": s_id,
                    "name": name or "Динамический GPS",
                    "lat": float(lat),
                    "lon": float(lon),
                    "type": "dynamic",
                    "updated_at": int(time.time()),
                    "accuracy_m": float(accuracy_m),
                    "danger_radius_km": danger_radius_km or float(user.get("settings", {}).get("danger_radius_km", DANGER_RADIUS_KM))
                }
                user["slots"][s_id] = dyn_slot
                self.save()
                return dyn_slot

        dyn_slot["lat"] = float(lat)
        dyn_slot["lon"] = float(lon)
        dyn_slot["updated_at"] = int(time.time())
        dyn_slot["accuracy_m"] = float(accuracy_m)
        if name: dyn_slot["name"] = name.strip()
        if danger_radius_km is not None:
            try:
                val = float(danger_radius_km)
                if 1.0 <= val <= 500.0:
                    dyn_slot["danger_radius_km"] = round(val, 1)
            except (ValueError, TypeError):
                pass
        self.save()
        return dyn_slot

storage = StorageManager(CONFIG_FILE)

# =====================================================================
# ГЕОМЕТРИЯ: HAVERSINE, BEARING, ПОЛЯРНЫЕ КООРДИНАТЫ
# =====================================================================

def calculate_haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2.0) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2.0) ** 2)
    return 2.0 * R * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))

def calculate_bearing(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_lambda = math.radians(lon2 - lon1)
    y = math.sin(delta_lambda) * math.cos(phi2)
    x = math.cos(phi1) * math.sin(phi2) - math.sin(phi1) * math.cos(phi2) * math.cos(delta_lambda)
    return (math.degrees(math.atan2(y, x)) + 360.0) % 360.0

def bearing_to_compass(deg: float) -> str:
    sectors = ["С (N)", "СВ (NE)", "В (E)", "ЮВ (SE)", "Ю (S)", "ЮЗ (SW)", "З (W)", "СЗ (NW)"]
    return sectors[int((deg + 22.5) // 45) % 8]

# =====================================================================
# РЕЕСТР ТИПОВ ВОЗДУШНЫХ ЦЕЛЕЙ, ПИКТОГРАММЫ И АВТО-ОБНАРУЖЕНИЕ
# =====================================================================

TARGET_METADATA = {
    "shahed": {
        "name_ua": "Шахед",
        "name_en": "Shahed",
        "ha_icon": "mdi:navigation-variant",
        "esp_code": 1,
        "default_speed": 185.0,
        "is_drone": True,
        "color_hex": "#FACC15"
    },
    "shahed_jet": {
        "name_ua": "Реактивний шахед",
        "name_en": "Jet-powered Shahed",
        "ha_icon": "mdi:rocket-outline",
        "esp_code": 2,
        "default_speed": 380.0,
        "is_drone": True,
        "color_hex": "#00E5FF"
    },
    "missile": {
        "name_ua": "Ракета",
        "name_en": "Missile",
        "ha_icon": "mdi:rocket",
        "esp_code": 3,
        "default_speed": 850.0,
        "is_drone": False,
        "color_hex": "#EF4444"
    },
    "banderol": {
        "name_ua": "Бандероль",
        "name_en": "Banderol",
        "ha_icon": "mdi:paper-plane-outline",
        "esp_code": 4,
        "default_speed": 150.0,
        "is_drone": True,
        "color_hex": "#A7F3D0"
    },
    "kab": {
        "name_ua": "КАБ",
        "name_en": "Guided aerial bomb",
        "ha_icon": "mdi:bomb",
        "esp_code": 5,
        "default_speed": 750.0,
        "is_drone": False,
        "color_hex": "#FB923C"
    },
    "recon": {
        "name_ua": "Розвідник",
        "name_en": "Reconnaissance UAV",
        "ha_icon": "mdi:crosshairs-gps",
        "esp_code": 6,
        "default_speed": 130.0,
        "is_drone": True,
        "color_hex": "#A855F7"
    },
    "fpv": {
        "name_ua": "FPV-дрон",
        "name_en": "FPV drone",
        "ha_icon": "mdi:quadcopter",
        "esp_code": 7,
        "default_speed": 120.0,
        "is_drone": True,
        "color_hex": "#F43F5E"
    },
    "unknown": {
        "name_ua": "Ціль не визначена",
        "name_en": "Unidentified target",
        "ha_icon": "mdi:help-rhombus",
        "esp_code": 0,
        "default_speed": 200.0,
        "is_drone": True,
        "color_hex": "#94A3B8"
    }
}

UNKNOWN_TARGET_TYPES_CATALOG = {}

def classify_target(raw_type: str, raw_code: int = 0) -> tuple[str, dict]:
    """
    Классифицирует цель по сырому имени или коду.
    Если обнаружен новый, ранее неизвестный тип цели, регистрирует его в каталоге и логирует предупреждение.
    """
    s = (raw_type or "").lower().strip()

    if "banderol" in s or "бандероль" in s or s == "ic_banderol" or "decoy" in s:
        return "banderol", TARGET_METADATA["banderol"]

    if ("jet" in s and "shahed" in s) or "реактив" in s or s in ("ic_shahed_jet", "ic_shahed_jet_mesh", "uav_jet"):
        return "shahed_jet", TARGET_METADATA["shahed_jet"]

    if "shahed" in s or "шахед" in s or s in ("ic_shahed", "ic_shahed_mesh"):
        return "shahed", TARGET_METADATA["shahed"]

    if "kab" in s or "каб" in s or "airbomb" in s or s == "ic_airbomb":
        return "kab", TARGET_METADATA["kab"]

    if "missile" in s or "ракета" in s or "ballistic" in s or "баліст" in s or "kinzhal" in s or s in ("ic_missile", "ic_ballistic") or raw_code in (3, 100, 101, 102, 103, 104, 105, 106, 107):
        return "missile", TARGET_METADATA["missile"]

    if "fpv" in s:
        return "fpv", TARGET_METADATA["fpv"]

    if any(k in s for k in ("zala", "supercam", "lancet", "mohajer", "recon", "розвід", "ланцет")):
        return "recon", TARGET_METADATA["recon"]

    if s in ("ic_air_threat_combined_white", "ic_asterix_plane_stroke", "ic_asterix_plane_masked", "unknown", "ціль не визначена", "не визначена") or raw_code in (116, 200):
        return "unknown", TARGET_METADATA["unknown"]

    if "drone" in s or "бпла" in s or "uav" in s or raw_code in (8, 11):
        return "shahed", TARGET_METADATA["shahed"]

    # Авто-регистрация нового или неизвестного типа цели
    key = raw_type or f"code_{raw_code}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if key not in UNKNOWN_TARGET_TYPES_CATALOG:
        UNKNOWN_TARGET_TYPES_CATALOG[key] = {
            "type_identifier": key,
            "raw_code": raw_code,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "count": 1
        }
        logger.warning(f"⚠️ [NEW_TARGET_TYPE_DETECTED] Upstream returned new threat type: '{key}' (code={raw_code}). Registered in unknown types catalog.")
    else:
        UNKNOWN_TARGET_TYPES_CATALOG[key]["last_seen"] = now_iso
        UNKNOWN_TARGET_TYPES_CATALOG[key]["count"] += 1

    return "unknown", TARGET_METADATA["unknown"]

# =====================================================================
# СОПРОВОЖДЕНИЕ ЦЕЛЕЙ (PERSISTENT TRACKER & HEAT TRAIL)
# =====================================================================

class TargetTrack:
    """Одиночная воздушная цель с историей траектории и прогнозом движения."""
    def __init__(self, target_id: str, t_type: str, raw_code: int, lat: float, lon: float,
                 heading: float, speed_kmh: float, oblast: str, oblast_id: str):
        self.id = target_id
        self.raw_type = t_type
        self.raw_code = raw_code
        cat, meta = classify_target(t_type, raw_code)
        self.category = cat
        self.type = meta["name_ua"]
        self.type_en = meta["name_en"]
        self.ha_icon = meta["ha_icon"]
        self.esp_code = meta["esp_code"]
        self.color_hex = meta["color_hex"]
        self.is_drone = meta["is_drone"]
        self.lat = lat
        self.lon = lon
        self.heading = heading
        self.speed_kmh = speed_kmh if (speed_kmh and speed_kmh > 0) else meta["default_speed"]
        self.oblast = oblast
        self.oblast_id = oblast_id
        self.first_seen = time.time()
        self.last_seen = time.time()
        # История точек для построения теплового следа / пройденного пути
        self.trajectory = [{"lat": round(lat, 5), "lon": round(lon, 5), "ts": int(self.last_seen)}]

    def update(self, lat: float, lon: float, heading: float, speed_kmh: float, oblast: str, oblast_id: str, t_type: str = None, raw_code: int = None):
        now = time.time()
        last_pt = self.trajectory[-1]
        dist_from_last = calculate_haversine_distance(last_pt["lat"], last_pt["lon"], lat, lon)

        # Добавляем точку в трек при смещении > 300 м или раз в 10 секунд
        if dist_from_last > 0.3 or (now - last_pt["ts"]) >= 10.0:
            self.trajectory.append({"lat": round(lat, 5), "lon": round(lon, 5), "ts": int(now)})
            if len(self.trajectory) > 30: # храним до 30 последних точек
                self.trajectory.pop(0)

        if t_type and t_type != self.raw_type:
            self.raw_type = t_type
            if raw_code is not None: self.raw_code = raw_code
            cat, meta = classify_target(t_type, self.raw_code)
            self.category = cat
            self.type = meta["name_ua"]
            self.type_en = meta["name_en"]
            self.ha_icon = meta["ha_icon"]
            self.esp_code = meta["esp_code"]
            self.color_hex = meta["color_hex"]
            self.is_drone = meta["is_drone"]

        self.lat = lat
        self.lon = lon
        # Вычисляем точный динамический курс по фактическому перемещению (0..360° без грубого 90° округления)
        if dist_from_last > 0.2:
            self.heading = round(calculate_bearing(last_pt["lat"], last_pt["lon"], lat, lon), 1)
        elif heading is not None and heading > 0:
            self.heading = round(float(heading), 1)
        if speed_kmh and speed_kmh > 0:
            self.speed_kmh = speed_kmh
        self.oblast = oblast
        self.oblast_id = oblast_id
        self.last_seen = now

    def get_extrapolated_corridor(self, minutes=(5, 10, 15)) -> list:
        """Экстраполирует движение цели вперед по курсу и скорости (коридор прогноза)."""
        corridor = []
        R = 6371.0
        phi1 = math.radians(self.lat)
        lambda1 = math.radians(self.lon)
        brng = math.radians(self.heading)

        for m in minutes:
            d = (self.speed_kmh * (m / 60.0))
            phi2 = math.asin(math.sin(phi1) * math.cos(d / R) + math.cos(phi1) * math.sin(d / R) * math.cos(brng))
            lambda2 = lambda1 + math.atan2(math.sin(brng) * math.sin(d / R) * math.cos(phi1), math.cos(d / R) - math.sin(phi1) * math.sin(phi2))
            corridor.append({
                "minutes_ahead": m,
                "lat": round(math.degrees(phi2), 5),
                "lon": round(math.degrees(lambda2), 5)
            })
        return corridor


# =====================================================================
# МЕНЕДЖЕР ІСТОРІЇ ПОЛЬОТІВ (ПОМІСЯЧНІ АРХІВИ, ЗАХИСТ SD-КАРТКИ ВІД ЗНОСУ)
# =====================================================================

class HistoryManager:
    """Збереження та надання історії польотів за місяцями та днями."""
    def __init__(self, data_dir: str):
        self.history_dir = os.path.join(data_dir, "history")
        os.makedirs(self.history_dir, exist_ok=True)
        self.active_tracks = {} # tid -> entry
        self.dirty_months = set()
        self.last_flush_ts = time.time()
        self.flush_interval = 300.0 # 5 хвилин між скиданнями на диск для збереження ресурсу SD-карти
        self._cache = {} # month_str -> full dict

    def update_point(self, trk):
        now = time.time()
        tid = trk.id
        dt_str = time.strftime("%Y-%m-%d", time.gmtime(trk.first_seen))
        month_str = dt_str[:7]

        if tid not in self.active_tracks:
            self.active_tracks[tid] = {
                "id": tid,
                "cat": trk.category,
                "name_ua": trk.type,
                "raw_type": getattr(trk, "raw_type", ""),
                "status": "active",
                "date": dt_str,
                "start_time": int(trk.first_seen),
                "end_time": int(now),
                "path": []
            }

        entry = self.active_tracks[tid]
        entry["end_time"] = int(now)

        lat = round(trk.lat, 4)
        lon = round(trk.lon, 4)
        heading = round(trk.heading, 1)
        speed = round(trk.speed_kmh, 1)

        # Тонке стиснення: не дублювати нерухомі або занадто часті точки
        if entry["path"]:
            last = entry["path"][-1]
            if abs(lat - last[1]) < 0.0002 and abs(lon - last[2]) < 0.0002 and (now - last[0]) < 5.0:
                return

        entry["path"].append([int(now), lat, lon, heading, speed])
        self.dirty_months.add(month_str)

    def finish_track(self, trk, status="lost"):
        tid = trk.id
        now = time.time()
        if tid in self.active_tracks:
            entry = self.active_tracks[tid]
            entry["status"] = status
            entry["end_time"] = int(now)
            month_str = entry["date"][:7]
            self._commit_to_month(entry, month_str)
            del self.active_tracks[tid]
            self.dirty_months.add(month_str)

    def _commit_to_month(self, entry, month_str):
        m_data = self._load_month_data(month_str)
        m_data["targets"][entry["id"]] = entry
        if entry["date"] not in m_data["dates"]:
            m_data["dates"].append(entry["date"])
            m_data["dates"].sort()
        m_data["total_targets"] = len(m_data["targets"])
        m_data["updated_at"] = int(time.time())

    def _load_month_data(self, month_str):
        if month_str in self._cache:
            return self._cache[month_str]
        filepath = os.path.join(self.history_dir, f"flight_history_{month_str}.json")
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    d = json.load(f)
                    self._cache[month_str] = d
                    return d
            except Exception as e:
                logger.error(f"Error reading history file {filepath}: {e}")
        new_d = {
            "month": month_str,
            "dates": [],
            "total_targets": 0,
            "updated_at": int(time.time()),
            "targets": {}
        }
        self._cache[month_str] = new_d
        return new_d

    def flush_to_disk(self, force=False):
        now = time.time()
        if not force and (now - self.last_flush_ts) < self.flush_interval:
            return
        if not self.dirty_months:
            return

        for m in list(self.dirty_months):
            if m in self._cache:
                d = self._cache[m]
                for entry in self.active_tracks.values():
                    if entry["date"].startswith(m):
                        d["targets"][entry["id"]] = entry
                        if entry["date"] not in d["dates"]:
                            d["dates"].append(entry["date"])
                            d["dates"].sort()
                d["total_targets"] = len(d["targets"])
                d["updated_at"] = int(now)

                filepath = os.path.join(self.history_dir, f"flight_history_{m}.json")
                tmp_path = filepath + ".tmp"
                try:
                    with open(tmp_path, "w", encoding="utf-8") as f:
                        json.dump(d, f, ensure_ascii=False, separators=(',', ':'))
                    os.replace(tmp_path, filepath)
                    logger.info(f"💾 [HistoryManager] Збережено історію за {m}: {d['total_targets']} цілей.")
                except Exception as e:
                    logger.error(f"Error saving history {filepath}: {e}")

        self.dirty_months.clear()
        self.last_flush_ts = now

    def get_available_months(self):
        months_dict = {}
        if os.path.exists(self.history_dir):
            for fn in os.listdir(self.history_dir):
                if fn.startswith("flight_history_") and fn.endswith(".json"):
                    m_str = fn.replace("flight_history_", "").replace(".json", "")
                    d = self._load_month_data(m_str)
                    months_dict[m_str] = d.get("dates", [])
        return months_dict

    def get_history(self, month_str, date_str=None):
        d = self._load_month_data(month_str)
        if not date_str:
            return d
        filtered = {
            tid: t for tid, t in d.get("targets", {}).items()
            if t.get("date") == date_str
        }
        return {
            "month": month_str,
            "date": date_str,
            "total_targets": len(filtered),
            "targets": filtered
        }

    def import_external_history(self, raw_data: dict) -> int:
        items = raw_data.values() if isinstance(raw_data, dict) else raw_data
        count = 0
        for item in items:
            tid = item.get("display_id") or item.get("id")
            if not tid: continue
            raw_t = item.get("type", "")
            raw_c = item.get("raw_type_code", 0)
            cat, meta = classify_target(raw_t, raw_c)
            s_time = item.get("start_time", 0)
            e_time = item.get("end_time", s_time)
            dt_str = time.strftime("%Y-%m-%d", time.gmtime(s_time))
            m_str = dt_str[:7]

            raw_path = item.get("path", [])
            c_path = []
            for p in raw_path:
                if isinstance(p, list) and len(p) >= 3:
                    c_path.append(p)
                elif isinstance(p, dict):
                    c_path.append([
                        p.get("time", 0),
                        round(float(p.get("lat", 0)), 4),
                        round(float(p.get("lon", 0)), 4),
                        round(float(p.get("heading", 0)), 1),
                        round(float(p.get("speed", 185.0)), 1)
                    ])

            entry = {
                "id": tid,
                "cat": cat,
                "name_ua": meta["name_ua"],
                "raw_type": raw_t,
                "status": item.get("status", "lost"),
                "date": dt_str,
                "start_time": s_time,
                "end_time": e_time,
                "path": c_path
            }
            self._commit_to_month(entry, m_str)
            self.dirty_months.add(m_str)
            count += 1

        self.flush_to_disk(force=True)
        return count

    def get_admin_summary(self):
        files_list = []
        total_sz = 0
        total_targets = 0
        if os.path.exists(self.history_dir):
            for fn in sorted(os.listdir(self.history_dir), reverse=True):
                if fn.startswith("flight_history_") and fn.endswith(".json"):
                    m_str = fn.replace("flight_history_", "").replace(".json", "")
                    fp = os.path.join(self.history_dir, fn)
                    sz = os.path.getsize(fp)
                    total_sz += sz
                    d = self._load_month_data(m_str)
                    t_count = d.get("total_targets", len(d.get("targets", {})))
                    total_targets += t_count
                    files_list.append({
                        "filename": fn,
                        "month": m_str,
                        "size_bytes": sz,
                        "size_kb": round(sz / 1024, 1),
                        "total_targets": t_count,
                        "dates": d.get("dates", []),
                        "updated_at": d.get("updated_at", int(os.path.getmtime(fp)))
                    })
        return {
            "total_size_bytes": total_sz,
            "total_size_mb": f"{total_sz / (1024 * 1024):.2f} MB",
            "total_files": len(files_list),
            "total_targets": total_targets,
            "files": files_list
        }

    def delete_month(self, month_str):
        fn = f"flight_history_{month_str}.json"
        fp = os.path.join(self.history_dir, fn)
        tmp = fp + ".tmp"
        deleted = False
        if os.path.exists(fp):
            try:
                os.remove(fp)
                deleted = True
            except Exception as e:
                logger.error(f"Error removing {fp}: {e}")
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except Exception: pass
        if month_str in self._cache:
            del self._cache[month_str]
        self.dirty_months.discard(month_str)
        return deleted

    def get_month_filepath(self, month_str):
        fn = f"flight_history_{month_str}.json"
        fp = os.path.join(self.history_dir, fn)
        return fp if os.path.exists(fp) else None

history_manager = HistoryManager(DATA_DIR)

class TargetTracker:
    """Менеджер всех сопровождаемых целей."""
    def __init__(self):
        self.tracks = {} # id -> TargetTrack

    def update_batch(self, incoming_targets: list) -> list:
        now = time.time()
        seen_ids = set()

        for t in incoming_targets:
            t_id = t["id"]
            seen_ids.add(t_id)

            lat = float(t.get("lat") or 0.0)
            lon = float(t.get("lon") or 0.0)
            heading = float(t.get("heading") or 0.0)
            speed = float(t.get("speed_kmh") or 0.0)
            ob_name = t.get("oblast") or oblast_detector.find_oblast(lat, lon)
            ob_id = t.get("oblast_id") or oblast_detector.get_oblast_id_by_name(ob_name)

            if t_id in self.tracks:
                self.tracks[t_id].update(
                    lat=lat,
                    lon=lon,
                    heading=heading,
                    speed_kmh=speed,
                    oblast=ob_name,
                    oblast_id=ob_id,
                    t_type=t.get("type"),
                    raw_code=t.get("raw_type_code", 0)
                )
            else:
                self.tracks[t_id] = TargetTrack(
                    target_id=t_id,
                    t_type=t.get("type", "unknown"),
                    raw_code=t.get("raw_type_code", 0),
                    lat=lat,
                    lon=lon,
                    heading=heading,
                    speed_kmh=speed,
                    oblast=ob_name,
                    oblast_id=ob_id
                )

        # Очистка исчезнувших целей (если не появлялись в потоке более 25 секунд)
        expired = [tid for tid, trk in self.tracks.items() if (now - trk.last_seen) > 25.0]
        for tid in expired:
            trk = self.tracks[tid]
            history_manager.finish_track(trk, status="lost")
            del self.tracks[tid]

        # Запись текущих точек активных целей в кольцевой буфер истории
        for trk in self.tracks.values():
            history_manager.update_point(trk)
        history_manager.flush_to_disk()

        return list(self.tracks.values())

# =====================================================================
# МЕНЕДЖЕР СОСТОЯНИЯ УГРОЗ И ОФИЦИАЛЬНЫХ СИРЕН
# =====================================================================

class ThreatState:
    def __init__(self):
        self.lock = asyncio.Lock()
        self.tracker = TargetTracker()
        self.last_update_ts = 0.0
        self.upstream_provider = "none"
        self.ws_subscribers = set()
        # Официальные сирены с сервера
        self.official_alerts = {} # regionId -> { name, type, since, alerts }
        self.mig_active = False
        self.artillery_alerts = set()
        self.alert_reasons = []
        self.oblast_alerts = {} # oblast_id -> status dict
        self.recompute_oblast_alerts()

    def recompute_oblast_alerts(self):
        """Пересчитывает статус всех 26 областей Украины (дрон/желтый, ракета/красный, чисто)."""
        ob_status = {}
        for ob in oblast_detector.get_all_oblasts():
            ob_status[ob["id"]] = {
                "id": ob["id"],
                "name": ob["name"],
                "alert": False,
                "alert_type": "none", # "none", "drone", "missile", "artillery"
                "color": "none",      # "none", "yellow", "red"
                "reasons": [],
                "since": "",
                "targets_count": 0
            }

        # 1. Анализ официальных сирен и районов
        for rid, a_info in self.official_alerts.items():
            ob_id = oblast_detector.get_oblast_id_by_region(rid)
            if ob_id not in ob_status:
                continue
            ob = ob_status[ob_id]
            ob["alert"] = True
            if not ob["since"] and a_info.get("since"):
                ob["since"] = a_info["since"]

            active_alerts = a_info.get("alerts", [])
            if not active_alerts:
                if ob["alert_type"] == "none":
                    ob["alert_type"] = "missile"
                    ob["color"] = "red"

            for al in active_alerts:
                al_type = al.get("type", "")
                levels = al.get("activeAlertLevels", [])
                for lvl in levels:
                    lvl_level = str(lvl.get("alertLevel", "")).strip().capitalize()
                    reason = lvl.get("reason", "")
                    if reason and reason not in ob["reasons"]:
                        ob["reasons"].append(reason)

                    # Прямая проверка поля alertLevel из mapUpdate ("Yellow" / "Red"):
                    if lvl_level == "Yellow":
                        if ob["alert_type"] != "missile":
                            ob["alert_type"] = "drone"
                            ob["color"] = "yellow"
                    elif lvl_level == "Red":
                        ob["alert_type"] = "missile"
                        ob["color"] = "red"
                    else:
                        # Резервный анализ по тексту причины:
                        r_lower = reason.lower()
                        if "дрон" in r_lower or "бпла" in r_lower or "жовт" in r_lower:
                            if ob["alert_type"] != "missile":
                                ob["alert_type"] = "drone"
                                ob["color"] = "yellow"
                        elif "ракет" in r_lower or "баліст" in r_lower or "червон" in r_lower or "авіац" in r_lower or "каб" in r_lower:
                            ob["alert_type"] = "missile"
                            ob["color"] = "red"
                if al_type in ("ARTILLERY", "URBAN_FIGHTS") or rid in self.artillery_alerts:
                    ob["alert_type"] = "missile"
                    ob["color"] = "red"
                elif ob["alert_type"] == "none":
                    ob["alert_type"] = "missile"
                    ob["color"] = "red"

        # 2. Анализ летящих целей в небе (Centrifugo / TargetTracker)
        for trk in self.tracker.tracks.values():
            ob_info = oblast_detector.find_oblast_info(trk.lat, trk.lon)
            ob_id = str(ob_info.get("id", "0"))
            if ob_id in ob_status:
                ob = ob_status[ob_id]
                ob["targets_count"] += 1
                if trk.is_drone:
                    if ob["alert_type"] != "missile":
                        ob["alert"] = True
                        ob["alert_type"] = "drone"
                        ob["color"] = "yellow"
                else:
                    ob["alert"] = True
                    ob["alert_type"] = "missile"
                    ob["color"] = "red"

        self.oblast_alerts = ob_status

    def build_map_snapshot(self) -> dict:
        """Снапшот стратегической карты Украины для ESP32 и дашбордов."""
        if not self.oblast_alerts:
            self.recompute_oblast_alerts()
        oblasts_list = list(self.oblast_alerts.values())
        targets_list = []
        for trk in self.tracker.tracks.values():
            targets_list.append({
                "trk_id": trk.id,
                "lat": round(trk.lat, 4),
                "lon": round(trk.lon, 4),
                "heading_deg": round(trk.heading, 1),
                "speed_kmh": round(trk.speed_kmh, 1),
                "type": trk.type,
                "category": getattr(trk, "category", "shahed"),
                "ha_icon": getattr(trk, "ha_icon", "mdi:crosshairs-gps"),
                "esp_code": getattr(trk, "esp_code", 1),
                "color_hex": getattr(trk, "color_hex", "#FACC15"),
                "is_drone": trk.is_drone
            })
        return {
            "status": "ok",
            "total_threats": len(self.tracker.tracks),
            "mig_active": self.mig_active,
            "updated_at": int(self.last_update_ts),
            "oblasts": oblasts_list,
            "targets": targets_list
        }

    async def update_threats(self, raw_targets: list, provider: str):
        async with self.lock:
            self.tracker.update_batch(raw_targets)
            self.last_update_ts = time.time()
            self.upstream_provider = provider
            self.recompute_oblast_alerts()
        await self.broadcast()

    async def update_official_alerts(self, alerts_data: dict):
        async with self.lock:
            active = {}
            for a in alerts_data.get("alerts", []):
                rid = str(a.get("regionId", ""))
                if rid:
                    active[rid] = {
                        "name": a.get("regionName", ""),
                        "type": a.get("regionType", ""),
                        "since": a.get("lastUpdate", ""),
                        "alerts": a.get("activeAlerts", [])
                    }
            self.official_alerts = active
            self.mig_active = len(alerts_data.get("migAlerts", [])) > 0
            self.artillery_alerts = {str(x.get("regionId", "")) for x in alerts_data.get("artillery", [])}
            self.alert_reasons = alerts_data.get("reasons", [])
            self.recompute_oblast_alerts()

    async def update_neptun_alerts(self, neptun_data: dict):
        """Резервное обновление официальных сирен и тревог из Neptun API (/api/v1/alerts)."""
        async with self.lock:
            active = {}
            # 1. Анализируем области целиком
            for ob_item in neptun_data.get("oblasts", []):
                ob_name = ob_item.get("oblast") or ob_item.get("name", "")
                ob_id = oblast_detector.get_oblast_id_by_name(ob_name)
                if ob_id and ob_id != "0":
                    lvl = "Yellow" if str(ob_item.get("level", "")).lower() == "yellow" else "Red"
                    active[ob_id] = {
                        "name": ob_item.get("name", ob_name),
                        "type": "State",
                        "since": ob_item.get("since", ""),
                        "alerts": [{
                            "type": "AIR",
                            "activeAlertLevels": [{
                                "alertLevel": lvl,
                                "reason": (ob_item.get("reasons") or [""])[0] if ob_item.get("reasons") else ""
                            }]
                        }]
                    }
            # 2. Анализируем районы
            for r_item in neptun_data.get("raions", []):
                ob_name = r_item.get("oblast", "")
                ob_id = oblast_detector.get_oblast_id_by_name(ob_name)
                if ob_id and ob_id != "0":
                    lvl = "Yellow" if str(r_item.get("level", "")).lower() == "yellow" else "Red"
                    reason = (r_item.get("reasons") or [""])[0] if r_item.get("reasons") else ""
                    if ob_id not in active:
                        active[ob_id] = {
                            "name": ob_name,
                            "type": "State",
                            "since": r_item.get("since", ""),
                            "alerts": [{
                                "type": "AIR",
                                "activeAlertLevels": [{
                                    "alertLevel": lvl,
                                    "reason": reason
                                }]
                            }]
                        }
                    else:
                        # Если в районе красный уровень, поднимаем статус всей области до Red
                        if lvl == "Red":
                            active[ob_id]["alerts"][0]["activeAlertLevels"] = [{
                                "alertLevel": "Red",
                                "reason": reason
                            }]
            self.official_alerts = active
            self.recompute_oblast_alerts()

    async def broadcast(self):
        if not self.ws_subscribers: return
        disconnected = set()
        for item in list(self.ws_subscribers):
            ws, user = item
            try:
                snapshot = self.build_user_snapshot(user, slot_id="1")
                await ws.send_str(json.dumps(snapshot, ensure_ascii=False))
            except Exception:
                disconnected.add(item)
        self.ws_subscribers -= disconnected

    def build_user_snapshot(self, user: dict, slot_id: str = "1", radius_km: float = None,
                            custom_lat: float = None, custom_lon: float = None,
                            danger_radius_km: float = None,
                            alert_threat: bool = None,
                            alert_siren: bool = None,
                            alert_mig: bool = None,
                            alert_artillery: bool = None) -> dict:
        slots = user.get("slots", {})
        target_slot = slots.get(str(slot_id))
        if not target_slot and slots:
            target_slot = next(iter(slots.values()))

        # Эффективные настройки опасной зоны и алертов для выбранного слота
        u_settings = user.get("settings", DEFAULT_USER_SETTINGS)
        slot_danger = float(target_slot.get("danger_radius_km", u_settings.get("danger_radius_km", DANGER_RADIUS_KM))) if target_slot else float(u_settings.get("danger_radius_km", DANGER_RADIUS_KM))
        eff_danger_km = float(danger_radius_km) if (danger_radius_km is not None and danger_radius_km > 0) else slot_danger
        eff_alert_threat = alert_threat if alert_threat is not None else bool(u_settings.get("alert_threat", True))
        eff_alert_siren = alert_siren if alert_siren is not None else bool(u_settings.get("alert_siren", True))
        eff_alert_mig = alert_mig if alert_mig is not None else bool(u_settings.get("alert_mig", False))
        eff_alert_artillery = alert_artillery if alert_artillery is not None else bool(u_settings.get("alert_artillery", False))

        center_lat = custom_lat if custom_lat is not None else (target_slot["lat"] if target_slot else 50.4501)
        center_lon = custom_lon if custom_lon is not None else (target_slot["lon"] if target_slot else 30.5234)
        center_name = "Пользовательская точка" if custom_lat is not None else (target_slot["name"] if target_slot else "Точки не настроены")

        active_tracks = list(self.tracker.tracks.values())
        processed = []
        closest_dist = 99999.0
        closest_threat = None

        for t in active_tracks:
            lat, lon = t.lat, t.lon
            dist = calculate_haversine_distance(center_lat, center_lon, lat, lon)
            bearing = calculate_bearing(center_lat, center_lon, lat, lon)

            if radius_km is not None and dist > radius_km:
                continue

            heading = t.heading
            speed = t.speed_kmh

            # Вектор сближения: угол между курсом цели и пеленгом на дом
            bearing_from_target = (bearing + 180.0) % 360.0
            angle_diff = abs((heading - bearing_from_target + 180.0) % 360.0 - 180.0)
            if angle_diff < 50.0:
                approach_status = "approaching"
                approach_desc = "Наближається"
            elif angle_diff > 130.0:
                approach_status = "receding"
                approach_desc = "Віддаляється"
            else:
                approach_status = "tangential"
                approach_desc = "Пролітає повз"

            eta_min = round((dist / speed) * 60.0, 1) if approach_status == "approaching" and speed > 0 else None

            in_danger = (dist <= eff_danger_km) if (target_slot or custom_lat is not None) else False

            item = {
                "id": t.id,
                "type": t.type,
                "type_en": getattr(t, "type_en", t.type),
                "category": getattr(t, "category", "shahed"),
                "ha_icon": getattr(t, "ha_icon", "mdi:crosshairs-gps"),
                "esp_code": getattr(t, "esp_code", 1),
                "color_hex": getattr(t, "color_hex", "#FACC15"),
                "raw_code": t.raw_code,
                "oblast": t.oblast,
                "lat": round(lat, 5),
                "lon": round(lon, 5),
                "distance_km": round(dist, 1),
                "bearing_deg": round(bearing, 1),
                "bearing_sector": bearing_to_compass(bearing),
                "heading": heading,
                "heading_deg": heading,
                "speed_kmh": speed,
                "approach_status": approach_status,
                "approach_desc": approach_desc,
                "eta_minutes": eta_min,
                "in_danger_zone": in_danger,
                "trajectory": t.trajectory, # Тепловой след / история пути
                "extrapolated_path": t.get_extrapolated_corridor((5, 10, 15)) # Прогноз полета
            }
            processed.append(item)
            if dist < closest_dist:
                closest_dist = dist
                closest_threat = item

        # Сводка по всем 5 слотам пользователя (с учетом индивидуальной опасной зоны каждого слота!)
        user_slots_stats = {}
        for s_id, s_data in slots.items():
            s_lat, s_lon = s_data["lat"], s_data["lon"]
            s_min = 99999.0
            s_type = "Нет"
            s_danger = False

            # Индивидуальный радиус опасности для этого расположения
            s_danger_km = float(s_data.get("danger_radius_km", u_settings.get("danger_radius_km", DANGER_RADIUS_KM)))

            s_info = oblast_detector.find_oblast_info(s_lat, s_lon)
            s_oblast = s_info["name"]
            s_rid = s_info["id"]

            threats_in_s_oblast = sum(1 for trk in active_tracks if trk.oblast == s_oblast)

            s_min_trk = None
            for t in active_tracks:
                d = calculate_haversine_distance(s_lat, s_lon, t.lat, t.lon)
                if d < s_min:
                    s_min = d
                    s_type = t.type
                    s_min_trk = t
                if d <= s_danger_km:
                    s_danger = True

            s_eta = None
            if s_min_trk and s_min < 90000 and s_min_trk.speed_kmh > 0:
                b = calculate_bearing(s_lat, s_lon, s_min_trk.lat, s_min_trk.lon)
                b_from_t = (b + 180.0) % 360.0
                diff = abs((s_min_trk.heading - b_from_t + 180.0) % 360.0 - 180.0)
                if diff < 65.0:
                    s_eta = round((s_min / s_min_trk.speed_kmh) * 60.0, 1)

            # Официальная тревога в области слота (даже если физических целей еще нет)
            is_official_alert = (s_rid in self.official_alerts) or ("31" in self.official_alerts and s_rid == "14")
            alert_meta = self.official_alerts.get(s_rid, {})

            user_slots_stats[s_id] = {
                "id": s_id,
                "name": s_data["name"],
                "type": s_data.get("type", "static"),
                "lat": s_lat,
                "lon": s_lon,
                "oblast": s_oblast,
                "oblast_id": s_rid,
                "danger_radius_km": s_danger_km,
                "siren_active": is_official_alert,
                "siren_since": alert_meta.get("since"),
                "mig_threat_active": self.mig_active,
                "artillery_active": s_rid in self.artillery_alerts,
                "threats_in_this_oblast": threats_in_s_oblast,
                "closest_distance_km": round(s_min, 1) if s_min < 90000 else None,
                "closest_type": s_type if s_min < 90000 else "Спокійно",
                "closest_eta_minutes": s_eta,
                "danger_zone_active": s_danger
            }

        # Анализ срабатывания звукового оповещения для выбранного слота
        target_slot_stat = user_slots_stats.get(str(slot_id), {})
        is_threat_in_target_danger = target_slot_stat.get("danger_zone_active", False)
        is_siren_in_target_slot = target_slot_stat.get("siren_active", False)
        is_artillery_in_target_slot = target_slot_stat.get("artillery_active", False)
        is_mig_active = self.mig_active

        audio_alert_reasons = []
        if eff_alert_threat and is_threat_in_target_danger:
            audio_alert_reasons.append("THREAT_IN_DANGER_ZONE")
        if eff_alert_siren and is_siren_in_target_slot:
            audio_alert_reasons.append("OBLAST_SIREN")
        if eff_alert_mig and is_mig_active:
            audio_alert_reasons.append("MIG31K_AIRBORNE")
        if eff_alert_artillery and is_artillery_in_target_slot:
            audio_alert_reasons.append("ARTILLERY_DANGER")

        audio_alert_active = len(audio_alert_reasons) > 0

        return {
            "timestamp": int(self.last_update_ts * 1000),
            "owner": user["owner"],
            "upstream_provider": self.upstream_provider,
            "active_threats_total": len(active_tracks),
            "total_threats_in_country": len(active_tracks),
            "general_alerts": {
                "mig31k_active": self.mig_active,
                "total_official_sirens": len(self.official_alerts),
                "reasons": self.alert_reasons
            },
            "current_point": {
                "slot_id": slot_id,
                "name": center_name,
                "lat": center_lat,
                "lon": center_lon,
                "danger_radius_km": eff_danger_km
            },
            "settings": {
                "danger_radius_km": eff_danger_km,
                "alert_threat": eff_alert_threat,
                "alert_siren": eff_alert_siren,
                "alert_mig": eff_alert_mig,
                "alert_artillery": eff_alert_artillery
            },
            "audio_alert_active": audio_alert_active,
            "audio_alert_reasons": audio_alert_reasons,
            "closest_threat": closest_threat,
            "slots": user_slots_stats,
            "threats": processed,
            "map_oblasts": list(self.oblast_alerts.values()) if self.oblast_alerts else []
        }

    def build_radar_projection(self, user: dict, slot_id: str = "1", radius_km: float = 100.0,
                               custom_lat: float = None, custom_lon: float = None,
                               screen_w: int = 368, screen_h: int = 448,
                               danger_radius_km: float = None,
                               alert_threat: bool = None,
                               alert_siren: bool = None,
                               alert_mig: bool = None,
                               alert_artillery: bool = None) -> dict:
        snapshot = self.build_user_snapshot(user, slot_id=slot_id, radius_km=radius_km,
                                            custom_lat=custom_lat, custom_lon=custom_lon,
                                            danger_radius_km=danger_radius_km,
                                            alert_threat=alert_threat,
                                            alert_siren=alert_siren,
                                            alert_mig=alert_mig,
                                            alert_artillery=alert_artillery)
        center_x, center_y = screen_w / 2.0, screen_h / 2.0
        max_px = min(center_x, center_y) * 0.92

        radar_targets = []
        for t in snapshot["threats"]:
            dist = t["distance_km"]
            bearing = t["bearing_deg"]
            norm_dist = min(dist / radius_km, 1.0)
            angle_rad = math.radians(bearing)
            px_dist = norm_dist * max_px

            px_x = center_x + px_dist * math.sin(angle_rad)
            px_y = center_y - px_dist * math.cos(angle_rad)

            # Перевод точек теплового следа в экранные пиксели для радара
            screen_trail = []
            for p in t["trajectory"]:
                p_dist = calculate_haversine_distance(snapshot["current_point"]["lat"], snapshot["current_point"]["lon"], p["lat"], p["lon"])
                p_bearing = calculate_bearing(snapshot["current_point"]["lat"], snapshot["current_point"]["lon"], p["lat"], p["lon"])
                p_norm = min(p_dist / radius_km, 1.0)
                p_px = p_norm * max_px
                p_rad = math.radians(p_bearing)
                screen_trail.append([
                    int(round(center_x + p_px * math.sin(p_rad))),
                    int(round(center_y - p_px * math.cos(p_rad)))
                ])

            radar_targets.append({
                "id": t["id"],
                "type": t["type"],
                "category": t.get("category", "shahed"),
                "ha_icon": t.get("ha_icon", "mdi:crosshairs-gps"),
                "esp_code": t.get("esp_code", 1),
                "color_hex": t.get("color_hex", "#FACC15"),
                "code": t["raw_code"],
                "dist_km": t["distance_km"],
                "bearing": t["bearing_deg"],
                "x": int(round(px_x)),
                "y": int(round(px_y)),
                "heading": t.get("heading", 0.0),
                "eta_min": t.get("eta_minutes"),
                "danger": t["in_danger_zone"],
                "screen_trail": screen_trail # Пиксели для отрисовки хвоста на AMOLED
            })

        slot_stat = snapshot["slots"].get(str(slot_id), {})
        eff_danger_km = snapshot["settings"]["danger_radius_km"]
        # Точный радиус зоны опасности в пикселях для отображения окружности на дисплее
        danger_circle_px = int(round(min(eff_danger_km / radius_km, 1.0) * max_px))

        return {
            "timestamp": snapshot["timestamp"],
            "owner": user["owner"],
            "slot_id": slot_id,
            "location_name": snapshot["current_point"]["name"],
            "radius_km": radius_km,
            "danger_radius_km": eff_danger_km,
            "danger_circle_px": danger_circle_px,
            "threats_count": len(radar_targets),
            "siren_active": slot_stat.get("siren_active", False),
            "mig_active": snapshot["general_alerts"]["mig31k_active"],
            "closest_km": snapshot["closest_threat"]["distance_km"] if snapshot["closest_threat"] else None,
            "closest_eta": snapshot["closest_threat"]["eta_minutes"] if snapshot["closest_threat"] else None,
            "danger_active": slot_stat.get("danger_zone_active", False),
            "audio_alert_active": snapshot["audio_alert_active"],
            "audio_alert_reasons": snapshot["audio_alert_reasons"],
            "settings": snapshot["settings"],
            "targets": radar_targets
        }

state = ThreatState()

# =====================================================================
# ДЕШИФРАТОР CHACHA20 + ИЗВЛЕЧЕНИЕ ПОСТОЯННЫХ UUID
# =====================================================================

def rotl(val: int, shift: int) -> int: return ((val << shift) & 0xFFFFFFFF) | (val >> (32 - shift))
def quarter_round(st: list, a: int, b: int, c: int, d: int):
    st[a] = (st[a] + st[b]) & 0xFFFFFFFF; st[d] = rotl(st[d] ^ st[a], 16)
    st[c] = (st[c] + st[d]) & 0xFFFFFFFF; st[b] = rotl(st[b] ^ st[c], 12)
    st[a] = (st[a] + st[b]) & 0xFFFFFFFF; st[d] = rotl(st[d] ^ st[a], 8)
    st[c] = (st[c] + st[d]) & 0xFFFFFFFF; st[b] = rotl(st[b] ^ st[c], 7)

class PRNG:
    def __init__(self, seed_val: int = 1831565813): self.seed = seed_val & 0xFFFFFFFF
    def next(self) -> int:
        s = self.seed; s = (s ^ ((s << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
        s = (s ^ (s >> 17)) & 0xFFFFFFFF; s = (s ^ ((s << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
        self.seed = s; return s

def decode_payload_native(payload_str: str):
    if not isinstance(payload_str, str) or not payload_str.startswith("~5:"): raise ValueError("Unsupported payload")
    b64 = payload_str[3:].replace('-', '+').replace('_', '/')
    pad = (4 - len(b64) % 4) % 4
    raw_bytes = bytearray(base64.b64decode(b64 + '=' * pad))
    if len(raw_bytes) < 16: raise ValueError("Too short")

    f, h, g = struct.unpack_from('<III', raw_bytes, 0)
    state_arr = [1634760805, 857760878, 2036477234, 1797285236, 2838917605, 566540499, 2028117766, 3025996967, 1063430289, 3353677899, 1519178294, 2422993229, 1, f, h, g]
    block = [0] * 16; raw_len = len(raw_bytes)

    for i in range(16, raw_len, 64):
        block[:] = state_arr
        for _ in range(10):
            quarter_round(block, 0, 4, 8, 12); quarter_round(block, 1, 5, 9, 13)
            quarter_round(block, 2, 6, 10, 14); quarter_round(block, 3, 7, 11, 15)
            quarter_round(block, 0, 5, 10, 15); quarter_round(block, 1, 6, 11, 12)
            quarter_round(block, 2, 7, 8, 13); quarter_round(block, 3, 4, 9, 14)
        block_len = min(64, raw_len - i)
        for j in range(block_len):
            key_word = (block[j >> 2] + state_arr[j >> 2]) & 0xFFFFFFFF
            raw_bytes[i + j] ^= (key_word >> (8 * (3 & j))) & 0xFF
        state_arr[12] = (state_arr[12] + 1) & 0xFFFFFFFF

    type_rng = PRNG((f ^ h ^ g ^ 668265263) & 0xFFFFFFFF)
    types = list(range(10))
    for i in range(len(types) - 1, 0, -1):
        rand_idx = type_rng.next() % (i + 1)
        types[i], types[rand_idx] = types[rand_idx], types[i]
    type_map = [0] * 10
    for i, t in enumerate(types): type_map[t] = i

    offset, limit = 16, 0
    val_rng = PRNG((f ^ g ^ 2246822507) & 0xFFFFFFFF)
    xor_rng = PRNG((3266489909 ^ h) & 0xFFFFFFFF)
    string_cache, number_cache = [], []

    def read_byte():
        nonlocal offset
        if offset >= raw_len: raise EOFError("EOF")
        b = raw_bytes[offset]; offset += 1; return b

    def read_varint():
        value, shift = 0, 1
        for _ in range(8):
            byte = read_byte(); value += (127 & byte) * shift
            if not (128 & byte): return value
            shift *= 128
        raise ValueError("Invalid varint")

    def parse_node(depth: int):
        nonlocal limit, offset
        if depth > 63 or limit > 1_000_000: raise ValueError("Limit")
        limit += 1
        b = read_byte()
        if b >= len(type_map): raise ValueError("Out of range")
        node_type = type_map[b]

        if node_type == 0: return None
        elif node_type == 1: return False
        elif node_type == 2: return True
        elif node_type == 3:
            val = read_varint(); xor_val = 65535 & xor_rng.next()
            low = (val & 0xFFFFFFFF) ^ xor_val
            high = (val // 4294967296) * 4294967296
            num = high + low
            return -(num + 1) // 2 if (num % 2) else num // 2
        elif node_type == 4:
            u0 = struct.unpack_from('<I', raw_bytes, offset)[0] ^ xor_rng.next()
            u1 = struct.unpack_from('<I', raw_bytes, offset + 4)[0] ^ xor_rng.next()
            offset += 8
            fval = struct.unpack('<d', struct.pack('<II', u0, u1))[0]
            number_cache.append(fval); return fval
        elif node_type == 5:
            slen = read_varint(); str_xor = xor_rng.next()
            chars = bytearray()
            for i in range(slen):
                chars.append(raw_bytes[offset + i] ^ ((str_xor >> (8 * (3 & i))) & 0xFF))
            offset += slen
            try: s = chars.decode('utf-8')
            except: s = chars.decode('latin1', errors='replace')
            string_cache.append(s); return s
        elif node_type == 6:
            alen = read_varint()
            if alen == 0: return []
            arr = [None] * alen
            start_offset = val_rng.next() % alen
            is_reverse = bool(1 & val_rng.next())
            for i in range(alen):
                idx = (start_offset + (alen - i if is_reverse else i)) % alen
                arr[idx] = parse_node(depth + 1)
            return arr
        elif node_type == 7: return string_cache[read_varint()]
        elif node_type == 8: return number_cache[read_varint()]
        else: raise ValueError(f"Unknown node type {node_type}")

    return parse_node(0)

def extract_targets(decoded_data):
    """Извлекает цели с постоянными UUID и векторами смещения."""
    found_coords, found_types, found_targets = None, None, None
    found_uuids = None

    # Поиск списка постоянных UUID в структуре
    try:
        if len(decoded_data) > 4 and isinstance(decoded_data[4], list):
            for item in decoded_data[4]:
                if isinstance(item, list) and len(item) > 0 and isinstance(item[0], str) and item[0].startswith('~'):
                    found_uuids = item
                    break
    except Exception: pass

    def search_global(node):
        nonlocal found_coords, found_types, found_targets
        if isinstance(node, list):
            if found_coords is None and len(node) > 0 and isinstance(node[0], list) and len(node[0]) >= 4 and all(isinstance(x, float) and 0 <= x <= 1.0 for x in node[0][:4]):
                found_coords = node
            if found_types is None and len(node) > 0 and isinstance(node[0], list) and len(node[0]) >= 3 and isinstance(node[0][0], int) and isinstance(node[0][1], str):
                found_types = node
            if found_targets is None and len(node) > 0 and isinstance(node[0], list) and len(node[0]) >= 8 and isinstance(node[0][0], int) and isinstance(node[0][7], float):
                found_targets = node
            for item in node:
                if isinstance(item, list): search_global(item)

    search_global(decoded_data)
    if not (found_coords and found_types and found_targets): return []

    MIN_LON, LON_RANGE = 22.13, 18.09
    MAX_LAT, LAT_RANGE = 52.37, 7.99
    normalized = []

    for idx, t in enumerate(found_targets):
        try:
            uuid_idx, c_idx, typ_idx = t[0], t[1], t[2]
            heading = float(t[3]) if len(t) > 3 and isinstance(t[3], (int, float)) else 0.0

            # Стабильный UUID от первоисточника
            uid = found_uuids[uuid_idx] if found_uuids and uuid_idx < len(found_uuids) else f"t_{uuid_idx}"

            if c_idx < len(found_coords):
                lon = MIN_LON + (found_coords[c_idx][0] * LON_RANGE)
                lat = MAX_LAT - (found_coords[c_idx][1] * LAT_RANGE)
                name = found_types[typ_idx][1] if typ_idx < len(found_types) else "Ціль"
                raw_code = found_types[typ_idx][0] if typ_idx < len(found_types) else 0

                cat, meta = classify_target(name, raw_code)
                speed = meta["default_speed"]
                ob_info = oblast_detector.find_oblast_info(lat, lon)

                normalized.append({
                    "id": uid,
                    "lat": lat,
                    "lon": lon,
                    "type": name,
                    "category": cat,
                    "raw_type_code": raw_code,
                    "oblast": ob_info["name"],
                    "oblast_id": ob_info["id"],
                    "heading": heading,
                "heading_deg": heading,
                    "speed_kmh": speed
                })
        except Exception: continue

    return normalized

# =====================================================================
# ФОНОВЫЕ СЛУЖБЫ: RADAR STREAM, OFFICIAL ALERTS & FAILOVER
# =====================================================================

PAGE_URL = "https://map.ukrainealarm.com/onlyMap"
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Origin": "https://map.ukrainealarm.com",
    "Referer": "https://map.ukrainealarm.com/"
}

cookie_jar = http.cookiejar.CookieJar()
handlers = [urllib.request.HTTPCookieProcessor(cookie_jar)]
if UPSTREAM_PROXY:
    logger.info(f"Настроен прокси для апстрима: {mask_proxy(UPSTREAM_PROXY)}")
    handlers.append(urllib.request.ProxyHandler({'http': UPSTREAM_PROXY, 'https': UPSTREAM_PROXY}))
opener = urllib.request.build_opener(*handlers)

def fetch_url_text(req, opener_inst=None, timeout=10) -> str:
    """Безопасное чтение HTTP-ответа с гарантированным немедленным закрытием сокета."""
    op = opener_inst or urllib.request
    with op.open(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8')

async def run_ukrainealarm_collector():
    """Основной сборщик данных через WebSocket Centrifugo."""
    import websockets

    while True:
        try:
            req = urllib.request.Request(PAGE_URL, headers=BROWSER_HEADERS)
            html = await asyncio.to_thread(lambda: fetch_url_text(req, opener_inst=opener, timeout=12))

            token_m = re.search(r'id=["\']centrifugo-token["\'][^>]*value=["\']([^"\']+)["\']', html)
            auth_token = token_m.group(1) if token_m else None
            chan_m = re.search(r'data-target-centrifugo-channel=["\']([^"\']+)["\']', html)
            channel = chan_m.group(1) if chan_m else "$r_09f4c276b81de5a3"
            ws_m = re.search(r'id=["\']centrifugo-url["\'][^>]*value=["\']([^"\']+)["\']', html)
            ws_url = ws_m.group(1) if ws_m else "wss://ws.ukrainealarm.com/connection/websocket"
            sub_m = re.search(r'data-target-subscribe-endpoint=["\']([^"\']+)["\']', html)
            sub_ep = f"https://map.ukrainealarm.com{sub_m.group(1)}" if sub_m else "https://map.ukrainealarm.com/api/centrifuge/map/subscribe"

            if not auth_token:
                await asyncio.sleep(5); continue

            ws_kwargs = {"additional_headers": {"Origin": "https://map.ukrainealarm.com"}}
            sig = inspect.signature(websockets.connect)
            if "origin" in sig.parameters: ws_kwargs["origin"] = "https://map.ukrainealarm.com"
            if "extra_headers" in sig.parameters and "additional_headers" not in sig.parameters:
                ws_kwargs["extra_headers"] = {"Origin": "https://map.ukrainealarm.com"}

            async with websockets.connect(ws_url, **ws_kwargs) as ws:
                await ws.send(json.dumps({"params": {"token": auth_token, "name": "js"}, "id": 1}))

                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=45.0)
                    if msg in ("{}", '{"id":0}'): continue

                    for line in msg.strip().split('\n'):
                        if not line: continue
                        data = json.loads(line)

                        if data.get("id") == 1:
                            client_id = data.get("result", {}).get("client", "")
                            s_headers = BROWSER_HEADERS.copy()
                            s_headers["Content-Type"] = "application/json"
                            sub_payload = json.dumps({"client": client_id, "channels": [channel]}).encode('utf-8')
                            sub_req = urllib.request.Request(sub_ep, data=sub_payload, headers=s_headers, method="POST")

                            sub_resp_text = await asyncio.to_thread(lambda: fetch_url_text(sub_req, opener_inst=opener, timeout=10))
                            sub_data = json.loads(sub_resp_text)
                            stoken = None
                            if isinstance(sub_data.get("channels"), list):
                                for ch in sub_data["channels"]:
                                    if ch.get("channel") == channel: stoken = ch.get("token")
                            if not stoken and isinstance(sub_data.get(channel), dict):
                                stoken = sub_data[channel].get("token")

                            if stoken:
                                await ws.send(json.dumps({"method": 1, "params": {"channel": channel, "token": stoken}, "id": 4}))
                            continue

                        payload = ""
                        if "push" in data and "pub" in data["push"]:
                            pub = data["push"]["pub"].get("data", {})
                            payload = pub.get("data", {}).get("n", "") if isinstance(pub, dict) and "data" in pub else pub.get("n", "") if isinstance(pub, dict) else ""
                        elif "result" in data and "data" in data["result"]:
                            payload = data["result"]["data"].get("data", {}).get("n", "")

                        if payload and isinstance(payload, str) and payload.startswith("~5:"):
                            try:
                                decoded = decode_payload_native(payload)
                                targets = extract_targets(decoded)
                                await state.update_threats(targets, provider="ukrainealarm")
                            except Exception as ex:
                                logger.error(f"Decode error: {ex}")

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"Апстрим реконнект ({e}). Пауза 6 сек...")
            await asyncio.sleep(6)

async def run_official_alerts_collector():
    """Сборщик официальных сирен, тревог МиГ-31К и артиллерии по всей Украине (/api/v2/data/mapUpdate)."""
    update_url = "https://map.ukrainealarm.com/api/v2/data/mapUpdate"

    while True:
        try:
            req = urllib.request.Request(update_url, headers=BROWSER_HEADERS)
            raw = await asyncio.to_thread(lambda: fetch_url_text(req, opener_inst=opener, timeout=10))
            data = json.loads(raw)
            await state.update_official_alerts(data)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.debug(f"Ошибка обновления официальных сирен: {e}")
        await asyncio.sleep(12) # Опрос раз в 12 секунд

async def run_failover_neptun_collector():
    while True:
        try:
            await asyncio.sleep(6)
            if time.time() - state.last_update_ts > 45.0:
                # 1. Сбор воздушных целей из Neptun API
                try:
                    req = urllib.request.Request("https://neptun.in.ua/api/v1/threats", headers={"User-Agent": "Mozilla/5.0"})
                    resp = await asyncio.to_thread(lambda: fetch_url_text(req, timeout=8))
                    threats_raw = json.loads(resp).get("threats", [])
                    normalized = []
                    for t in threats_raw:
                        lat = float(t.get("lat") or 0.0)
                        lon = float(t.get("lon") or 0.0)
                        heading = float(t.get("heading") or 0.0)
                        raw_type = t.get("type", "uav")
                        raw_code = 8 if raw_type == "uav" else (3 if raw_type in ("missile", "ballistic") else 0)
                        cat, meta = classify_target(raw_type, raw_code)
                        ob_info = oblast_detector.find_oblast_info(lat, lon)
                        normalized.append({
                            "id": t.get("id", f"nep_{lat:.2f}"),
                            "lat": lat,
                            "lon": lon,
                            "type": raw_type,
                            "category": cat,
                            "raw_type_code": raw_code,
                            "oblast": ob_info["name"],
                            "oblast_id": ob_info["id"],
                            "heading": heading,
                "heading_deg": heading,
                            "speed_kmh": meta["default_speed"]
                        })
                    await state.update_threats(normalized, provider="neptun_failover")
                except Exception as ex_t:
                    logger.debug(f"Neptun threats failover error: {ex_t}")

                # 2. Резервный сбор официальных сирен и тревог областей из Neptun API
                try:
                    req_a = urllib.request.Request("https://neptun.in.ua/api/v1/alerts", headers={"User-Agent": "Mozilla/5.0"})
                    resp_a = await asyncio.to_thread(lambda: fetch_url_text(req_a, timeout=8))
                    alerts_raw = json.loads(resp_a)
                    await state.update_neptun_alerts(alerts_raw)
                except Exception as ex_a:
                    logger.debug(f"Neptun alerts failover error: {ex_a}")
        except asyncio.CancelledError:
            break

# =====================================================================
# REST & WEBSOCKET API ЭНДПОИНТЫ
# =====================================================================

def is_external_request(request: web.Request) -> bool:
    """
    Определяет, пришёл ли запрос из внешнего интернета (через Cloudflare Tunnel или внешний прокси).
    Защищает админку и мастер-ключи от любого доступа извне.
    """
    # Cloudflare Tunnel всегда добавляет заголовок CF-Connecting-IP и CF-Ray
    if request.headers.get("CF-Connecting-IP") or request.headers.get("CF-Ray"):
        return True
    # Проверка цепочки прокси X-Forwarded-For на наличие внешних публичных IP
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        client_ip = xff.split(",")[0].strip()
        # Разрешаем только локальные приватные подсети (LAN)
        is_private = (
            client_ip.startswith("192.168.") or
            client_ip.startswith("10.") or
            client_ip.startswith("127.") or
            client_ip.startswith("172.")
        )
        if not is_private:
            return True
    return False

def is_admin(request: web.Request) -> bool:
    # Запрещаем любые административные действия из внешнего интернета
    if is_external_request(request):
        return False
    admin_key = (request.query.get("admin_key") or request.headers.get("X-Admin-Key") or "").strip()
    if not admin_key or not ADMIN_SECRET_KEY:
        return False
    return secrets.compare_digest(admin_key, ADMIN_SECRET_KEY)

def get_authenticated_user(request: web.Request):
    token = request.query.get("token") or request.headers.get("X-API-Key")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "): token = auth[7:].strip()
    if not token: return None
    # Если это админский запрос, разрешаем доступ к профилю даже если ключ отключен
    if is_admin(request):
        user = storage.data["users"].get(token)
        if user:
            storage._normalize_user(user)
            return user
    return storage.get_user_by_key(token)

async def handle_get_slots(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    storage._normalize_user(user)
    slots = user.get("slots", {})
    return web.json_response({
        "owner": user["owner"],
        "total_slots": len(slots),
        "max_slots": 5,
        "can_add": len(slots) < 5,
        "slots": slots
    })

async def handle_create_slot(request: web.Request):
    """Создать новую точку (слот) для пользователя. Лимит: максимум 5 локаций на ключ."""
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)

    storage._normalize_user(user)
    if len(user.get("slots", {})) >= 5:
        return web.json_response({
            "error": "Location limit reached",
            "message": "Maximum 5 locations allowed per API key (limit reached: 5/5). To add a new location, delete an existing slot first.",
            "limit": 5,
            "current_count": len(user.get("slots", {}))
        }, status=400)

    try:
        data = await request.json()
    except Exception:
        data = {}

    lat = data.get("lat")
    lon = data.get("lon")
    if lat is None or lon is None:
        return web.json_response({
            "error": "Missing coordinates",
            "message": "Both 'lat' and 'lon' are required to create a location."
        }, status=400)

    try:
        lat = float(lat)
        lon = float(lon)
    except (ValueError, TypeError):
        return web.json_response({
            "error": "Invalid coordinates",
            "message": "'lat' and 'lon' must be valid numbers."
        }, status=400)

    name = str(data.get("name", "")).strip()
    danger_radius = data.get("danger_radius_km") or data.get("danger_radius")
    slot_type = data.get("type", "static")
    custom_id = data.get("slot_id") or data.get("id")

    new_slot, status = storage.create_slot(
        user["api_key"],
        name=name,
        lat=lat,
        lon=lon,
        danger_radius_km=danger_radius,
        slot_type=slot_type,
        custom_id=custom_id
    )

    if not new_slot:
        if status == "limit_reached":
            return web.json_response({
                "error": "Location limit reached",
                "message": "Maximum 5 locations allowed per API key (limit reached: 5/5).",
                "limit": 5,
                "current_count": len(user.get("slots", {}))
            }, status=400)
        return web.json_response({"error": "Failed to create location"}, status=400)

    return web.json_response({
        "status": "success",
        "slot": new_slot,
        "total_slots": len(user.get("slots", {})),
        "max_slots": 5,
        "can_add": len(user.get("slots", {})) < 5
    }, status=201)

async def handle_delete_slot(request: web.Request):
    """Удалить точку (слот) пользователя."""
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    slot_id = str(request.match_info.get("slot_id", "")).strip()
    ok = storage.delete_slot(user["api_key"], slot_id)
    if not ok:
        return web.json_response({"error": f"Slot #{slot_id} not found"}, status=404)
    return web.json_response({
        "status": "deleted",
        "slot_id": slot_id,
        "remaining_slots": len(user.get("slots", {})),
        "can_add": len(user.get("slots", {})) < 5
    })

async def handle_update_slot(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    slot_id = str(request.match_info.get("slot_id", "")).strip()
    if slot_id not in ("1", "2", "3", "4", "5"):
        return web.json_response({
            "error": "Location limit reached",
            "message": f"Slot #{slot_id} is invalid. Maximum 5 locations allowed per API key (slots 1 to 5).",
            "limit": 5
        }, status=400)
    try:
        data = await request.json()
        slot = storage.update_slot(
            user["api_key"], slot_id,
            name=data.get("name"),
            lat=data.get("lat"),
            lon=data.get("lon"),
            danger_radius_km=data.get("danger_radius_km")
        )
        if not slot: return web.json_response({"error": "Slot not found"}, status=404)
        return web.json_response({"status": "success", "slot": slot})
    except Exception as e: return web.json_response({"error": str(e)}, status=400)

async def handle_update_dynamic(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    try:
        data = await request.json()
        slot = storage.update_dynamic_slot(
            user["api_key"],
            lat=data.get("lat"),
            lon=data.get("lon"),
            name=data.get("name"),
            accuracy_m=data.get("accuracy_m", 0.0),
            danger_radius_km=data.get("danger_radius_km")
        )
        return web.json_response({"status": "success", "slot": slot})
    except Exception as e: return web.json_response({"error": str(e)}, status=400)

def parse_bool_param(val):
    if val is None: return None
    s = str(val).lower().strip()
    return s in ("1", "true", "yes", "on")

def parse_float_param(val):
    if val is None: return None
    try:
        f = float(val)
        return f if f > 0 else None
    except: return None

async def handle_get_settings(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    storage._normalize_user(user)
    return web.json_response({
        "status": "success",
        "owner": user["owner"],
        "settings": user["settings"]
    })

async def handle_update_settings(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    try:
        data = await request.json()
        new_settings = storage.update_user_settings(user["api_key"], data)
        return web.json_response({
            "status": "success",
            "owner": user["owner"],
            "settings": new_settings
        })
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)

async def handle_get_threats(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)

    slot_id = request.query.get("slot_id") or request.query.get("slot", "1")
    radius = float(request.query.get("radius", 0)) or None
    custom_lat = float(request.query["lat"]) if "lat" in request.query else None
    custom_lon = float(request.query["lon"]) if "lon" in request.query else None

    # Поддержка динамического переопределения радиуса и фильтров в запросе
    danger_radius = parse_float_param(request.query.get("danger_radius") or request.query.get("danger_radius_km"))
    alert_threat = parse_bool_param(request.query.get("alert_threat"))
    alert_siren = parse_bool_param(request.query.get("alert_siren"))
    alert_mig = parse_bool_param(request.query.get("alert_mig"))
    alert_artillery = parse_bool_param(request.query.get("alert_artillery"))

    snapshot = state.build_user_snapshot(
        user, slot_id=slot_id, radius_km=radius,
        custom_lat=custom_lat, custom_lon=custom_lon,
        danger_radius_km=danger_radius,
        alert_threat=alert_threat, alert_siren=alert_siren,
        alert_mig=alert_mig, alert_artillery=alert_artillery
    )
    return web.json_response(snapshot)

async def handle_get_radar(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)

    slot_id = request.query.get("slot_id") or request.query.get("slot", "1")
    radius = float(request.query.get("radius", 100.0))
    custom_lat = float(request.query["lat"]) if "lat" in request.query else None
    custom_lon = float(request.query["lon"]) if "lon" in request.query else None
    w = int(request.query.get("w", 368))
    h = int(request.query.get("h", 448))

    danger_radius = parse_float_param(request.query.get("danger_radius") or request.query.get("danger_radius_km"))
    alert_threat = parse_bool_param(request.query.get("alert_threat"))
    alert_siren = parse_bool_param(request.query.get("alert_siren"))
    alert_mig = parse_bool_param(request.query.get("alert_mig"))
    alert_artillery = parse_bool_param(request.query.get("alert_artillery"))

    radar = state.build_radar_projection(
        user, slot_id=slot_id, radius_km=radius,
        custom_lat=custom_lat, custom_lon=custom_lon,
        screen_w=w, screen_h=h,
        danger_radius_km=danger_radius,
        alert_threat=alert_threat, alert_siren=alert_siren,
        alert_mig=alert_mig, alert_artillery=alert_artillery
    )
    return web.json_response(radar)

async def handle_get_map(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    snapshot = state.build_map_snapshot()
    return web.json_response(snapshot)

async def handle_websocket_stream(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.Response(text="Unauthorized", status=401)

    ws = web.WebSocketResponse()
    await ws.prepare(request)
    sub_tuple = (ws, user)
    state.ws_subscribers.add(sub_tuple)

    slot_id = request.query.get("slot_id") or request.query.get("slot", "1")
    init_data = state.build_user_snapshot(user, slot_id=slot_id)
    await ws.send_str(json.dumps(init_data, ensure_ascii=False))

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    cmd = json.loads(msg.data)
                    if cmd.get("action") == "switch_slot":
                        new_slot = str(cmd.get("slot", "1"))
                        await ws.send_str(json.dumps(state.build_user_snapshot(user, slot_id=new_slot), ensure_ascii=False))
                except: pass
            elif msg.type == WSMsgType.ERROR: break
    finally:
        state.ws_subscribers.discard(sub_tuple)

    return ws

# =====================================================================
# ADMIN API & WEB DASHBOARD
# =====================================================================

async def handle_admin_verify(request: web.Request):
    """Проверка валидности мастер-ключа админа."""
    if not is_admin(request):
        return web.json_response({"error": "Admin unauthorized", "authenticated": False}, status=403)
    return web.json_response({"status": "ok", "authenticated": True})

async def handle_admin_get_keys(request: web.Request):
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    keys_list = []
    for k, u in storage.data["users"].items():
        storage._normalize_user(u)
        keys_list.append({
            "id": u["id"],
            "owner": u["owner"],
            "api_key": u["api_key"],
            "enabled": u.get("enabled", True),
            "created_at": u.get("created_at", 0),
            "last_used_at": u.get("last_used_at", 0),
            "slots_count": len(u.get("slots", {})),
            "slots": u.get("slots", {}),
            "settings": u.get("settings", DEFAULT_USER_SETTINGS)
        })
    return web.json_response({"users": keys_list})

async def handle_admin_update_user_settings(request: web.Request):
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    key_id = request.match_info.get("key")
    try:
        data = await request.json()
        new_settings = storage.update_user_settings(key_id, data)
        if new_settings is None:
            return web.json_response({"error": "User not found"}, status=404)
        return web.json_response({"status": "success", "settings": new_settings})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)

async def handle_admin_create_key(request: web.Request):
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    data = await request.json()
    new_user = storage.create_user(owner_name=data.get("owner", "Пользователь"), custom_key=data.get("api_key"))
    return web.json_response({"status": "created", "user": new_user})

async def handle_admin_update_key(request: web.Request):
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    key_id = request.match_info.get("key")
    data = await request.json()
    ok = storage.update_user(api_key=key_id, owner_name=data.get("owner"), enabled=data.get("enabled"))
    return web.json_response({"status": "success" if ok else "not_found"})

async def handle_admin_delete_key(request: web.Request):
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    key_id = request.match_info.get("key")
    ok = storage.delete_user(api_key=key_id)
    return web.json_response({"status": "deleted" if ok else "not_found"})


# =====================================================================
# ADMIN HISTORY API ENDPOINTS
# =====================================================================

async def handle_admin_get_history(request: web.Request):
    """Список файлов истории, размер и количество целей для админки."""
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    summary = history_manager.get_admin_summary()
    return web.json_response(summary)

async def handle_admin_delete_history(request: web.Request):
    """Удаление помесячного файла истории."""
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    month_id = request.match_info.get("month")
    ok = history_manager.delete_month(month_id)
    return web.json_response({"status": "deleted" if ok else "not_found"})

async def handle_admin_download_history(request: web.Request):
    """Скачивание файла истории на ПК."""
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    month_id = request.match_info.get("month")
    fp = history_manager.get_month_filepath(month_id)
    if not fp: return web.json_response({"error": "File not found"}, status=404)
    with open(fp, "r", encoding="utf-8") as f:
        file_content = f.read()
    return web.Response(
        text=file_content,
        content_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="flight_history_{month_id}.json"'}
    )

async def handle_admin_upload_history(request: web.Request):
    """Загрузка внешнего JSON файла истории через админ-панель."""
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    try:
        data = await request.json()
        count = history_manager.import_external_history(data)
        return web.json_response({"status": "success", "imported_targets": count})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)

async def handle_admin_backup(request: web.Request):
    """Экспорт полной базы пользователей и слотов в JSON-файл."""
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    content = json.dumps(storage.data, ensure_ascii=False, indent=2)
    return web.Response(
        text=content,
        content_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="air_alert_backup_{int(time.time())}.json"'}
    )

async def handle_admin_restore(request: web.Request):
    """Импорт и восстановление базы пользователей и слотов из JSON."""
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    try:
        data = await request.json()
        if "users" not in data or not isinstance(data["users"], dict):
            return web.json_response({"error": "Неверный формат бэкапа: отсутствует раздел 'users'"}, status=400)
        storage.data = data
        storage.save()
        logger.info(f"База успешно восстановлена из бэкапа: {len(storage.data['users'])} пользователей")
        return web.json_response({"status": "success", "users_count": len(storage.data['users'])})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)

ADMIN_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Air Alert Hub - Менеджер ключей и локаций</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #0d1117; color: #c9d1d9; font-family: system-ui, -apple-system, sans-serif; }
    input::-ms-reveal, input::-ms-clear { display: none !important; }
  </style>
</head>
<body class="bg-[#0d1117] text-[#c9d1d9] min-h-screen">

  <!-- 1. ЭКРАН ВХОДА (LOGIN GATE) -->
  <div id="loginScreen" class="min-h-screen flex items-center justify-center p-4">
    <div class="bg-gray-900 border border-gray-800 rounded-2xl p-6 md:p-8 max-w-md w-full shadow-2xl">
      <div class="text-center mb-6">
        <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-950/70 border border-red-800/60 text-red-500 text-3xl mb-3 shadow-inner">
          🛡️
        </div>
        <h1 class="text-xl font-bold text-white tracking-wide">Air Alert Radar Hub</h1>
        <p class="text-xs text-gray-400 mt-1">Доступ к панели управления администратора</p>
      </div>

      <form id="loginForm" onsubmit="handleLoginSubmit(event)" class="space-y-4">
        <div>
          <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-2">Мастер-ключ администратора</label>
          <div class="relative">
            <input id="loginKeyInput" type="password" required autocomplete="current-password" placeholder="Введите мастер-ключ..." class="w-full bg-gray-950 border border-gray-700 px-3.5 py-2.5 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500 font-mono transition pr-10">
            <button type="button" onclick="const inp=document.getElementById('loginKeyInput'); if(inp){ inp.type = inp.type==='password' ? 'text' : 'password'; this.innerText = inp.type==='password' ? '👁️' : '🙈'; }" class="absolute right-3 top-2.5 text-gray-400 hover:text-white text-sm z-10 cursor-pointer select-none p-1 focus:outline-none" title="Показать/скрыть ключ" id="eyeIcon">👁️</button>
          </div>
        </div>

        <div class="flex items-center justify-between text-xs">
          <label class="flex items-center gap-2 text-gray-400 cursor-pointer select-none">
            <input type="checkbox" id="rememberKeyCheck" checked class="accent-emerald-500 rounded w-4 h-4 cursor-pointer">
            <span>Запомнить в этом браузере</span>
          </label>
        </div>

        <div id="loginError" class="hidden p-3 rounded-lg bg-red-950/80 border border-red-800 text-red-400 text-xs font-medium">
          ❌ Неверный мастер-ключ! Проверьте переменную ADMIN_SECRET_KEY в настройках контейнера.
        </div>

        <button type="submit" id="loginBtn" class="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-2.5 rounded-lg text-sm transition shadow-lg flex items-center justify-center gap-2 cursor-pointer">
          <span>🔓 Войти в панель управления</span>
        </button>
      </form>

      <div class="mt-6 pt-4 border-t border-gray-800 text-center">
        <p class="text-[11px] text-gray-500">
          Все добавленные ключи, координаты и настройки опасных зон сохраняются локально на диск в автоматическом режиме.
        </p>
      </div>
    </div>
  </div>

  <!-- 2. ОСНОВНОЙ ДАШБОРД (СКРЫТ ДО АВТОРИЗАЦИИ) -->
  <div id="adminApp" class="hidden max-w-5xl mx-auto p-4 md:p-8">
    <header class="flex flex-col md:flex-row justify-between items-start md:items-center pb-6 border-b border-gray-800 gap-4">
      <div>
        <h1 class="text-2xl font-bold text-white flex items-center gap-2">
          <span class="text-red-500">🛡️</span> Air Alert Radar Hub
        </h1>
        <p class="text-sm text-gray-400">Центр управления API-ключами, официальными сиренами и радаром (Home Assistant & ESP32)</p>
      </div>
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-2 bg-emerald-950/80 border border-emerald-800/80 px-3.5 py-1.5 rounded-lg shadow-sm">
          <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
          <span class="text-xs text-emerald-300 font-semibold font-mono">✅ Мастер-ключ принят | Админ</span>
        </div>
        <button onclick="handleLogout()" class="bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 hover:text-white px-3 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-1.5 shadow" title="Выйти из сессии админа">
          <span>🚪 Выйти</span>
        </button>
      </div>
    </header>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 my-5">
      <div class="bg-gray-900 border border-gray-800 p-3.5 rounded-lg flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div id="upstreamDot" class="w-3.5 h-3.5 rounded-full bg-emerald-500 animate-pulse"></div>
          <div>
            <div class="text-xs text-gray-400">Источник данных (Апстрим)</div>
            <div id="upstreamName" class="text-sm font-semibold text-white">Основной (WebSocket map.ukrainealarm.com)</div>
          </div>
        </div>
        <span id="upstreamBadge" class="bg-emerald-950 text-emerald-400 border border-emerald-800 text-xs px-2.5 py-0.5 rounded font-mono font-bold">ОСНОВНОЙ</span>
      </div>
      <div class="bg-gray-900 border border-gray-800 p-3.5 rounded-lg flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div id="proxyDot" class="w-3.5 h-3.5 rounded-full bg-blue-500"></div>
          <div>
            <div class="text-xs text-gray-400">Режим подключения</div>
            <div id="proxyName" class="text-sm font-semibold text-white">Прямое подключение (Без прокси)</div>
          </div>
        </div>
        <span id="proxyBadge" class="bg-blue-950 text-blue-400 border border-blue-800 text-xs px-2.5 py-0.5 rounded font-mono font-bold">DIRECT</span>
      </div>
    </div>

    <div id="unknownTypesBanner" class="hidden my-4 p-3.5 bg-amber-950/80 border border-amber-600 rounded-lg text-amber-200 text-xs flex items-center justify-between shadow-lg">
      <div class="flex items-center gap-2.5">
        <span class="text-base">⚠️</span>
        <div id="unknownTypesText"></div>
      </div>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 my-6">
      <div class="bg-gray-900 border border-gray-800 p-4 rounded-lg">
        <div class="text-xs text-gray-400">Физических целей в воздухе</div>
        <div id="statThreats" class="text-2xl font-bold text-red-400 mt-1">--</div>
      </div>
      <div class="bg-gray-900 border border-gray-800 p-4 rounded-lg">
        <div class="text-xs text-gray-400">Официальных сирен (области)</div>
        <div id="statSirens" class="text-2xl font-bold text-yellow-400 mt-1">--</div>
      </div>
      <div class="bg-gray-900 border border-gray-800 p-4 rounded-lg">
        <div class="text-xs text-gray-400">Угроза взлета МиГ-31К</div>
        <div id="statMig" class="text-2xl font-bold text-cyan-400 mt-1">--</div>
      </div>
      <div class="bg-gray-900 border border-gray-800 p-4 rounded-lg">
        <div class="text-xs text-gray-400">Всего API-ключей</div>
        <div id="statKeysCount" class="text-2xl font-bold text-blue-400 mt-1">--</div>
      </div>
    </div>

    <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden my-6 shadow-lg">
      <div class="p-4 border-b border-gray-800 flex flex-wrap justify-between items-center gap-3">
        <h2 class="font-semibold text-white">Список пользователей и ключей</h2>
        <div class="flex items-center gap-2">
          <button onclick="downloadBackup()" class="bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1 transition" title="Сохранить всех пользователей и слоты в JSON на свой ПК">📥 Скачать бэкап</button>
          <button onclick="document.getElementById('restoreFileInput').click()" class="bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1 transition" title="Восстановить ключи из сохранённого JSON-файла">📤 Восстановить бэкап</button>
          <input type="file" id="restoreFileInput" accept=".json" class="hidden" onchange="uploadBackup(event)">
          <button onclick="openCreateModal()" class="bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1.5 rounded text-xs font-semibold transition shadow">+ Создать ключ</button>
        </div>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-gray-950 text-gray-400 text-xs uppercase">
            <tr>
              <th class="p-3">Владелец</th>
              <th class="p-3">API Ключ</th>
              <th class="p-3">Статус</th>
              <th class="p-3">Опасная зона / Алерты</th>
              <th class="p-3">Был в сети</th>
              <th class="p-3 text-right">Действия</th>
            </tr>
          </thead>
          <tbody id="keysTableBody" class="divide-y divide-gray-800">
            <tr><td colspan="6" class="p-8 text-center text-gray-500">Загрузка данных...</td></tr>
          </tbody>
        </table>
      </div>
    </div>


    <!-- Панель управления архивом истории полетов -->
    <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden my-6 shadow-lg">
      <div class="p-4 border-b border-gray-800 flex flex-wrap justify-between items-center gap-3">
        <div>
          <h2 class="font-semibold text-white flex items-center gap-2">
            <span>📁 Архів історії польотів (Flight History)</span>
            <span id="histTotalBadge" class="text-xs bg-sky-950 text-sky-400 border border-sky-800 px-2 py-0.5 rounded-full font-mono">0 МБ</span>
          </h2>
          <p class="text-xs text-gray-400 mt-0.5">Помісячне збереження траєкторій цілей, оптимізація під SD-карту та керування архівами</p>
        </div>
        <div class="flex items-center gap-2">
          <button onclick="document.getElementById('histAdminFileInput').click()" class="bg-sky-600 hover:bg-sky-700 text-white px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1 transition" title="Завантажити JSON історії (наприклад, файл від друга)">📤 Додати JSON файл</button>
          <input type="file" id="histAdminFileInput" accept=".json" class="hidden" onchange="uploadAdminHistory(event)">
          <button onclick="loadAdminHistory()" class="bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 px-3 py-1.5 rounded text-xs font-semibold transition" title="Оновити список">🔄 Оновити</button>
        </div>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm text-gray-400">
          <thead class="bg-gray-950 text-gray-400 uppercase text-xs tracking-wider border-b border-gray-800">
            <tr>
              <th class="p-3">Місяць / Файл</th>
              <th class="p-3">Дні у файлі</th>
              <th class="p-3">Всього цілей</th>
              <th class="p-3">Розмір на диску</th>
              <th class="p-3">Останнє оновлення</th>
              <th class="p-3 text-right">Дії</th>
            </tr>
          </thead>
          <tbody id="histTableBody" class="divide-y divide-gray-800">
            <tr><td colspan="6" class="p-8 text-center text-gray-500">Завантаження архівів...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Панель настройки опасной зоны и фильтров алертов -->
    <div id="settingsSection" class="hidden bg-gray-900 border border-emerald-900/50 rounded-lg p-5 my-6 shadow-xl">
      <div class="flex justify-between items-center mb-4 border-b border-gray-800 pb-3">
        <div>
          <h3 class="font-bold text-white text-lg flex items-center gap-2">⚙️ Зона опасности и фильтры тревог: <span id="currentSettingsOwner" class="text-emerald-400"></span></h3>
          <p class="text-xs text-gray-400">Управляет расчетом радиуса поражения и срабатыванием звуковой сирены на ESP32 и в Home Assistant</p>
        </div>
        <button onclick="document.getElementById('settingsSection').classList.add('hidden')" class="text-gray-400 hover:text-white text-lg px-2">✕</button>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6 bg-gray-950 p-5 rounded-lg border border-gray-800">
        <!-- Зона опасности -->
        <div class="space-y-4">
          <div>
            <label class="block text-sm font-semibold text-white mb-2">Радиус зоны опасности по умолчанию (Default Danger Zone):</label>
            <div class="flex items-center gap-4">
              <input type="range" id="settingDangerRadiusRange" min="5" max="150" step="5" class="w-full accent-emerald-500 cursor-pointer" oninput="syncDangerRadius(this.value)">
              <div class="flex items-center gap-1.5 shrink-0">
                <input type="number" id="settingDangerRadiusNum" min="1" max="500" class="w-20 bg-gray-900 border border-gray-700 px-2.5 py-1.5 rounded text-white text-sm font-mono text-center" oninput="syncDangerRadius(this.value)">
                <span class="text-xs text-gray-400">км</span>
              </div>
            </div>
            <p class="text-xs text-gray-400 mt-2">
              Если любая цель (Шахед, ракета, КАБ) приближается ближе этой дистанции к выбранной локации, объявляется непосредственная угроза объекту и на экране ESP32 загорается красная зона.
            </p>

            <label class="flex items-center gap-2 mt-3 p-2 bg-gray-900/90 rounded border border-gray-800 cursor-pointer">
              <input type="checkbox" id="settingApplyToAllSlots" class="accent-emerald-500 rounded w-4 h-4 cursor-pointer">
              <span class="text-xs text-emerald-400 font-medium">Применить этот радиус сразу ко всем 5 точкам этого пользователя</span>
            </label>
          </div>
          <div class="bg-gray-900/70 p-3 rounded border border-gray-800 text-xs text-gray-300">
            <span class="text-emerald-400 font-semibold">Подсказка:</span> Вы также можете задать уникальный радиус для каждой из 5 точек отдельно через кнопку <span class="text-blue-400 font-semibold">«📍 Точки & Зоны (5)»</span> в таблице ключей.
          </div>
        </div>

        <!-- Фильтры алертов (ESP32) -->
        <div class="space-y-4">
          <label class="block text-sm font-semibold text-white mb-1">Восприятие тревог конечным устройством (Звук на ESP32 / Уведомления):</label>
          <div class="space-y-3 bg-gray-900/60 p-4 rounded-lg border border-gray-800">
            <label class="flex items-start gap-3 cursor-pointer">
              <input type="checkbox" id="settingAlertThreat" class="mt-0.5 rounded accent-emerald-500 w-4 h-4 cursor-pointer">
              <div>
                <span class="text-sm font-medium text-white">🎯 Физическая цель в зоне опасности (&lt; <span id="labelDangerKm" class="text-emerald-400 font-mono">35</span> км)</span>
                <p class="text-xs text-gray-400">Звуковой сигнал при приближении реального Шахеда/ракеты в радиус подлёта к выбранной точке.</p>
              </div>
            </label>

            <label class="flex items-start gap-3 cursor-pointer">
              <input type="checkbox" id="settingAlertSiren" class="mt-0.5 rounded accent-emerald-500 w-4 h-4 cursor-pointer">
              <div>
                <span class="text-sm font-medium text-white">📢 Официальная тревога в области слота</span>
                <p class="text-xs text-gray-400">Звуковой сигнал при включении областной сирены, даже если физических целей на радаре ещё не зафиксировано.</p>
              </div>
            </label>

            <label class="flex items-start gap-3 cursor-pointer">
              <input type="checkbox" id="settingAlertMig" class="mt-0.5 rounded accent-emerald-500 w-4 h-4 cursor-pointer">
              <div>
                <span class="text-sm font-medium text-white">✈️ Взлет МиГ-31К / Баллистическая угроза</span>
                <p class="text-xs text-gray-400">Всеукраинская тревога по гиперзвуковым ракетам «Кинжал» (включайте только если хотите просыпаться при каждом взлёте).</p>
              </div>
            </label>

            <label class="flex items-start gap-3 cursor-pointer">
              <input type="checkbox" id="settingAlertArtillery" class="mt-0.5 rounded accent-emerald-500 w-4 h-4 cursor-pointer">
              <div>
                <span class="text-sm font-medium text-white">💥 Угроза артобстрела / РСЗО</span>
                <p class="text-xs text-gray-400">Тревоги артиллерийского обстрела в прифронтовых районах (Никополь, Херсон, Харьков и др.).</p>
              </div>
            </label>
          </div>
        </div>
      </div>

      <div class="mt-5 flex justify-end items-center gap-3">
        <button onclick="document.getElementById('settingsSection').classList.add('hidden')" class="px-4 py-2 rounded text-xs text-gray-400 hover:text-white transition">Отмена</button>
        <button onclick="saveUserSettings()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold px-6 py-2 rounded text-xs transition shadow-lg flex items-center gap-1.5">💾 Сохранить настройки и алерты</button>
      </div>
    </div>

    <div id="slotsSection" class="hidden bg-gray-900 border border-blue-900/40 rounded-lg p-5 my-6 shadow-xl">
      <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-4 border-b border-gray-800 pb-3 gap-3">
        <div>
          <div class="flex items-center gap-2 flex-wrap">
            <h3 class="font-bold text-white text-lg flex items-center gap-2">
              <span>📍 Точки и зоны опасности:</span>
              <span id="currentSlotOwner" class="text-blue-400 font-mono"></span>
            </h3>
            <span id="slotsCountBadge" class="bg-blue-950/80 text-blue-400 border border-blue-800 text-xs px-2.5 py-0.5 rounded font-mono font-bold">0 / 5 точек</span>
          </div>
          <p class="text-xs text-gray-400 mt-0.5">Каждая точка имеет свои координаты и собственный радиус опасной зоны (Danger Zone)</p>
        </div>
        <div class="flex items-center gap-2 self-end sm:self-auto">
          <button id="addSlotBtn" onclick="toggleAddSlotForm()" class="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-3.5 py-1.5 rounded transition flex items-center gap-1.5 font-semibold shadow">
            <span>➕ Добавить точку</span>
          </button>
          <button onclick="document.getElementById('slotsSection').classList.add('hidden')" class="text-gray-400 hover:text-white text-xl px-2">✕</button>
        </div>
      </div>

      <!-- Карточка добавления новой точки -->
      <div id="addSlotFormCard" class="hidden bg-gray-950 border border-emerald-800/60 p-4 rounded-lg mb-5 shadow-lg">
        <div class="flex justify-between items-center mb-3 pb-2 border-b border-gray-800">
          <div class="text-sm font-bold text-emerald-400 flex items-center gap-1.5">
            <span>➕ Добавление новой точки</span>
            <span class="text-xs font-normal text-gray-400 font-mono">(лимит: до 5 точек на ключ)</span>
          </div>
          <button onclick="toggleAddSlotForm(false)" class="text-gray-500 hover:text-white text-sm">✕</button>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label class="block text-[11px] font-semibold text-gray-400 mb-1">Название точки:</label>
            <input id="newSlotName" type="text" class="w-full bg-gray-900 border border-gray-700 px-2.5 py-1.5 rounded text-sm text-white focus:border-emerald-500 focus:outline-none" placeholder="Дом, Офис, Дача, Склад...">
          </div>
          <div>
            <label class="block text-[11px] font-semibold text-gray-400 mb-1">Широта (Latitude):</label>
            <input id="newSlotLat" type="number" step="0.0001" class="w-full bg-gray-900 border border-gray-700 px-2.5 py-1.5 rounded text-sm text-white font-mono focus:border-emerald-500 focus:outline-none" placeholder="50.4501">
          </div>
          <div>
            <label class="block text-[11px] font-semibold text-gray-400 mb-1">Долгота (Longitude):</label>
            <input id="newSlotLon" type="number" step="0.0001" class="w-full bg-gray-900 border border-gray-700 px-2.5 py-1.5 rounded text-sm text-white font-mono focus:border-emerald-500 focus:outline-none" placeholder="30.5234">
          </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3 pt-3 border-t border-gray-900">
          <div>
            <div class="flex justify-between items-center text-xs text-gray-300 mb-1">
              <span class="font-semibold">🚨 Опасная зона (Danger Zone):</span>
              <span class="font-mono text-emerald-400 font-bold" id="newSlotDangerVal">35 км</span>
            </div>
            <div class="flex items-center gap-2">
              <input type="range" min="5" max="150" step="5" value="35" id="newSlotDangerRange" class="w-full accent-emerald-500 cursor-pointer" oninput="syncNewSlotDanger(this.value)">
              <div class="flex items-center gap-1 shrink-0">
                <input type="number" min="1" max="500" value="35" id="newSlotDangerNum" class="w-16 bg-gray-900 border border-gray-700 px-1.5 py-1 rounded text-xs text-white font-mono text-center" oninput="syncNewSlotDanger(this.value)">
                <span class="text-[10px] text-gray-400">км</span>
              </div>
            </div>
          </div>
          <div>
            <label class="block text-[11px] font-semibold text-gray-400 mb-1">Тип локации:</label>
            <select id="newSlotType" class="w-full bg-gray-900 border border-gray-700 px-2.5 py-1.5 rounded text-xs text-white focus:border-emerald-500 focus:outline-none">
              <option value="static">Статическая (постоянные координаты)</option>
              <option value="dynamic">Динамическая (GPS координаты со смартфона / HA)</option>
            </select>
          </div>
        </div>
        <div class="mt-4 flex justify-end items-center gap-2">
          <button onclick="toggleAddSlotForm(false)" class="px-3 py-1.5 text-xs text-gray-400 hover:text-white">Отмена</button>
          <button onclick="submitNewSlot()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold px-4 py-1.5 rounded text-xs transition shadow flex items-center gap-1">
            <span>💾 Сохранить и добавить точку</span>
          </button>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4" id="slotsCardsContainer"></div>
    </div>
  </div>

  <script>
    let currentAdminKey = "";
    let cachedUsers = {};
    let currentEditApiKey = "";
    let telemetryInterval = null;

    function togglePasswordVisibility(inputId, iconId) {
      const input = document.getElementById(inputId);
      const icon = document.getElementById(iconId);
      if (!input) return;
      if (input.type === "password") {
        input.type = "text";
        if (icon) icon.innerText = "🙈";
      } else {
        input.type = "password";
        if (icon) icon.innerText = "👁️";
      }
    }

    function handleAddSlotLimit() {
      alert(`⚠️ Достигнут лимит точек (Limit reached)!\n\nДля каждого API-ключа разрешено максимум 5 локаций (слоты 1..5).\n\nЧтобы добавить новую локацию, сначала удалите одну из ненужных точек (иконка 🗑️ на карточке).`);
    }

    function toggleAddSlotForm(show) {
      const card = document.getElementById("addSlotFormCard");
      if (!card) return;
      if (show === undefined) {
        card.classList.toggle("hidden");
      } else if (show) {
        card.classList.remove("hidden");
      } else {
        card.classList.add("hidden");
      }
      if (!card.classList.contains("hidden")) {
        const inp = document.getElementById("newSlotName");
        if (inp) inp.focus();
      }
    }

    function syncNewSlotDanger(val) {
      const r = document.getElementById("newSlotDangerRange");
      const n = document.getElementById("newSlotDangerNum");
      const l = document.getElementById("newSlotDangerVal");
      if (r) r.value = val;
      if (n) n.value = val;
      if (l) l.innerText = val + " км";
    }

    async function verifyKeyOnServer(key) {
      if (!key) return false;
      try {
        const res = await fetch("/api/v1/admin/verify?admin_key=" + encodeURIComponent(key));
        return res.ok;
      } catch (e) {
        return false;
      }
    }

    async function handleLoginSubmit(event) {
      if (event) event.preventDefault();
      const input = document.getElementById("loginKeyInput");
      const errBox = document.getElementById("loginError");
      const btn = document.getElementById("loginBtn");
      const key = input.value.trim();

      if (!key) {
        errBox.innerText = "❌ Пожалуйста, введите мастер-ключ админа";
        errBox.classList.remove("hidden");
        return;
      }

      btn.disabled = true;
      btn.innerHTML = `<span class="animate-spin inline-block mr-2">⏳</span> Проверка ключа...`;
      errBox.classList.add("hidden");

      const ok = await verifyKeyOnServer(key);
      btn.disabled = false;
      btn.innerHTML = `<span>🔓 Войти в панель управления</span>`;

      if (ok) {
        currentAdminKey = key;
        const remember = document.getElementById("rememberKeyCheck").checked;
        if (remember) {
          localStorage.setItem("hub_admin_key", key);
        } else {
          sessionStorage.setItem("hub_admin_key", key);
          localStorage.removeItem("hub_admin_key");
        }
        showAdminApp();
      } else {
        errBox.innerText = "❌ Неверный мастер-ключ администратора! Проверьте переменную ADMIN_SECRET_KEY.";
        errBox.classList.remove("hidden");
        input.focus();
        input.select();
      }
    }

    function showAdminApp() {
      document.getElementById("loginScreen").classList.add("hidden");
      document.getElementById("adminApp").classList.remove("hidden");
      updateTelemetry();
      loadKeys();
      if (!telemetryInterval) {
        telemetryInterval = setInterval(updateTelemetry, 4000);
      }
    }

    function showLoginScreen() {
      if (telemetryInterval) {
        clearInterval(telemetryInterval);
        telemetryInterval = null;
      }
      document.getElementById("adminApp").classList.add("hidden");
      document.getElementById("loginScreen").classList.remove("hidden");
      document.getElementById("loginKeyInput").value = "";
      document.getElementById("loginError").classList.add("hidden");
      setTimeout(() => {
        const inp = document.getElementById("loginKeyInput");
        if (inp) inp.focus();
      }, 100);
    }

    function handleLogout() {
      localStorage.removeItem("hub_admin_key");
      sessionStorage.removeItem("hub_admin_key");
      currentAdminKey = "";
      cachedUsers = {};
      showLoginScreen();
    }

    async function initAuth() {
      const savedKey = localStorage.getItem("hub_admin_key") || sessionStorage.getItem("hub_admin_key") || "";
      if (savedKey) {
        const ok = await verifyKeyOnServer(savedKey);
        if (ok) {
          currentAdminKey = savedKey;
          showAdminApp();
          return;
        } else {
          localStorage.removeItem("hub_admin_key");
          sessionStorage.removeItem("hub_admin_key");
        }
      }
      showLoginScreen();
    }

    function syncDangerRadius(val) {
      document.getElementById("settingDangerRadiusRange").value = val;
      document.getElementById("settingDangerRadiusNum").value = val;
      document.getElementById("labelDangerKm").innerText = val;
    }

    function syncSlotDanger(slotId, val) {
      const r = document.getElementById("danger_range_" + slotId);
      const n = document.getElementById("danger_num_" + slotId);
      const l = document.getElementById("danger_val_" + slotId);
      if (r) r.value = val;
      if (n) n.value = val;
      if (l) l.innerText = val + " км";
    }

    function openUserSettings(apiKey) {
      const u = cachedUsers[apiKey];
      if (!u) return alert("Пользователь не найден");
      currentEditApiKey = apiKey;
      document.getElementById("currentSettingsOwner").innerText = u.owner;
      document.getElementById("slotsSection").classList.add("hidden");
      document.getElementById("settingsSection").classList.remove("hidden");

      const s = u.settings || { danger_radius_km: 35, alert_threat: true, alert_siren: true, alert_mig: false, alert_artillery: false };
      syncDangerRadius(s.danger_radius_km || 35);
      const applyAllCheck = document.getElementById("settingApplyToAllSlots");
      if (applyAllCheck) applyAllCheck.checked = false;

      document.getElementById("settingAlertThreat").checked = s.alert_threat !== false;
      document.getElementById("settingAlertSiren").checked = s.alert_siren !== false;
      document.getElementById("settingAlertMig").checked = !!s.alert_mig;
      document.getElementById("settingAlertArtillery").checked = !!s.alert_artillery;

      document.getElementById("settingsSection").scrollIntoView({ behavior: "smooth" });
    }

    async function saveUserSettings() {
      if (!currentEditApiKey || !currentAdminKey) return;
      const radius = parseFloat(document.getElementById("settingDangerRadiusNum").value) || 35;
      const applyAll = document.getElementById("settingApplyToAllSlots") ? document.getElementById("settingApplyToAllSlots").checked : false;
      const payload = {
        danger_radius_km: radius,
        apply_to_all_slots: applyAll,
        alert_threat: document.getElementById("settingAlertThreat").checked,
        alert_siren: document.getElementById("settingAlertSiren").checked,
        alert_mig: document.getElementById("settingAlertMig").checked,
        alert_artillery: document.getElementById("settingAlertArtillery").checked
      };

      try {
        const res = await fetch("/api/v1/admin/keys/" + encodeURIComponent(currentEditApiKey) + "/settings?admin_key=" + encodeURIComponent(currentAdminKey), {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          alert("✅ Настройки успешно сохранены локально в базу данных!");
          document.getElementById("settingsSection").classList.add("hidden");
          loadKeys();
        } else {
          const err = await res.json();
          alert("Ошибка сохранения настроек: " + (err.error || "Неизвестная ошибка"));
        }
      } catch (e) {
        alert("Ошибка сети: " + e);
      }
    }

    async function updateTelemetry() {
      try {
        const hRes = await fetch("/api/v1/health");
        if (!hRes.ok) return;
        const hData = await hRes.json();

        document.getElementById("statThreats").innerText = hData.active_threats_count ?? "--";
        document.getElementById("statSirens").innerText = hData.official_sirens_count ?? "--";
        document.getElementById("statMig").innerText = hData.mig31k_active ? "АКТИВНА" : "НЕТ";
        document.getElementById("statMig").className = "text-2xl font-bold mt-1 " + (hData.mig31k_active ? "text-red-400 animate-pulse" : "text-cyan-400");

        // Upstream provider
        const upName = document.getElementById("upstreamName");
        const upDot = document.getElementById("upstreamDot");
        const upBadge = document.getElementById("upstreamBadge");
        if (hData.upstream_provider === "ukrainealarm") {
          upName.innerText = "Основной поток (WebSocket map.ukrainealarm.com)";
          upDot.className = "w-3.5 h-3.5 rounded-full bg-emerald-500 animate-pulse";
          upBadge.innerText = "ОСНОВНОЙ";
          upBadge.className = "bg-emerald-950 text-emerald-400 border border-emerald-800 text-xs px-2.5 py-0.5 rounded font-mono font-bold";
        } else if (hData.upstream_provider === "neptun_failover") {
          upName.innerText = "Резервный поток (REST neptun.in.ua)";
          upDot.className = "w-3.5 h-3.5 rounded-full bg-amber-500 animate-pulse";
          upBadge.innerText = "FAILOVER";
          upBadge.className = "bg-amber-950 text-amber-400 border border-amber-800 text-xs px-2.5 py-0.5 rounded font-mono font-bold";
        } else {
          upName.innerText = "Ожидание подключения...";
          upDot.className = "w-3.5 h-3.5 rounded-full bg-gray-500";
          upBadge.innerText = "CONNECTING";
          upBadge.className = "bg-gray-800 text-gray-400 border border-gray-700 text-xs px-2.5 py-0.5 rounded font-mono";
        }

        // Proxy
        const pName = document.getElementById("proxyName");
        const pDot = document.getElementById("proxyDot");
        const pBadge = document.getElementById("proxyBadge");
        if (hData.proxy_enabled) {
          pName.innerText = "Прокси активен (" + hData.proxy_info + ")";
          pDot.className = "w-3.5 h-3.5 rounded-full bg-emerald-500";
          pBadge.innerText = "PROXY";
          pBadge.className = "bg-emerald-950 text-emerald-400 border border-emerald-800 text-xs px-2.5 py-0.5 rounded font-mono font-bold";
        } else {
          pName.innerText = "Прямое подключение (Без прокси)";
          pDot.className = "w-3.5 h-3.5 rounded-full bg-blue-500";
          pBadge.innerText = "DIRECT";
          pBadge.className = "bg-blue-950 text-blue-400 border border-blue-800 text-xs px-2.5 py-0.5 rounded font-mono font-bold";
        }

        // Unknown target types banner
        const unkBanner = document.getElementById("unknownTypesBanner");
        const unkText = document.getElementById("unknownTypesText");
        if (unkBanner && unkText) {
          if (hData.unknown_target_types_count > 0) {
            const listStr = hData.unknown_target_types.map(x => `${x.type_identifier} (код: ${x.raw_code}, повторень: ${x.count})`).join(", ");
            unkText.innerHTML = `<b>Увага: виявлено новий невідомий тип цілі в ефірі:</b> ${listStr}. Ціль автоматично супроводжується як <i>"Ціль не визначена"</i> із збереженням усіх алерів та координат.`;
            unkBanner.classList.remove("hidden");
          } else {
            unkBanner.classList.add("hidden");
          }
        }
      } catch(e) {}
    }

    async function loadKeys() {
      if (!currentAdminKey) return showLoginScreen();

      updateTelemetry();

      try {
        const res = await fetch("/api/v1/admin/keys?admin_key=" + encodeURIComponent(currentAdminKey));
        if (res.status === 403) {
          alert("Сессия администратора истекла или ключ неверен!");
          return handleLogout();
        }
        const data = await res.json();
        document.getElementById("statKeysCount").innerText = data.users.length;
        renderKeysTable(data.users);
      } catch(e) { 
        alert("Ошибка загрузки списка ключей: " + e); 
      }
    }

    function renderKeysTable(users) {
      cachedUsers = {};
      const tbody = document.getElementById("keysTableBody");
      tbody.innerHTML = "";

      if (!users || users.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" class="p-8 text-center text-gray-400">
              <div class="text-3xl mb-2">📭</div>
              <div class="font-semibold text-white text-base">Нет созданных API-ключей</div>
              <p class="text-xs text-gray-500 mt-1 max-w-md mx-auto">
                База данных пустая. Нажмите кнопку <span class="text-emerald-400 font-semibold">«+ Создать ключ»</span> выше, чтобы добавить первый API-ключ для ESP32 или Home Assistant.
              </p>
            </td>
          </tr>
        `;
        return;
      }

      users.forEach(u => {
        cachedUsers[u.api_key] = u;
        const lastSeen = u.last_used_at ? new Date(u.last_used_at * 1000).toLocaleTimeString() : "Никогда";
        const s = u.settings || { danger_radius_km: 35, alert_threat: true, alert_siren: true, alert_mig: false, alert_artillery: false };

        // Генерируем компактные плашки с радиусом опасной зоны для каждого слота отдельно
        const slotsObj = u.slots || {};
        const slotsCount = Object.keys(slotsObj).length;
        const slotsBadges = Object.keys(slotsObj).sort().map(sid => {
          const sl = slotsObj[sid];
          const rad = sl.danger_radius_km ?? s.danger_radius_km ?? 35;
          const isDyn = sl.type === "dynamic";
          return `<span class="inline-block bg-gray-950 border border-gray-800 px-2 py-0.5 rounded text-[11px] text-gray-300" title="Точка #${sid}: ${sl.name || 'Слот'} (${sl.lat}, ${sl.lon})">
            <span class="text-gray-400 font-medium">#${sid}${isDyn ? ' 📡' : ''} ${sl.name || 'Точка'}:</span> 
            <span class="text-emerald-400 font-mono font-bold">${rad} км</span>
          </span>`;
        }).join(" ");

        const safeOwner = (u.owner || 'Пользователь').replace(/'/g, "\\'");
        const tr = document.createElement("tr");
        tr.className = "hover:bg-gray-800/50 transition";
        tr.innerHTML = `
          <td class="p-3 font-medium text-white">${u.owner}</td>
          <td class="p-3 font-mono text-xs text-gray-300">
            <span class="bg-gray-950 px-2 py-1 rounded border border-gray-800 select-all">${u.api_key}</span>
          </td>
          <td class="p-3">
            <span class="px-2 py-0.5 text-xs rounded font-semibold ${u.enabled ? 'bg-emerald-900/60 text-emerald-400' : 'bg-red-900/60 text-red-400'}">
              ${u.enabled ? 'Активен' : 'Отключен'}
            </span>
          </td>
          <td class="p-3">
            <div class="text-[11px] text-gray-300 font-semibold mb-1">Зоны опасности (по точкам):</div>
            <div class="flex flex-wrap gap-1 mb-2">
              ${slotsCount > 0 ? slotsBadges : '<span class="text-xs text-gray-500 italic">Точки не добавлены (0/5)</span>'}
            </div>
            <div class="text-[11px] text-gray-400 flex flex-wrap gap-1">
              ${s.alert_threat ? '<span class="bg-red-950/80 text-red-400 border border-red-900/60 px-1.5 py-0.5 rounded">🎯 Цели</span>' : '<span class="bg-gray-900 text-gray-600 line-through px-1.5 py-0.5 rounded">🎯 Цели</span>'}
              ${s.alert_siren ? '<span class="bg-yellow-950/80 text-yellow-400 border border-yellow-900/60 px-1.5 py-0.5 rounded">📢 Сирена</span>' : '<span class="bg-gray-900 text-gray-600 line-through px-1.5 py-0.5 rounded">📢 Сирена</span>'}
              ${s.alert_mig ? '<span class="bg-cyan-950/80 text-cyan-400 border border-cyan-900/60 px-1.5 py-0.5 rounded">✈️ МиГ</span>' : ''}
              ${s.alert_artillery ? '<span class="bg-amber-950/80 text-amber-400 border border-amber-900/60 px-1.5 py-0.5 rounded">💥 Арта</span>' : ''}
            </div>
          </td>
          <td class="p-3 text-xs text-gray-400">${lastSeen}</td>
          <td class="p-3 text-right space-x-1.5 whitespace-nowrap">
            <button onclick="editUserSlots('${u.api_key}', '${safeOwner}')" class="bg-blue-600 hover:bg-blue-500 text-white px-2.5 py-1 rounded text-xs font-semibold transition" title="Настроить локации и зоны опасности">📍 Точки (${slotsCount}/5)</button>
            <button onclick="openUserSettings('${u.api_key}')" class="bg-emerald-600 hover:bg-emerald-500 text-white px-2.5 py-1 rounded text-xs font-semibold transition" title="Настроить типы звуковых алертов">🔔 Алерты</button>
            <button onclick="toggleKey('${u.api_key}', ${!u.enabled})" class="bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 px-2 py-1 rounded text-xs transition">${u.enabled ? 'Выкл' : 'Вкл'}</button>
            <button onclick="deleteKey('${u.api_key}')" class="text-red-400 hover:text-red-300 px-2 py-1 text-xs transition">Удалить</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function editUserSlots(apiKey, owner) {
      if (!currentAdminKey) return showLoginScreen();
      currentEditApiKey = apiKey;
      const res = await fetch("/api/v1/slots?token=" + encodeURIComponent(apiKey) + "&admin_key=" + encodeURIComponent(currentAdminKey));
      if (!res.ok) return alert("Ошибка чтения слотов пользователя");
      const data = await res.json();

      document.getElementById("settingsSection").classList.add("hidden");
      document.getElementById("slotsSection").classList.remove("hidden");
      document.getElementById("currentSlotOwner").innerText = owner;
      toggleAddSlotForm(false);

      const slotsKeys = Object.keys(data.slots || {}).sort();
      const slotsCount = slotsKeys.length;
      const badge = document.getElementById("slotsCountBadge");
      const addBtn = document.getElementById("addSlotBtn");

      if (slotsCount >= 5) {
        if (badge) {
          badge.className = "bg-amber-950/80 text-amber-400 border border-amber-800 text-xs px-2.5 py-0.5 rounded font-mono font-bold";
          badge.innerText = "5 / 5 точек (Лимит исчерпан)";
        }
        if (addBtn) {
          addBtn.className = "bg-gray-800 text-gray-500 border border-gray-700 text-xs px-3.5 py-1.5 rounded flex items-center gap-1.5 font-semibold cursor-not-allowed";
          addBtn.title = "Достигнут лимит 5 точек. Удалите одну точку, чтобы добавить новую.";
          addBtn.onclick = handleAddSlotLimit;
        }
      } else {
        if (badge) {
          badge.className = "bg-blue-950/80 text-blue-400 border border-blue-800 text-xs px-2.5 py-0.5 rounded font-mono font-bold";
          badge.innerText = `${slotsCount} / 5 точек`;
        }
        if (addBtn) {
          addBtn.className = "bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-3.5 py-1.5 rounded transition flex items-center gap-1.5 font-semibold shadow";
          addBtn.title = "Добавить новую точку (до 5)";
          addBtn.onclick = () => toggleAddSlotForm();
        }
      }

      const container = document.getElementById("slotsCardsContainer");
      container.innerHTML = "";

      if (slotsCount === 0) {
        container.innerHTML = `
          <div class="col-span-full bg-gray-950 border border-dashed border-gray-800 p-8 rounded-lg text-center">
            <div class="text-3xl mb-2">📍</div>
            <div class="text-white font-semibold text-sm">Точки ещё не добавлены (0 / 5)</div>
            <p class="text-xs text-gray-500 mt-1 max-w-md mx-auto mb-4">
              У этого пользователя пока нет настроенных точек. Вы можете по очереди добавить до 5 локаций (например: Дом, Работа, Родители, GPS со смартфона).
            </p>
            <button onclick="toggleAddSlotForm(true)" class="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded text-xs font-semibold shadow transition inline-flex items-center gap-1.5">
              <span>➕ Добавить первую точку</span>
            </button>
          </div>
        `;
      } else {
        slotsKeys.forEach(slotId => {
          const s = data.slots[slotId];
          const isDyn = s.type === "dynamic";
          const dangerRadius = s.danger_radius_km ?? 35;
          const safeName = (s.name || ('Точка #' + slotId)).replace(/'/g, "\\'");
          const card = document.createElement("div");
          card.className = "bg-gray-950 border border-gray-800 p-4 rounded-lg space-y-3";
          card.innerHTML = `
            <div class="flex justify-between items-center pb-2 border-b border-gray-800/80">
              <div class="flex items-center gap-2">
                <span class="w-6 h-6 rounded-full bg-blue-900/60 text-blue-300 flex items-center justify-center text-xs font-bold font-mono">#${slotId}</span>
                <span class="text-sm font-bold text-white">${s.name || ('Слот #' + slotId)}</span>
              </div>
              <div class="flex items-center gap-2">
                <span class="text-[10px] px-2 py-0.5 rounded font-mono font-medium ${isDyn ? 'bg-purple-900/60 text-purple-300 border border-purple-800' : 'bg-blue-900/60 text-blue-300 border border-blue-800'}">${isDyn ? 'GPS ДИНАМИЧЕСКИЙ' : 'СТАТИЧЕСКИЙ'}</span>
                <button onclick="deleteSlot('${apiKey}', '${slotId}', '${safeName}')" class="text-red-400 hover:text-red-200 hover:bg-red-950/80 px-1.5 py-0.5 rounded transition text-xs font-bold" title="Удалить эту точку">🗑️</button>
              </div>
            </div>

            <div class="space-y-2">
              <div>
                <label class="block text-[11px] font-semibold text-gray-400 mb-1">Название точки:</label>
                <input id="name_${slotId}" type="text" value="${s.name || ''}" class="w-full bg-gray-900 border border-gray-700 px-2.5 py-1.5 rounded text-sm text-white focus:border-blue-500 focus:outline-none" placeholder="Дом, Работа, Дача...">
              </div>
              <div class="grid grid-cols-2 gap-2">
                <div>
                  <label class="block text-[11px] font-semibold text-gray-400 mb-1">Широта (Lat):</label>
                  <input id="lat_${slotId}" type="number" step="0.0001" value="${s.lat}" class="w-full bg-gray-900 border border-gray-700 px-2 py-1 rounded text-xs text-white font-mono" placeholder="50.4501">
                </div>
                <div>
                  <label class="block text-[11px] font-semibold text-gray-400 mb-1">Долгота (Lon):</label>
                  <input id="lon_${slotId}" type="number" step="0.0001" value="${s.lon}" class="w-full bg-gray-900 border border-gray-700 px-2 py-1 rounded text-xs text-white font-mono" placeholder="30.5234">
                </div>
              </div>

              <div class="pt-2 border-t border-gray-900">
                <div class="flex justify-between items-center text-xs text-gray-300 mb-1">
                  <span class="font-semibold flex items-center gap-1">🚨 Опасная зона (Danger Zone):</span>
                  <span class="font-mono text-emerald-400 font-bold" id="danger_val_${slotId}">${dangerRadius} км</span>
                </div>
                <div class="flex items-center gap-2">
                  <input type="range" min="5" max="150" step="5" value="${dangerRadius}" id="danger_range_${slotId}" class="w-full accent-emerald-500 cursor-pointer" oninput="syncSlotDanger('${slotId}', this.value)">
                  <div class="flex items-center gap-1 shrink-0">
                    <input type="number" min="1" max="500" value="${dangerRadius}" id="danger_num_${slotId}" class="w-16 bg-gray-900 border border-gray-700 px-1.5 py-1 rounded text-xs text-white font-mono text-center" oninput="syncSlotDanger('${slotId}', this.value)">
                    <span class="text-[10px] text-gray-400">км</span>
                  </div>
                </div>
                <p class="text-[10px] text-gray-500 mt-1">Персональный радиус подлёта цели к этой точке</p>
              </div>

              <button onclick="saveSlot('${apiKey}', '${slotId}')" class="w-full bg-blue-600/80 hover:bg-blue-600 text-white py-1.5 rounded text-xs font-semibold mt-2 transition shadow flex items-center justify-center gap-1">
                💾 Сохранить точку #${slotId}
              </button>
            </div>
          `;
          container.appendChild(card);
        });
      }

      document.getElementById("slotsSection").scrollIntoView({ behavior: "smooth" });
    }

    async function saveSlot(apiKey, slotId) {
      if (!currentAdminKey) return showLoginScreen();
      const name = document.getElementById("name_" + slotId).value;
      const lat = parseFloat(document.getElementById("lat_" + slotId).value);
      const lon = parseFloat(document.getElementById("lon_" + slotId).value);
      const danger_radius_km = parseFloat(document.getElementById("danger_num_" + slotId).value) || 35.0;

      try {
        const res = await fetch("/api/v1/slots/" + slotId + "?token=" + encodeURIComponent(apiKey) + "&admin_key=" + encodeURIComponent(currentAdminKey), {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, lat, lon, danger_radius_km })
        });
        if (res.ok) {
          alert("✅ Точка #" + slotId + " (" + name + ") с радиусом " + danger_radius_km + " км успешно сохранена на диск!");
          loadKeys();
        } else {
          const err = await res.json();
          alert("Ошибка сохранения: " + (err.error || "Неизвестная ошибка"));
        }
      } catch (e) {
        alert("Ошибка сети: " + e);
      }
    }

    async function submitNewSlot() {
      if (!currentEditApiKey || !currentAdminKey) return;
      const name = document.getElementById("newSlotName").value.trim();
      const latStr = document.getElementById("newSlotLat").value.trim();
      const lonStr = document.getElementById("newSlotLon").value.trim();
      const dangerRadius = parseFloat(document.getElementById("newSlotDangerNum").value) || 35;
      const slotType = document.getElementById("newSlotType").value || "static";

      if (!latStr || !lonStr) {
        alert("❌ Пожалуйста, введите широту (Lat) и долготу (Lon) точки!");
        return;
      }
      const lat = parseFloat(latStr);
      const lon = parseFloat(lonStr);
      if (isNaN(lat) || isNaN(lon)) {
        alert("❌ Координаты должны быть валидными числами (например: 50.4501, 30.5234)!");
        return;
      }

      try {
        const res = await fetch("/api/v1/slots?token=" + encodeURIComponent(currentEditApiKey) + "&admin_key=" + encodeURIComponent(currentAdminKey), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: name || undefined,
            lat: lat,
            lon: lon,
            danger_radius_km: dangerRadius,
            type: slotType
          })
        });
        const resp = await res.json();
        if (res.ok && resp.status === "success") {
          alert("✅ Точка «" + (resp.slot.name || ("#" + resp.slot.id)) + "» успешно добавлена!");
          toggleAddSlotForm(false);
          document.getElementById("newSlotName").value = "";
          document.getElementById("newSlotLat").value = "";
          document.getElementById("newSlotLon").value = "";
          const user = cachedUsers[currentEditApiKey];
          editUserSlots(currentEditApiKey, user ? user.owner : "Пользователь");
          loadKeys();
        } else {
          alert("❌ Ошибка добавления точки: " + (resp.message || resp.error || "Неизвестная ошибка"));
        }
      } catch (e) {
        alert("❌ Ошибка сети: " + e);
      }
    }

    async function deleteSlot(apiKey, slotId, slotName) {
      if (!currentAdminKey) return showLoginScreen();
      if (!confirm("Вы действительно хотите удалить точку #" + slotId + " («" + slotName + "»)?")) return;

      try {
        const res = await fetch("/api/v1/slots/" + encodeURIComponent(slotId) + "?token=" + encodeURIComponent(apiKey) + "&admin_key=" + encodeURIComponent(currentAdminKey), {
          method: "DELETE"
        });
        const resp = await res.json();
        if (res.ok && resp.status === "deleted") {
          alert("✅ Точка #" + slotId + " успешно удалена!");
          const user = cachedUsers[apiKey];
          editUserSlots(apiKey, user ? user.owner : "Пользователь");
          loadKeys();
        } else {
          alert("❌ Ошибка удаления точки: " + (resp.error || "Неизвестная ошибка"));
        }
      } catch (e) {
        alert("❌ Ошибка сети: " + e);
      }
    }

    async function toggleKey(key, enabled) {
      if (!currentAdminKey) return showLoginScreen();
      await fetch("/api/v1/admin/keys/" + encodeURIComponent(key) + "?admin_key=" + encodeURIComponent(currentAdminKey), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled })
      });
      loadKeys();
    }

    async function deleteKey(key) {
      if (!currentAdminKey) return showLoginScreen();
      if (!confirm("Вы уверены, что хотите отозвать этот API-ключ?")) return;
      await fetch("/api/v1/admin/keys/" + encodeURIComponent(key) + "?admin_key=" + encodeURIComponent(currentAdminKey), {
        method: "DELETE"
      });
      loadKeys();
    }

    async function openCreateModal() {
      if (!currentAdminKey) return showLoginScreen();
      const owner = prompt("Введите имя владельца (например: 'Жена (Анна)', 'Сын', 'Домашний ESP32'):");
      if (!owner || !owner.trim()) return;
      try {
        const res = await fetch("/api/v1/admin/keys?admin_key=" + encodeURIComponent(currentAdminKey), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ owner: owner.trim() })
        });
        if (res.ok) {
          alert("✅ Ключ для '" + owner.trim() + "' успешно создан и сохранён на диск!");
          loadKeys();
        } else {
          const err = await res.json().catch(() => ({}));
          alert("❌ Ошибка создания ключа: " + (err.error || "Не авторизован"));
        }
      } catch (e) {
        alert("Ошибка сети: " + e);
      }
    }


    async function loadAdminHistory() {
      const tbody = document.getElementById("histTableBody");
      const badge = document.getElementById("histTotalBadge");
      if (!tbody) return;
      try {
        const res = await fetch("/api/v1/admin/history?admin_key=" + encodeURIComponent(currentAdminKey));
        if (!res.ok) return;
        const data = await res.json();
        
        if (badge) {
          badge.innerText = `${data.total_size_mb} (${data.total_targets} цілей)`;
        }

        if (!data.files || data.files.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" class="p-8 text-center text-gray-500">Архів історії порожній. Нові цілі будуть записуватися сюди автоматично кожні 5 хвилин.</td></tr>';
          return;
        }

        let html = "";
        data.files.forEach(f => {
          const datesStr = f.dates && f.dates.length > 0 ? f.dates.join(", ") : "Немає";
          const updatedStr = f.updated_at ? new Date(f.updated_at * 1000).toLocaleString() : "--";
          
          html += `
            <tr class="hover:bg-gray-800/50 transition">
              <td class="p-3 font-semibold text-white flex items-center gap-2">
                <span class="text-sky-400">📅</span>
                <span>${f.month}</span>
                <span class="text-xs text-gray-500 font-mono">(${f.filename})</span>
              </td>
              <td class="p-3 text-xs text-gray-300 font-mono">${datesStr}</td>
              <td class="p-3"><span class="bg-gray-800 text-amber-400 text-xs px-2 py-0.5 rounded font-mono font-bold">${f.total_targets}</span></td>
              <td class="p-3 font-mono text-emerald-400 text-xs font-bold">${f.size_kb} КБ</td>
              <td class="p-3 text-xs text-gray-400">${updatedStr}</td>
              <td class="p-3 text-right space-x-2">
                <button onclick="downloadHistoryFile('${f.month}')" class="text-xs bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 px-2.5 py-1 rounded transition" title="Завантажити JSON на ПК">📥 Завантажити</button>
                <button onclick="deleteHistoryFile('${f.month}')" class="text-xs bg-red-950/40 hover:bg-red-900/60 text-red-400 border border-red-800/50 px-2.5 py-1 rounded transition" title="Видалити цей місяць">🗑️ Видалити</button>
              </td>
            </tr>
          `;
        });
        tbody.innerHTML = html;
      } catch (e) {
        console.error("Error loading admin history:", e);
      }
    }

    function downloadHistoryFile(month) {
      window.location.href = "/api/v1/admin/history/download/" + encodeURIComponent(month) + "?admin_key=" + encodeURIComponent(currentAdminKey);
    }

    async function deleteHistoryFile(month) {
      if (!confirm(`Ви дійсно бажаєте видалити файл історії за ${month}? Цю дію неможливо скасувати.`)) return;
      try {
        const res = await fetch("/api/v1/admin/history/" + encodeURIComponent(month) + "?admin_key=" + encodeURIComponent(currentAdminKey), {
          method: "DELETE"
        });
        if (res.ok) {
          loadAdminHistory();
        } else {
          alert("Помилка при видаленні файлу!");
        }
      } catch (e) {
        alert("Помилка з'єднання: " + e);
      }
    }

    async function uploadAdminHistory(event) {
      const file = event.target.files[0];
      if (!file) return;
      try {
        const text = await file.text();
        const json = JSON.parse(text);
        const res = await fetch("/api/v1/admin/history/upload?admin_key=" + encodeURIComponent(currentAdminKey), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(json)
        });
        const resp = await res.json();
        if (res.ok) {
          alert(`Успішно імпортовано ${resp.imported_targets} цілей в архів!`);
          loadAdminHistory();
        } else {
          alert("Помилка імпорту: " + (resp.error || "Невідома помилка"));
        }
      } catch (e) {
        alert("Помилка читання JSON: " + e);
      }
      event.target.value = "";
    }

    function downloadBackup() {
      if (!currentAdminKey) return showLoginScreen();
      window.location.href = "/api/v1/admin/backup?admin_key=" + encodeURIComponent(currentAdminKey);
    }

    async function uploadBackup(event) {
      const file = event.target.files[0];
      if (!file) return;
      if (!currentAdminKey) return showLoginScreen();
      try {
        const text = await file.text();
        const json = JSON.parse(text);
        const res = await fetch("/api/v1/admin/restore?admin_key=" + encodeURIComponent(currentAdminKey), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(json)
        });
        const resp = await res.json();
        if (resp.status === "success") {
          alert("✅ Бэкап успешно восстановлен! Загружено ключей: " + resp.users_count);
          loadKeys();
        } else {
          alert("❌ Ошибка восстановления: " + (resp.error || "Неизвестная ошибка"));
        }
      } catch (e) {
        alert("Ошибка чтения файла: " + e);
      }
      event.target.value = "";
    }

    // Инициализация авторизации при загрузке страницы
    initAuth();
  </script>
</body>
</html>
"""

async def handle_admin_dashboard(request: web.Request):
    # Если запрос пришёл через Cloudflare Tunnel или извне — возвращаем 404 (будто страницы не существует)
    if is_external_request(request):
        return web.Response(text="404: Not Found", status=404)
    return web.Response(
        text=ADMIN_HTML,
        content_type="text/html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )


RADAR_MAP_HTML = """<!DOCTYPE html>
<html lang="uk">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Тактичний Радар Повітряних Загроз</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body, html { width: 100%; height: 100%; overflow: hidden; background: #0b0f19; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #fff; }
    #map { width: 100%; height: 100%; background: #0b0f19; }
    
    /* HUD Overlay */
    .hud-top {
      position: absolute; top: 12px; left: 12px; right: 12px;
      display: flex; justify-content: space-between; align-items: center;
      z-index: 1000; pointer-events: none;
    }
    .hud-card {
      background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(8px);
      border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px;
      padding: 8px 14px; pointer-events: auto; box-shadow: 0 4px 12px rgba(0,0,0,0.5);
      display: flex; align-items: center; gap: 12px;
    }
    .hud-title { font-size: 13px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; color: #38bdf8; }
    .badge { padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .badge-red { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-green { background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }
    .badge-yellow { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
    
    /* Target Markers */
    .target-marker { background: none; border: none; }
    .leaflet-popup-content-wrapper {
      background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(8px);
      color: #fff; border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 8px;
    }
    .leaflet-popup-tip { background: rgba(15, 23, 42, 0.95); }
    .popup-title { font-size: 14px; font-weight: 800; color: #fb923c; margin-bottom: 4px; }
    .popup-row { font-size: 12px; color: #94a3b8; display: flex; justify-content: space-between; gap: 12px; margin-top: 2px; }
    .popup-val { color: #f8fafc; font-weight: 600; font-family: monospace; }
  </style>
</head>
<body>
  <div class="hud-top">
    <div class="hud-card">
      <span class="hud-title">⚡ Повітряний Радар</span>
      <span id="threatsBadge" class="badge badge-green">Цілей: 0</span>
      <span id="migBadge" class="badge badge-green">МіГ-31К: Чисто</span>
    </div>
    <div class="hud-card" id="closestCard" style="display: none;">
      <span style="font-size: 12px; color: #94a3b8;">Найближча:</span>
      <span id="closestInfo" style="font-size: 12px; font-weight: 700; color: #fb923c;">--</span>
    </div>
  </div>

  <div id="map"></div>

  <script>
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token') || localStorage.getItem('hub_user_token') || '';
    if (urlParams.get('token')) localStorage.setItem('hub_user_token', token);

    const map = L.map('map', {
      center: [48.5, 31.2],
      zoom: 6,
      zoomControl: false,
      attributionControl: false
    });

    L.control.zoom({ position: 'bottomright' }).addTo(map);

    // Dark tactical basemap (CartoDB Dark Matter)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 18,
      subdomains: 'abcd'
    }).addTo(map);

    let threatLayers = {};   // id -> { marker, heatTrail, futureCorridor }
    let slotLayers = {};     // slot_id -> { marker, circle }

    function getTargetSvg(t) {
      const heading = t.heading || t.bearing_deg || 0;
      const cat = (t.category || 'shahed').toLowerCase();
      let silhouette = '';
      let glowRx = 9, glowRy = 16;

      if (cat.includes('kab') || (t.type && t.type.includes('КАБ'))) {
        silhouette = '<path fill=\"#FFFFFF\" stroke=\"#111827\" stroke-width=\"1.8\" stroke-linejoin=\"round\" d=\"M24 7 C21 7, 19 11, 19 16 L19 23 L9 26 L9 29 L19 29 L19 33 L14 38 L16 38 L20 35 L20 39 L28 39 L28 35 L32 38 L34 38 L29 33 L29 29 L39 29 L39 26 L29 23 L29 16 C29 11, 27 7, 24 7 Z\"/><circle cx=\"24\" cy=\"18\" r=\"2.2\" fill=\"#E11D48\"/>';
        glowRx = 8; glowRy = 14;
      } else if (cat.includes('missile') || (t.type && t.type.includes('ракет'))) {
        silhouette = '<path fill=\"#FFFFFF\" stroke=\"#111827\" stroke-width=\"1.8\" stroke-linejoin=\"round\" d=\"M24 6 L22 13 L22 21 L11 27 L13 28 L22 26 L22 33 L16 38 L18 38 L22 36 L22 39 L26 39 L26 36 L30 38 L32 38 L26 33 L26 26 L35 28 L37 27 L26 21 L26 13 Z\"/><polygon points=\"23,39 24,46 25,39\" fill=\"#FFEA00\" stroke=\"#FF5722\" stroke-width=\"0.8\"/>';
        glowRx = 7; glowRy = 17;
      } else {
        // Shahed-136 delta wing (identical to screenshot 3)
        silhouette = '<path fill=\"#FFFFFF\" stroke=\"#111827\" stroke-width=\"1.8\" stroke-linejoin=\"round\" d=\"M24 10 L12 28 L12 24 L10 24 L10 32 L12 32 L12 30 L21 28 L21 34 L27 34 L27 28 L36 30 L36 32 L38 32 L38 24 L36 24 L36 28 Z\"/><circle cx=\"24\" cy=\"34\" r=\"1.5\" fill=\"#111827\"/>';
      }

      return `<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 48 48\" width=\"48\" height=\"48\">
        <defs>
          <radialGradient id=\"heatGlow\" cx=\"50%\" cy=\"30%\" r=\"55%\" fx=\"50%\" fy=\"30%\">
            <stop offset=\"0%\" stop-color=\"#FF3D00\" stop-opacity=\"0.9\"/>
            <stop offset=\"35%\" stop-color=\"#FF6D00\" stop-opacity=\"0.6\"/>
            <stop offset=\"70%\" stop-color=\"#FF9800\" stop-opacity=\"0.28\"/>
            <stop offset=\"100%\" stop-color=\"#FF5722\" stop-opacity=\"0\"/>
          </radialGradient>
        </defs>
        <g transform=\"rotate(${heading.toFixed(1)} 24 24)\">
          <ellipse cx=\"24\" cy=\"30\" rx=\"${glowRx}\" ry=\"${glowRy}\" fill=\"url(#heatGlow)\"/>
          ${silhouette}
        </g>
      </svg>`;
    }

    function updateRadarData(data) {
      if (!data) return;

      // Update HUD
      const count = data.active_threats_total || (data.threats ? data.threats.length : 0);
      const tBadge = document.getElementById('threatsBadge');
      tBadge.innerText = `Цілей: ${count}`;
      tBadge.className = count > 0 ? 'badge badge-red' : 'badge badge-green';

      const migActive = data.general_alerts && data.general_alerts.mig31k_active;
      const mBadge = document.getElementById('migBadge');
      mBadge.innerText = migActive ? '⚠️ МіГ-31К: ЗЛІТ' : 'МіГ-31К: Чисто';
      mBadge.className = migActive ? 'badge badge-red' : 'badge badge-green';

      const closest = data.closest_threat;
      const cCard = document.getElementById('closestCard');
      if (closest && closest.distance_km) {
        cCard.style.display = 'flex';
        document.getElementById('closestInfo').innerText = `${closest.type} (${closest.distance_km} км, ETA: ${closest.eta_minutes || '--'} хв)`;
      } else {
        cCard.style.display = 'none';
      }

      // Update User Slots (Home / Danger circles)
      if (data.slots) {
        for (const [sId, s] of Object.entries(data.slots)) {
          if (!slotLayers[sId]) {
            const circle = L.circle([s.lat, s.lon], {
              radius: (s.danger_radius_km || 15) * 1000,
              color: '#ef4444',
              fillColor: '#ef4444',
              fillOpacity: 0.12,
              weight: 1.5,
              dashArray: '4, 4'
            }).addTo(map);

            const sMarker = L.circleMarker([s.lat, s.lon], {
              radius: 6,
              color: '#38bdf8',
              fillColor: '#0284c7',
              fillOpacity: 1,
              weight: 2
            }).bindTooltip(`<b>${s.name}</b> (${s.danger_radius_km || 15} км)`, { permanent: false, direction: 'top' }).addTo(map);

            slotLayers[sId] = { circle, marker: sMarker };
          }
        }
      }

      // Update Threats & Trajectories
      const activeIds = new Set();
      const threats = data.threats || [];

      for (const t of threats) {
        activeIds.add(t.id);
        const lat = t.lat;
        const lon = t.lon;

        // Extract trajectory points
        const trajPoints = (t.trajectory || []).map(p => [p.lat, p.lon]);
        if (trajPoints.length === 0 || (trajPoints[trajPoints.length-1][0] !== lat || trajPoints[trajPoints.length-1][1] !== lon)) {
          trajPoints.push([lat, lon]);
        }

        // Extract extrapolated corridor points
        const extraPoints = [[lat, lon]].concat((t.extrapolated_path || []).map(p => [p.lat, p.lon]));

        const svgHtml = getTargetSvg(t);
        const icon = L.divIcon({
          html: svgHtml,
          className: 'target-marker',
          iconSize: [48, 48],
          iconAnchor: [24, 24]
        });

        const popupContent = `
          <div class="popup-title">🎯 ${t.type}</div>
          <div class="popup-row"><span>Дистанція:</span><span class="popup-val">${t.distance_km || '--'} км</span></div>
          <div class="popup-row"><span>Курс:</span><span class="popup-val">${t.heading || '--'}°</span></div>
          <div class="popup-row"><span>Швидкість:</span><span class="popup-val">${t.speed_kmh || '--'} км/год</span></div>
          <div class="popup-row"><span>Час підльоту (ETA):</span><span class="popup-val">${t.eta_minutes ? t.eta_minutes + ' хв' : '--'}</span></div>
          <div class="popup-row"><span>Область:</span><span class="popup-val">${t.oblast || '--'}</span></div>
        `;

        if (!threatLayers[t.id]) {
          // Heat trail polyline (glow + central path)
          const glowTrail = L.polyline(trajPoints, {
            color: '#ff3d00',
            weight: 10,
            opacity: 0.35,
            lineCap: 'round',
            lineJoin: 'round'
          }).addTo(map);

          const coreTrail = L.polyline(trajPoints, {
            color: '#facc15',
            weight: 2.5,
            opacity: 0.85,
            lineCap: 'round',
            lineJoin: 'round'
          }).addTo(map);

          // Future extrapolated flight corridor (dashed)
          const futureLine = L.polyline(extraPoints, {
            color: '#fb923c',
            weight: 2,
            opacity: 0.6,
            dashArray: '5, 8'
          }).addTo(map);

          // Target marker
          const marker = L.marker([lat, lon], { icon }).bindPopup(popupContent).addTo(map);

          threatLayers[t.id] = { marker, glowTrail, coreTrail, futureLine };
        } else {
          // Update existing
          const item = threatLayers[t.id];
          item.marker.setLatLng([lat, lon]);
          item.marker.setIcon(icon);
          item.marker.setPopupContent(popupContent);
          item.glowTrail.setLatLngs(trajPoints);
          item.coreTrail.setLatLngs(trajPoints);
          item.futureLine.setLatLngs(extraPoints);
        }
      }

      // Remove vanished threats
      for (const [id, item] of Object.entries(threatLayers)) {
        if (!activeIds.has(id)) {
          map.removeLayer(item.marker);
          map.removeLayer(item.glowTrail);
          map.removeLayer(item.coreTrail);
          map.removeLayer(item.futureLine);
          delete threatLayers[id];
        }
      }
    }

    // Connect via WebSocket or Poll
    function connectStream() {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${proto}//${location.host}/api/v1/stream?token=${encodeURIComponent(token)}`;
      const ws = new WebSocket(wsUrl);

      ws.onmessage = (event) => {
        try {
          const data = json.parse(event.data);
          updateRadarData(data);
        } catch (e) { console.error('WS Parse error', e); }
      };

      ws.onclose = () => {
        setTimeout(connectStream, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    // Fallback polling
    async function pollFallback() {
      try {
        const res = await fetch(`/api/v1/threats?token=${encodeURIComponent(token)}`);
        if (res.ok) {
          const data = await res.json();
          updateRadarData(data);
        }
      } catch (e) {}
    }

    connectStream();
    setInterval(pollFallback, 5000);
  </script>
</body>
</html>
"""

async def handle_radar_map(request: web.Request):
    """Интерактивная живая карта радара с тепловыми следами и прогнозом траектории."""
    return web.Response(
        text=RADAR_MAP_HTML,
        content_type="text/html",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )

async def handle_root(request: web.Request):
    if is_external_request(request):
        return web.Response(text="404: Not Found", status=404)
    raise web.HTTPFound("/admin")

# =====================================================================
# ИНИЦИАЛИЗАЦИЯ И СТАРТ ПРИЛОЖЕНИЯ
# =====================================================================

async def on_startup(app):
    app["task_ua"] = asyncio.create_task(run_ukrainealarm_collector())
    app["task_alerts"] = asyncio.create_task(run_official_alerts_collector())
    app["task_failover"] = asyncio.create_task(run_failover_neptun_collector())

async def on_cleanup(app):
    app["task_ua"].cancel()
    app["task_alerts"].cancel()
    app["task_failover"].cancel()

def create_app() -> web.Application:
    app = web.Application()

    app.router.add_get("/", handle_root)
    app.router.add_get("/api/v1/health", lambda r: web.json_response({
        "status": "ok",
        "service": "Air Alert Hub",
        "active_threats_count": len(state.tracker.tracks),
        "official_sirens_count": len(state.official_alerts),
        "mig31k_active": state.mig_active,
        "upstream_provider": state.upstream_provider,
        "upstream_name": "Основной (WebSocket map.ukrainealarm.com)" if state.upstream_provider == "ukrainealarm" else ("Резервный (REST neptun.in.ua)" if state.upstream_provider == "neptun_failover" else "Ожидание подключения"),
        "unknown_target_types_count": len(UNKNOWN_TARGET_TYPES_CATALOG),
        "unknown_target_types": list(UNKNOWN_TARGET_TYPES_CATALOG.values()),
        "proxy_enabled": bool(UPSTREAM_PROXY),
        "proxy_info": mask_proxy(UPSTREAM_PROXY)
    }))
    app.router.add_get("/api/v1/unknown_types", lambda r: web.json_response({
        "status": "ok",
        "count": len(UNKNOWN_TARGET_TYPES_CATALOG),
        "catalog": list(UNKNOWN_TARGET_TYPES_CATALOG.values())
    }))
    app.router.add_get("/api/v1/slots", handle_get_slots)
    app.router.add_post("/api/v1/slots", handle_create_slot)
    app.router.add_put("/api/v1/slots/{slot_id}", handle_update_slot)
    app.router.add_delete("/api/v1/slots/{slot_id}", handle_delete_slot)
    app.router.add_post("/api/v1/locations/dynamic", handle_update_dynamic)
    app.router.add_get("/api/v1/settings", handle_get_settings)
    app.router.add_put("/api/v1/settings", handle_update_settings)
    app.router.add_post("/api/v1/settings", handle_update_settings)
    app.router.add_get("/api/v1/threats", handle_get_threats)
    app.router.add_get("/api/v1/radar", handle_get_radar)
    
# =====================================================================
# API ЕНДПОІНТИ ДЛЯ GEOJSON РЕГІОНІВ ТА ІСТОРІЇ ПОЛЬОТІВ
# =====================================================================

async def handle_get_regions_geojson(request: web.Request):
    """Повертає оптимізований GeoJSON 26 областей України для карти."""
    for fn in ["ukraine_oblasts_compact.geojson", "ukraine_oblasts.geojson"]:
        geojson_path = os.path.join(DATA_DIR, fn)
        if os.path.exists(geojson_path):
            with open(geojson_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return web.json_response(data, headers={"Cache-Control": "public, max-age=86400"})
    return web.json_response({"error": "GeoJSON not found"}, status=404)

async def handle_get_history_months(request: web.Request):
    """Повертає список доступних місяців та дат в архіві історії."""
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    months = history_manager.get_available_months()
    return web.json_response({"status": "ok", "months": months})

async def handle_get_history(request: web.Request):
    """Повертає історію польотів за місяць або конкретну дату."""
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    month = request.query.get("month")
    date = request.query.get("date")
    if not month and not date:
        now_dt = time.gmtime()
        month = time.strftime("%Y-%m", now_dt)
    elif not month and date:
        month = date[:7]
    data = history_manager.get_history(month, date_str=date)
    return web.json_response(data)

async def handle_upload_history(request: web.Request):
    """Імпорт зовнішнього JSON файлу з історією польотів."""
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    try:
        data = await request.json()
        count = history_manager.import_external_history(data)
        return web.json_response({"status": "ok", "imported_targets": count})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=400)

    app.router.add_get("/api/v1/map", handle_get_map)
    app.router.add_get("/api/v1/regions/geojson", handle_get_regions_geojson)
    app.router.add_get("/api/v1/history/months", handle_get_history_months)
    app.router.add_get("/api/v1/history", handle_get_history)
    app.router.add_post("/api/v1/history/upload", handle_upload_history)
    app.router.add_get("/map", handle_radar_map)
    app.router.add_get("/radar-map", handle_radar_map)
    app.router.add_get("/api/v1/stream", handle_websocket_stream)

    app.router.add_get("/admin", handle_admin_dashboard)
    app.router.add_get("/api/v1/admin/verify", handle_admin_verify)
    app.router.add_post("/api/v1/admin/verify", handle_admin_verify)
    app.router.add_get("/api/v1/admin/keys", handle_admin_get_keys)
    app.router.add_post("/api/v1/admin/keys", handle_admin_create_key)
    app.router.add_put("/api/v1/admin/keys/{key}", handle_admin_update_key)
    app.router.add_put("/api/v1/admin/keys/{key}/settings", handle_admin_update_user_settings)
    app.router.add_delete("/api/v1/admin/keys/{key}", handle_admin_delete_key)
    app.router.add_get("/api/v1/admin/history", handle_admin_get_history)
    app.router.add_delete("/api/v1/admin/history/{month}", handle_admin_delete_history)
    app.router.add_get("/api/v1/admin/history/download/{month}", handle_admin_download_history)
    app.router.add_post("/api/v1/admin/history/upload", handle_admin_upload_history)
    app.router.add_get("/api/v1/admin/backup", handle_admin_backup)
    app.router.add_post("/api/v1/admin/restore", handle_admin_restore)

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app

if __name__ == "__main__":
    logger.info(f"Старт Air Alert Hub на порту {PORT}...")
    web_app = create_app()
    web.run_app(web_app, host="0.0.0.0", port=PORT, access_log=None)
