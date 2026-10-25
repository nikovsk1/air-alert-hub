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
ADMIN_SECRET_KEY = os.environ.get("ADMIN_SECRET_KEY", "admin_super_secret_master_key_123")
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

DEFAULT_USER_SLOTS = {
    "1": {"id": "1", "name": "Дом (Квартира)", "lat": 50.4501, "lon": 30.5234, "type": "static"},
    "2": {"id": "2", "name": "Работа / Офис", "lat": 50.4600, "lon": 30.5100, "type": "static"},
    "3": {"id": "3", "name": "Дача / Родители", "lat": 50.3500, "lon": 30.7000, "type": "static"},
    "4": {"id": "4", "name": "Школа / Резерв", "lat": 50.4400, "lon": 30.5300, "type": "static"},
    "5": {"id": "5", "name": "Я (Динамическая)", "lat": 50.4501, "lon": 30.5234, "type": "dynamic", "updated_at": 0, "accuracy_m": 0.0}
}

class StorageManager:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = {"users": {}}
        self.load()

    def load(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        loaded = False
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
                    logger.info(f"Загружено пользователей из базы: {len(self.data.get('users', {}))}")
                    loaded = True
            except Exception as e:
                logger.error(f"Ошибка чтения {self.filepath}: {e}")

        if not loaded:
            # Начальные пользователи (если база пустая): Муж и Жена
            self.data = {
                "users": {
                    "ak_husband_demo123": {
                        "id": "usr_husband",
                        "api_key": "ak_husband_demo123",
                        "owner": "Муж (Основной)",
                        "enabled": True,
                        "created_at": int(time.time()),
                        "last_used_at": 0,
                        "slots": json.loads(json.dumps(DEFAULT_USER_SLOTS))
                    },
                    "ak_wife_demo456": {
                        "id": "usr_wife",
                        "api_key": "ak_wife_demo456",
                        "owner": "Жена",
                        "enabled": True,
                        "created_at": int(time.time()),
                        "last_used_at": 0,
                        "slots": json.loads(json.dumps(DEFAULT_USER_SLOTS))
                    }
                }
            }

        # Гарантия сохранения ключей из переменной окружения INITIAL_USERS
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
                            "slots": json.loads(json.dumps(DEFAULT_USER_SLOTS))
                        }
                        logger.info(f"Добавлен ключ из INITIAL_USERS: {p_name} ({p_key})")

        self.save()

    def save(self):
        tmp_file = self.filepath + ".tmp"
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            if os.path.exists(self.filepath):
                os.remove(self.filepath)
            os.replace(tmp_file, self.filepath)
        except Exception as e:
            logger.error(f"Ошибка сохранения {self.filepath}: {e}")

    def get_user_by_key(self, api_key: str):
        user = self.data["users"].get(api_key)
        if user and user.get("enabled", True):
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
            "slots": json.loads(json.dumps(DEFAULT_USER_SLOTS))
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

    def delete_user(self, api_key: str) -> bool:
        if api_key in self.data["users"]:
            del self.data["users"][api_key]
            self.save()
            return True
        return False

    def update_slot(self, api_key: str, slot_id: str, name: str, lat: float, lon: float) -> dict:
        user = self.data["users"].get(api_key)
        if not user or slot_id not in user.get("slots", {}):
            return None
        slot = user["slots"][slot_id]
        if name: slot["name"] = name
        if lat is not None: slot["lat"] = float(lat)
        if lon is not None: slot["lon"] = float(lon)
        self.save()
        return slot

    def update_dynamic_slot(self, api_key: str, lat: float, lon: float, name: str = None, accuracy_m: float = 0.0) -> dict:
        user = self.data["users"].get(api_key)
        if not user or "5" not in user.get("slots", {}):
            return None
        slot = user["slots"]["5"]
        slot["lat"] = float(lat)
        slot["lon"] = float(lon)
        slot["updated_at"] = int(time.time())
        slot["accuracy_m"] = float(accuracy_m)
        if name: slot["name"] = name
        self.save()
        return slot

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
# СОПРОВОЖДЕНИЕ ЦЕЛЕЙ (PERSISTENT TRACKER & HEAT TRAIL)
# =====================================================================

class TargetTrack:
    """Одиночная воздушная цель с историей траектории и прогнозом движения."""
    def __init__(self, target_id: str, t_type: str, raw_code: int, lat: float, lon: float,
                 heading: float, speed_kmh: float, oblast: str, oblast_id: str):
        self.id = target_id
        self.type = t_type
        self.raw_code = raw_code
        self.lat = lat
        self.lon = lon
        self.heading = heading
        self.speed_kmh = speed_kmh
        self.oblast = oblast
        self.oblast_id = oblast_id
        self.first_seen = time.time()
        self.last_seen = time.time()
        # История точек для построения теплового следа / пройденного пути
        self.trajectory = [{"lat": round(lat, 5), "lon": round(lon, 5), "ts": int(self.last_seen)}]

    def update(self, lat: float, lon: float, heading: float, speed_kmh: float, oblast: str, oblast_id: str):
        now = time.time()
        last_pt = self.trajectory[-1]
        dist_from_last = calculate_haversine_distance(last_pt["lat"], last_pt["lon"], lat, lon)

        # Добавляем точку в трек при смещении > 300 м или раз в 10 секунд
        if dist_from_last > 0.3 or (now - last_pt["ts"]) >= 10.0:
            self.trajectory.append({"lat": round(lat, 5), "lon": round(lon, 5), "ts": int(now)})
            if len(self.trajectory) > 30: # храним до 30 последних точек
                self.trajectory.pop(0)

        self.lat = lat
        self.lon = lon
        self.heading = heading
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

            if t_id in self.tracks:
                self.tracks[t_id].update(
                    lat=t["lat"],
                    lon=t["lon"],
                    heading=t["heading"],
                    speed_kmh=t["speed_kmh"],
                    oblast=t["oblast"],
                    oblast_id=t.get("oblast_id", "0")
                )
            else:
                self.tracks[t_id] = TargetTrack(
                    target_id=t_id,
                    t_type=t["type"],
                    raw_code=t["raw_type_code"],
                    lat=t["lat"],
                    lon=t["lon"],
                    heading=t["heading"],
                    speed_kmh=t["speed_kmh"],
                    oblast=t["oblast"],
                    oblast_id=t.get("oblast_id", "0")
                )

        # Очистка исчезнувших целей (если не появлялись в потоке более 25 секунд)
        expired = [tid for tid, trk in self.tracks.items() if (now - trk.last_seen) > 25.0]
        for tid in expired:
            del self.tracks[tid]

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
        self.official_alerts = {} # regionId -> { name, type, since }
        self.mig_active = False
        self.artillery_alerts = set()
        self.alert_reasons = []

    async def update_threats(self, raw_targets: list, provider: str):
        async with self.lock:
            self.tracker.update_batch(raw_targets)
            self.last_update_ts = time.time()
            self.upstream_provider = provider
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
                        "since": a.get("lastUpdate", "")
                    }
            self.official_alerts = active
            self.mig_active = len(alerts_data.get("migAlerts", [])) > 0
            self.artillery_alerts = {str(x.get("regionId", "")) for x in alerts_data.get("artillery", [])}
            self.alert_reasons = alerts_data.get("reasons", [])

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

    def build_user_snapshot(self, user: dict, slot_id: str = "1", radius_km: float = None, custom_lat: float = None, custom_lon: float = None) -> dict:
        slots = user.get("slots", DEFAULT_USER_SLOTS)
        target_slot = slots.get(str(slot_id), slots.get("1"))

        center_lat = custom_lat if custom_lat is not None else target_slot["lat"]
        center_lon = custom_lon if custom_lon is not None else target_slot["lon"]
        center_name = "Пользовательская точка" if custom_lat is not None else target_slot["name"]

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

            item = {
                "id": t.id,
                "type": t.type,
                "raw_code": t.raw_code,
                "oblast": t.oblast,
                "lat": round(lat, 5),
                "lon": round(lon, 5),
                "distance_km": round(dist, 1),
                "bearing_deg": round(bearing, 1),
                "bearing_sector": bearing_to_compass(bearing),
                "heading": heading,
                "speed_kmh": speed,
                "approach_status": approach_status,
                "approach_desc": approach_desc,
                "eta_minutes": eta_min,
                "in_danger_zone": dist <= DANGER_RADIUS_KM,
                "trajectory": t.trajectory, # Тепловой след / история пути
                "extrapolated_path": t.get_extrapolated_corridor((5, 10, 15)) # Прогноз полета
            }
            processed.append(item)
            if dist < closest_dist:
                closest_dist = dist
                closest_threat = item

        # Сводка по всем 5 слотам пользователя (с учетом официальных сирен!)
        user_slots_stats = {}
        for s_id, s_data in slots.items():
            s_lat, s_lon = s_data["lat"], s_data["lon"]
            s_min = 99999.0
            s_type = "Нет"
            s_danger = False

            s_info = oblast_detector.find_oblast_info(s_lat, s_lon)
            s_oblast = s_info["name"]
            s_rid = s_info["id"]

            threats_in_s_oblast = sum(1 for trk in active_tracks if trk.oblast == s_oblast)

            for t in active_tracks:
                d = calculate_haversine_distance(s_lat, s_lon, t.lat, t.lon)
                if d < s_min:
                    s_min = d
                    s_type = t.type
                if d <= DANGER_RADIUS_KM:
                    s_danger = True

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
                "siren_active": is_official_alert,
                "siren_since": alert_meta.get("since"),
                "mig_threat_active": self.mig_active,
                "artillery_active": s_rid in self.artillery_alerts,
                "threats_in_this_oblast": threats_in_s_oblast,
                "closest_distance_km": round(s_min, 1) if s_min < 90000 else None,
                "closest_type": s_type if s_min < 90000 else "Спокійно",
                "danger_zone_active": s_danger
            }

        return {
            "timestamp": int(self.last_update_ts * 1000),
            "owner": user["owner"],
            "upstream_provider": self.upstream_provider,
            "active_threats_total": len(active_tracks),
            "general_alerts": {
                "mig31k_active": self.mig_active,
                "total_official_sirens": len(self.official_alerts),
                "reasons": self.alert_reasons
            },
            "current_point": {
                "slot_id": slot_id,
                "name": center_name,
                "lat": center_lat,
                "lon": center_lon
            },
            "closest_threat": closest_threat,
            "slots": user_slots_stats,
            "threats": processed
        }

    def build_radar_projection(self, user: dict, slot_id: str = "1", radius_km: float = 100.0,
                               custom_lat: float = None, custom_lon: float = None,
                               screen_w: int = 368, screen_h: int = 448) -> dict:
        snapshot = self.build_user_snapshot(user, slot_id=slot_id, radius_km=radius_km, custom_lat=custom_lat, custom_lon=custom_lon)
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
        return {
            "timestamp": snapshot["timestamp"],
            "owner": user["owner"],
            "slot_id": slot_id,
            "location_name": snapshot["current_point"]["name"],
            "radius_km": radius_km,
            "threats_count": len(radar_targets),
            "siren_active": slot_stat.get("siren_active", False),
            "mig_active": snapshot["general_alerts"]["mig31k_active"],
            "closest_km": snapshot["closest_threat"]["distance_km"] if snapshot["closest_threat"] else None,
            "closest_eta": snapshot["closest_threat"]["eta_minutes"] if snapshot["closest_threat"] else None,
            "danger_active": snapshot["closest_threat"]["in_danger_zone"] if snapshot["closest_threat"] else False,
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

                ob_info = oblast_detector.find_oblast_info(lat, lon)
                speed = 280.0 if "jet" in name.lower() else 185.0

                normalized.append({
                    "id": uid,
                    "lat": lat,
                    "lon": lon,
                    "type": name,
                    "raw_type_code": raw_code,
                    "oblast": ob_info["name"],
                    "oblast_id": ob_info["id"],
                    "heading": heading,
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

async def run_ukrainealarm_collector():
    """Основной сборщик данных через WebSocket Centrifugo."""
    import websockets

    while True:
        try:
            req = urllib.request.Request(PAGE_URL, headers=BROWSER_HEADERS)
            html = await asyncio.to_thread(lambda: opener.open(req, timeout=12).read().decode('utf-8'))

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

                            sub_resp_text = await asyncio.to_thread(lambda: opener.open(sub_req, timeout=10).read().decode('utf-8'))
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

        except Exception as e:
            logger.warning(f"Апстрим реконнект ({e}). Пауза 6 сек...")
            await asyncio.sleep(6)

async def run_official_alerts_collector():
    """Сборщик официальных сирен, тревог МиГ-31К и артиллерии по всей Украине (/api/v2/data/mapUpdate)."""
    update_url = "https://map.ukrainealarm.com/api/v2/data/mapUpdate"

    while True:
        try:
            req = urllib.request.Request(update_url, headers=BROWSER_HEADERS)
            raw = await asyncio.to_thread(lambda: opener.open(req, timeout=10).read().decode('utf-8'))
            data = json.loads(raw)
            await state.update_official_alerts(data)
        except Exception as e:
            logger.debug(f"Ошибка обновления официальных сирен: {e}")
        await asyncio.sleep(12) # Опрос раз в 12 секунд

async def run_failover_neptun_collector():
    while True:
        await asyncio.sleep(6)
        if time.time() - state.last_update_ts > 45.0:
            try:
                req = urllib.request.Request("https://neptun.in.ua/api/v1/threats", headers={"User-Agent": "Mozilla/5.0"})
                resp = await asyncio.to_thread(lambda: urllib.request.urlopen(req, timeout=8).read().decode('utf-8'))
                threats_raw = json.loads(resp).get("threats", [])
                normalized = []
                for t in threats_raw:
                    lat, lon = float(t.get("lat", 0.0)), float(t.get("lon", 0.0))
                    ob_info = oblast_detector.find_oblast_info(lat, lon)
                    normalized.append({
                        "id": t.get("id", f"nep_{lat:.2f}"),
                        "lat": lat,
                        "lon": lon,
                        "type": t.get("type", "uav"),
                        "raw_type_code": 8 if t.get("type") == "uav" else 1,
                        "oblast": ob_info["name"],
                        "oblast_id": ob_info["id"],
                        "heading": float(t.get("heading", 0.0)),
                        "speed_kmh": 185.0
                    })
                await state.update_threats(normalized, provider="neptun_failover")
            except Exception: pass

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

def get_authenticated_user(request: web.Request):
    token = request.query.get("token") or request.headers.get("X-API-Key")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "): token = auth[7:].strip()
    if not token: return None
    return storage.get_user_by_key(token)

def is_admin(request: web.Request) -> bool:
    # Запрещаем любые административные действия из внешнего интернета
    if is_external_request(request):
        return False
    admin_key = request.query.get("admin_key") or request.headers.get("X-Admin-Key")
    return bool(admin_key and admin_key == ADMIN_SECRET_KEY)

async def handle_get_slots(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    return web.json_response({"owner": user["owner"], "slots": user["slots"]})

async def handle_update_slot(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    slot_id = request.match_info.get("slot_id")
    try:
        data = await request.json()
        slot = storage.update_slot(user["api_key"], slot_id, data.get("name"), data.get("lat"), data.get("lon"))
        if not slot: return web.json_response({"error": "Slot not found"}, status=404)
        return web.json_response({"status": "success", "slot": slot})
    except Exception as e: return web.json_response({"error": str(e)}, status=400)

async def handle_update_dynamic(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)
    try:
        data = await request.json()
        slot = storage.update_dynamic_slot(user["api_key"], data.get("lat"), data.get("lon"), data.get("name"), data.get("accuracy_m", 0.0))
        return web.json_response({"status": "success", "slot": slot})
    except Exception as e: return web.json_response({"error": str(e)}, status=400)

async def handle_get_threats(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)

    slot_id = request.query.get("slot", "1")
    radius = float(request.query.get("radius", 0)) or None
    custom_lat = float(request.query["lat"]) if "lat" in request.query else None
    custom_lon = float(request.query["lon"]) if "lon" in request.query else None

    snapshot = state.build_user_snapshot(user, slot_id=slot_id, radius_km=radius, custom_lat=custom_lat, custom_lon=custom_lon)
    return web.json_response(snapshot)

async def handle_get_radar(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.json_response({"error": "Unauthorized"}, status=401)

    slot_id = request.query.get("slot", "1")
    radius = float(request.query.get("radius", 100.0))
    custom_lat = float(request.query["lat"]) if "lat" in request.query else None
    custom_lon = float(request.query["lon"]) if "lon" in request.query else None
    w = int(request.query.get("w", 368))
    h = int(request.query.get("h", 448))

    radar = state.build_radar_projection(user, slot_id=slot_id, radius_km=radius, custom_lat=custom_lat, custom_lon=custom_lon, screen_w=w, screen_h=h)
    return web.json_response(radar)

async def handle_websocket_stream(request: web.Request):
    user = get_authenticated_user(request)
    if not user: return web.Response(text="Unauthorized", status=401)

    ws = web.WebSocketResponse()
    await ws.prepare(request)
    sub_tuple = (ws, user)
    state.ws_subscribers.add(sub_tuple)

    slot_id = request.query.get("slot", "1")
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

async def handle_admin_get_keys(request: web.Request):
    if not is_admin(request): return web.json_response({"error": "Admin unauthorized"}, status=403)
    keys_list = []
    for k, u in storage.data["users"].items():
        keys_list.append({
            "id": u["id"],
            "owner": u["owner"],
            "api_key": u["api_key"],
            "enabled": u.get("enabled", True),
            "created_at": u.get("created_at", 0),
            "last_used_at": u.get("last_used_at", 0),
            "slots_count": len(u.get("slots", {}))
        })
    return web.json_response({"users": keys_list})

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
  <style>body { background-color: #0d1117; color: #c9d1d9; font-family: system-ui, -apple-system, sans-serif; }</style>
</head>
<body class="p-4 md:p-8">
  <div class="max-w-5xl mx-auto">
    <header class="flex flex-col md:flex-row justify-between items-start md:items-center pb-6 border-b border-gray-800 gap-4">
      <div>
        <h1 class="text-2xl font-bold text-white flex items-center gap-2">
          <span class="text-red-500">🛡️</span> Air Alert Radar Hub
        </h1>
        <p class="text-sm text-gray-400">Центр управления API-ключами, официальными сиренами и радаром (Home Assistant & ESP32)</p>
      </div>
      <div class="flex items-center gap-2">
        <input id="adminKeyInput" type="password" placeholder="Мастер-ключ админа" class="bg-gray-900 border border-gray-700 px-3 py-1.5 rounded text-sm text-white focus:outline-none focus:border-blue-500">
        <button onclick="loadKeys()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium transition">Войти</button>
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

    <div class="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden my-6">
      <div class="p-4 border-b border-gray-800 flex flex-wrap justify-between items-center gap-3">
        <h2 class="font-semibold text-white">Список пользователей и ключей</h2>
        <div class="flex items-center gap-2">
          <button onclick="downloadBackup()" class="bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1 transition" title="Сохранить всех пользователей и слоты в JSON">📥 Скачать бэкап</button>
          <button onclick="document.getElementById('restoreFileInput').click()" class="bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1 transition" title="Восстановить ключи из сохранённого JSON">📤 Восстановить бэкап</button>
          <input type="file" id="restoreFileInput" accept=".json" class="hidden" onchange="uploadBackup(event)">
          <button onclick="openCreateModal()" class="bg-emerald-600 hover:bg-emerald-700 text-white px-3 py-1.5 rounded text-xs font-semibold transition">+ Создать ключ</button>
        </div>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-gray-950 text-gray-400 text-xs uppercase">
            <tr>
              <th class="p-3">Владелец</th>
              <th class="p-3">API Ключ</th>
              <th class="p-3">Статус</th>
              <th class="p-3">Был в сети</th>
              <th class="p-3 text-right">Действия</th>
            </tr>
          </thead>
          <tbody id="keysTableBody" class="divide-y divide-gray-800">
            <tr><td colspan="5" class="p-4 text-center text-gray-500">Введите мастер-ключ админа для загрузки списка</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div id="slotsSection" class="hidden bg-gray-900 border border-gray-800 rounded-lg p-5 my-6">
      <div class="flex justify-between items-center mb-4">
        <div>
          <h3 class="font-bold text-white text-lg">Персональные локации: <span id="currentSlotOwner" class="text-blue-400"></span></h3>
          <p class="text-xs text-gray-400">Слоты используются одновременно на экране ESP32 и в Home Assistant этого пользователя</p>
        </div>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4" id="slotsCardsContainer"></div>
    </div>
  </div>

  <script>
    let currentAdminKey = localStorage.getItem("hub_admin_key") || "";
    if (currentAdminKey) document.getElementById("adminKeyInput").value = currentAdminKey;

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
      } catch(e) {}
    }

    async function loadKeys() {
      const key = document.getElementById("adminKeyInput").value.trim();
      if (!key) return alert("Введите мастер-ключ админа");
      currentAdminKey = key;
      localStorage.setItem("hub_admin_key", key);

      updateTelemetry();

      try {
        const res = await fetch("/api/v1/admin/keys?admin_key=" + encodeURIComponent(key));
        if (res.status === 403) return alert("Неверный мастер-ключ админа!");
        const data = await res.json();
        document.getElementById("statKeysCount").innerText = data.users.length;
        renderKeysTable(data.users);
      } catch(e) { alert("Ошибка загрузки: " + e); }
    }

    function renderKeysTable(users) {
      const tbody = document.getElementById("keysTableBody");
      tbody.innerHTML = "";
      users.forEach(u => {
        const lastSeen = u.last_used_at ? new Date(u.last_used_at * 1000).toLocaleTimeString() : "Никогда";
        const tr = document.createElement("tr");
        tr.className = "hover:bg-gray-800/50 transition";
        tr.innerHTML = `
          <td class="p-3 font-medium text-white">${u.owner}</td>
          <td class="p-3 font-mono text-xs text-gray-300">
            <span class="bg-gray-950 px-2 py-1 rounded border border-gray-800">${u.api_key}</span>
          </td>
          <td class="p-3">
            <span class="px-2 py-0.5 text-xs rounded ${u.enabled ? 'bg-emerald-900/60 text-emerald-400' : 'bg-red-900/60 text-red-400'}">
              ${u.enabled ? 'Активен' : 'Отключен'}
            </span>
          </td>
          <td class="p-3 text-xs text-gray-400">${lastSeen}</td>
          <td class="p-3 text-right space-x-2">
            <button onclick="editUserSlots('${u.api_key}', '${u.owner}')" class="bg-blue-600/80 hover:bg-blue-600 text-white px-2.5 py-1 rounded text-xs">Точки (5)</button>
            <button onclick="toggleKey('${u.api_key}', ${!u.enabled})" class="bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded text-xs">${u.enabled ? 'Выкл' : 'Вкл'}</button>
            <button onclick="deleteKey('${u.api_key}')" class="text-red-400 hover:text-red-300 px-2 py-1 text-xs">Удалить</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function editUserSlots(apiKey, owner) {
      const res = await fetch("/api/v1/slots?token=" + apiKey);
      if (!res.ok) return alert("Ошибка чтения слотов пользователя");
      const data = await res.json();

      document.getElementById("slotsSection").classList.remove("hidden");
      document.getElementById("currentSlotOwner").innerText = owner;
      const container = document.getElementById("slotsCardsContainer");
      container.innerHTML = "";

      Object.keys(data.slots).sort().forEach(slotId => {
        const s = data.slots[slotId];
        const isDyn = s.type === "dynamic";
        const card = document.createElement("div");
        card.className = "bg-gray-950 border border-gray-800 p-3 rounded";
        card.innerHTML = `
          <div class="flex justify-between items-center mb-2">
            <span class="text-xs font-bold text-gray-400">СЛОТ #${slotId} ${isDyn ? '(Динамический GPS)' : ''}</span>
            <span class="text-xs px-2 py-0.5 rounded ${isDyn ? 'bg-purple-900/60 text-purple-300' : 'bg-blue-900/60 text-blue-300'}">${s.type}</span>
          </div>
          <div class="space-y-2">
            <input id="name_${slotId}" type="text" value="${s.name}" class="w-full bg-gray-900 border border-gray-700 px-2.5 py-1 rounded text-sm text-white" placeholder="Название точки">
            <div class="flex gap-2">
              <input id="lat_${slotId}" type="number" step="0.0001" value="${s.lat}" class="w-1/2 bg-gray-900 border border-gray-700 px-2 py-1 rounded text-xs text-white" placeholder="Широта (Lat)">
              <input id="lon_${slotId}" type="number" step="0.0001" value="${s.lon}" class="w-1/2 bg-gray-900 border border-gray-700 px-2 py-1 rounded text-xs text-white" placeholder="Долгота (Lon)">
            </div>
            <button onclick="saveSlot('${apiKey}', '${slotId}')" class="w-full bg-gray-800 hover:bg-gray-700 text-blue-400 py-1 rounded text-xs font-semibold mt-1">Сохранить слот</button>
          </div>
        `;
        container.appendChild(card);
      });
    }

    async function saveSlot(apiKey, slotId) {
      const name = document.getElementById("name_" + slotId).value;
      const lat = parseFloat(document.getElementById("lat_" + slotId).value);
      const lon = parseFloat(document.getElementById("lon_" + slotId).value);

      const res = await fetch("/api/v1/slots/" + slotId + "?token=" + apiKey, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, lat, lon })
      });
      if (res.ok) alert("Слот #" + slotId + " успешно сохранён!");
      else alert("Ошибка сохранения слота");
    }

    async function toggleKey(key, enabled) {
      await fetch("/api/v1/admin/keys/" + encodeURIComponent(key) + "?admin_key=" + encodeURIComponent(currentAdminKey), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled })
      });
      loadKeys();
    }

    async function deleteKey(key) {
      if (!confirm("Вы уверены, что хотите отозвать этот API-ключ?")) return;
      await fetch("/api/v1/admin/keys/" + encodeURIComponent(key) + "?admin_key=" + encodeURIComponent(currentAdminKey), {
        method: "DELETE"
      });
      loadKeys();
    }

    async function openCreateModal() {
      const owner = prompt("Введите имя владельца (например: 'Жена (Анна)', 'Сын'):");
      if (!owner) return;
      await fetch("/api/v1/admin/keys?admin_key=" + encodeURIComponent(currentAdminKey), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ owner })
      });
      loadKeys();
    }

    function downloadBackup() {
      if (!currentAdminKey) return alert("Сначала введите мастер-ключ админа");
      window.location.href = "/api/v1/admin/backup?admin_key=" + encodeURIComponent(currentAdminKey);
    }

    async function uploadBackup(event) {
      const file = event.target.files[0];
      if (!file) return;
      if (!currentAdminKey) return alert("Сначала введите мастер-ключ админа");
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
          alert("Бэкап успешно восстановлен! Загружено ключей: " + resp.users_count);
          loadKeys();
        } else {
          alert("Ошибка восстановления: " + (resp.error || "Неизвестная ошибка"));
        }
      } catch (e) {
        alert("Ошибка чтения файла: " + e);
      }
      event.target.value = "";
    }

    updateTelemetry();
    setInterval(updateTelemetry, 4000);
    if (currentAdminKey) loadKeys();
  </script>
</body>
</html>
"""

async def handle_admin_dashboard(request: web.Request):
    # Если запрос пришёл через Cloudflare Tunnel или извне — возвращаем 404 (будто страницы не существует)
    if is_external_request(request):
        return web.Response(text="404: Not Found", status=404)
    return web.Response(text=ADMIN_HTML, content_type="text/html")

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
        "proxy_enabled": bool(UPSTREAM_PROXY),
        "proxy_info": mask_proxy(UPSTREAM_PROXY)
    }))
    app.router.add_get("/api/v1/slots", handle_get_slots)
    app.router.add_put("/api/v1/slots/{slot_id}", handle_update_slot)
    app.router.add_post("/api/v1/locations/dynamic", handle_update_dynamic)
    app.router.add_get("/api/v1/threats", handle_get_threats)
    app.router.add_get("/api/v1/radar", handle_get_radar)
    app.router.add_get("/api/v1/stream", handle_websocket_stream)

    app.router.add_get("/admin", handle_admin_dashboard)
    app.router.add_get("/api/v1/admin/keys", handle_admin_get_keys)
    app.router.add_post("/api/v1/admin/keys", handle_admin_create_key)
    app.router.add_put("/api/v1/admin/keys/{key}", handle_admin_update_key)
    app.router.add_delete("/api/v1/admin/keys/{key}", handle_admin_delete_key)
    app.router.add_get("/api/v1/admin/backup", handle_admin_backup)
    app.router.add_post("/api/v1/admin/restore", handle_admin_restore)

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app

if __name__ == "__main__":
    logger.info(f"Старт Air Alert Hub на порту {PORT}...")
    web_app = create_app()
    web.run_app(web_app, host="0.0.0.0", port=PORT, access_log=None)
