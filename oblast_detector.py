import json
import os

class OblastDetector:
    """Быстрый локальный детектор областей Украины по координатам (Ray-casting 2D) и маппер регионов."""
    def __init__(self, geojson_path: str = None):
        if not geojson_path:
            geojson_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "regions.geojson")
        
        self.regions = []
        self.oblasts_by_id = {}
        self.region_to_oblast = {}
        self.raions_by_id = {}
        self.raion_name_to_id = {}

        if not os.path.exists(geojson_path):
            return

        try:
            with open(geojson_path, "r", encoding="utf-8") as f:
                d = json.load(f)

            # 1. Загрузка 26 областей (Rank 1)
            for feat in d.get("features", []):
                props = feat.get("properties", {})
                if props.get("rank") == 1:
                    name = props.get("name")
                    reg_id = str(props.get("regionId"))
                    geom = feat.get("geometry", {})
                    
                    polygons = []
                    if geom.get("type") == "Polygon":
                        polygons = geom.get("coordinates", [])
                    elif geom.get("type") == "MultiPolygon":
                        for poly in geom.get("coordinates", []):
                            polygons.extend(poly)

                    if not polygons:
                        continue

                    all_pts = [pt for ring in polygons for pt in ring]
                    min_lon = min(pt[0] for pt in all_pts)
                    max_lon = max(pt[0] for pt in all_pts)
                    min_lat = min(pt[1] for pt in all_pts)
                    max_lat = max(pt[1] for pt in all_pts)

                    ob_data = {
                        "id": reg_id,
                        "name": name,
                        "bbox": (min_lon, min_lat, max_lon, max_lat),
                        "center": ((min_lat + max_lat) / 2.0, (min_lon + max_lon) / 2.0),
                        "polygons": polygons
                    }
                    self.regions.append(ob_data)
                    self.oblasts_by_id[reg_id] = ob_data
                    self.region_to_oblast[reg_id] = reg_id

            # 2. Построение маппинга для районов (Rank 2) и громад (Rank 3)
            for feat in d.get("features", []):
                props = feat.get("properties", {})
                rank = props.get("rank")
                if rank == 1:
                    continue
                rid = str(props.get("regionId"))
                rname = props.get("name", "")
                geom = feat.get("geometry", {})
                polygons = []
                if geom.get("type") == "Polygon":
                    polygons = geom.get("coordinates", [])
                elif geom.get("type") == "MultiPolygon":
                    for poly in geom.get("coordinates", []):
                        polygons.extend(poly)
                if not polygons or not polygons[0]:
                    continue

                pt = polygons[0][0]
                px, py = pt[0], pt[1]
                f_id = None
                for r1_id, r1_d in self.oblasts_by_id.items():
                    b = r1_d["bbox"]
                    if b[0] <= px <= b[2] and b[1] <= py <= b[3]:
                        for ring in r1_d["polygons"]:
                            if self._point_in_polygon(px, py, ring):
                                f_id = r1_id
                                break
                        if f_id:
                            break

                if not f_id:
                    best_d = 999999.0
                    for r1_id, r1_d in self.oblasts_by_id.items():
                        b = r1_d["bbox"]
                        dist = (px - (b[0] + b[2]) / 2.0)**2 + (py - (b[1] + b[3]) / 2.0)**2
                        if dist < best_d:
                            best_d = dist
                            f_id = r1_id

                if f_id:
                    self.region_to_oblast[rid] = f_id

                if rank == 2:
                    self.raions_by_id[rid] = {
                        "id": rid,
                        "name": rname,
                        "oblast_id": f_id or "0"
                    }
                    if rname:
                        rn_lower = rname.lower().strip()
                        self.raion_name_to_id[rn_lower] = rid
                        short = rn_lower.replace("район", "").strip()
                        self.raion_name_to_id[short] = rid

        except Exception as e:
            print(f"[WARN] Ошибка загрузки regions.geojson: {e}")

    @staticmethod
    def _point_in_polygon(x: float, y: float, poly: list) -> bool:
        n = len(poly)
        inside = False
        p1x, p1y = poly[0]
        for i in range(1, n + 1):
            p2x, p2y = poly[i % n]
            if y > min(p1y, p2y):
                if y <= max(p1y, p2y):
                    if x <= max(p1x, p2x):
                        if p1y != p2y:
                            xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                        if p1x == p2x or x <= xinters:
                            inside = not inside
            p1x, p1y = p2x, p2y
        return inside

    def get_oblast_id_by_region(self, region_id: str) -> str:
        """Возвращает ID области (Rank 1) для любого района или громады."""
        return self.region_to_oblast.get(str(region_id), "0")

    def get_oblast_id_by_name(self, name: str) -> str:
        """Поиск ID области по её названию (на украинском языке, с учетом падежей и префиксов)."""
        if not name:
            return "0"
        n = name.lower().strip()
        if not hasattr(self, "_name_to_id"):
            self._name_to_id = {}
            for r in self.regions:
                r_name = r["name"].lower()
                self._name_to_id[r_name] = r["id"]
                short = r_name.replace("область", "").replace("м.", "").strip()
                self._name_to_id[short] = r["id"]
            self._name_to_id["автономна республіка крим"] = "9999"
            self._name_to_id["крим"] = "9999"
            self._name_to_id["севастополь"] = "9999"
            self._name_to_id["м. київ"] = "31"
            self._name_to_id["київ"] = "31"

        if n in self._name_to_id:
            return self._name_to_id[n]
        short_n = n.replace("область", "").replace("м.", "").strip()
        if short_n in self._name_to_id:
            return self._name_to_id[short_n]
        for k, v in self._name_to_id.items():
            if len(k) > 4 and (k in n or n in k):
                return v
        return "0"

    def get_all_oblasts(self) -> list:
        """Возвращает список всех 26 областей Украины с ID, названиями и координатами центра."""
        result = []
        for r in self.regions:
            result.append({
                "id": r["id"],
                "name": r["name"],
                "center_lat": round(r["center"][0], 4),
                "center_lon": round(r["center"][1], 4),
                "bbox": [round(x, 4) for x in r["bbox"]]
            })
        return result

    def get_raion_id_by_name(self, name: str) -> str:
        """Поиск ID района (Rank 2) по его названию."""
        if not name:
            return "0"
        n = name.lower().strip()
        if n in self.raion_name_to_id:
            return self.raion_name_to_id[n]
        short_n = n.replace("район", "").strip()
        if short_n in self.raion_name_to_id:
            return self.raion_name_to_id[short_n]
        for k, v in self.raion_name_to_id.items():
            if len(k) > 4 and (k in n or n in k):
                return v
        return "0"

    def get_all_raions(self) -> list:
        """Возвращает список всех районов (Rank 2)."""
        return list(self.raions_by_id.values())

    def find_oblast_info(self, lat: float, lon: float) -> dict:
        if not self.regions:
            return {"name": "Не визначено", "id": "0"}

        # 1. Быстрый фильтр по Bounding Box
        candidates = []
        for reg in self.regions:
            b = reg["bbox"]
            if b[0] <= lon <= b[2] and b[1] <= lat <= b[3]:
                candidates.append(reg)

        if not candidates:
            return {"name": "Поза межами України", "id": "0"}

        # 2. Точная проверка вхождения в полигон
        for reg in candidates:
            for ring in reg["polygons"]:
                if self._point_in_polygon(lon, lat, ring):
                    return {"name": reg["name"], "id": reg["id"]}

        return {"name": candidates[0]["name"], "id": candidates[0]["id"]}

    def find_oblast(self, lat: float, lon: float) -> str:
        return self.find_oblast_info(lat, lon)["name"]
