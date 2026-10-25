import json
import os

class OblastDetector:
    """Быстрый локальный детектор областей Украины по координатам (Ray-casting 2D)."""
    def __init__(self, geojson_path: str = None):
        if not geojson_path:
            geojson_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "regions.geojson")
        
        self.regions = []
        if not os.path.exists(geojson_path):
            return

        try:
            with open(geojson_path, "r", encoding="utf-8") as f:
                d = json.load(f)

            for feat in d.get("features", []):
                # Нам нужны только области (rank 1)
                if feat.get("properties", {}).get("rank") == 1:
                    name = feat["properties"].get("name")
                    reg_id = feat["properties"].get("regionId")
                    geom = feat.get("geometry", {})
                    
                    polygons = []
                    if geom.get("type") == "Polygon":
                        polygons = geom.get("coordinates", [])
                    elif geom.get("type") == "MultiPolygon":
                        for poly in geom.get("coordinates", []):
                            polygons.extend(poly)

                    if not polygons:
                        continue

                    # Вычисление Bounding Box [min_lon, min_lat, max_lon, max_lat]
                    all_pts = [pt for ring in polygons for pt in ring]
                    min_lon = min(pt[0] for pt in all_pts)
                    max_lon = max(pt[0] for pt in all_pts)
                    min_lat = min(pt[1] for pt in all_pts)
                    max_lat = max(pt[1] for pt in all_pts)

                    self.regions.append({
                        "id": reg_id,
                        "name": name,
                        "bbox": (min_lon, min_lat, max_lon, max_lat),
                        "polygons": polygons
                    })
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
