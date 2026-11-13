import json
from pathlib import Path


class IOC_Cache:
    def __init__(self, cache_path: str = "data/ioc_cache.json"):
        self.cache_path = Path(cache_path)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.cache_path.exists():
            self.cache_path.write_text("{}", encoding="utf-8")

        self.data = self._load()

    def _load(self) -> dict:
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def get(self, ioc: str):
        return self.data.get(ioc)

    def set(self, ioc: str, result: dict):
        self.data[ioc] = result
        self.cache_path.write_text(
            json.dumps(self.data, indent=4, ensure_ascii=False),
            encoding="utf-8",
        )
