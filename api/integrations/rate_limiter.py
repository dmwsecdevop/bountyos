import time
import threading
from typing import Dict

class RateLimiter:
    def __init__(self):
        self._limits: Dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_wait(self, provider: str):
        with self._lock:
            now = time.time()
            # Simple adaptive backoff: 0.5s delay if accessed too frequently
            last_access = self._limits.get(provider, 0)
            if now - last_access < 0.5:
                time.sleep(0.5)
            self._limits[provider] = time.time()
