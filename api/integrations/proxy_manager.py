import random
import threading
from typing import List, Optional

class ProxyManager:
    def __init__(self, proxy_list_path: str = "proxy_list.txt"):
        self.proxy_list_path = proxy_list_path
        self._proxies: List[str] = []
        self._lock = threading.Lock()
        self._load_proxies()

    def _load_proxies(self):
        try:
            with open(self.proxy_list_path, "r") as f:
                self._proxies = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Default to empty list if no file exists for now
            self._proxies = []

    def get_proxy(self) -> Optional[str]:
        with self._lock:
            if not self._proxies:
                return None
            return random.choice(self._proxies)

    def report_failure(self, proxy: str):
        with self._lock:
            if proxy in self._proxies:
                self._proxies.remove(proxy)

