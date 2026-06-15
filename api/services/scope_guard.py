from __future__ import annotations
from urllib.parse import urlparse

def normalize_host(url_or_domain: str | None) -> str:
    raw = (url_or_domain or "").strip().lower()
    if not raw: return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="http")
    host = parsed.hostname or raw.split('/')[0]
    return host.strip('.').lower()

def is_subdomain_or_same(host: str, root_domain: str) -> bool:
    h, r = normalize_host(host), normalize_host(root_domain)
    return bool(h and r and (h == r or h.endswith('.' + r)))

def is_target_in_scope(target_url: str, allowed_roots: list[str]) -> bool:
    host = normalize_host(target_url)
    return any(is_subdomain_or_same(host, root) for root in allowed_roots if root)
