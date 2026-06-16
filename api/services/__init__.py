"""
Package initializer for api.services to ensure modules register SQLModel tables
without causing heavy import-time side effects.
"""

# Import only modules that define SQLModel models or light-weight service metadata.
# Avoid importing modules that perform network I/O or start background tasks.

from importlib import import_module

# List modules that define SQLModel models or provide small helpers.
_safe_modules = [
    "api.services.debate_engine",
    "api.services.agent_revisions",
    "api.services.skill_registry",
]

for m in _safe_modules:
    try:
        import_module(m)
    except Exception:
        # Swallow exceptions here; if a module fails to import due to missing
        # optional dependencies we'll surface that at runtime when the service
        # is actually used.
        pass
