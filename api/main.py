"""
BountyOS - Main FastAPI application
Run: uvicorn api.main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
import os
import posixpath

from api.database import init_db
# ensure SQLModel service tables are registered before init_db runs
from api.services import agent_revisions, agent_tasks, browser_agent, debate_engine, knowledge_graph, mobile_apk, takeover_monitor  # type: ignore

from api.routes.targets      import router as targets_router
from api.routes.scans        import router as scans_router
from api.routes.findings     import findings_router, approvals_router
from api.routes.ws           import router as ws_router
from api.routes.ai           import router as ai_router
from api.routes.caido        import router as caido_router
from api.routes.integrations import router as integrations_router
from api.routes.integration_config import router as integration_config_router
from api.routes.agent        import router as agent_router
from api.routes.live         import router as live_router, ws_router as live_ws_router
from api.routes.programs     import router as programs_router
from api.routes.live_data   import router as live_data_router
from api.routes.accounts    import router as accounts_router
from api.routes.connector_health import router as connector_health_router
from api.routes.hunter       import router as hunter_router
from api.routes.quality      import router as quality_router
from api.routes.runners      import router as runners_router, ws_router as runners_ws_router
from api.routes.debate       import router as debate_router
from api.routes.skills       import router as skills_router
from api.routes.tasks        import router as tasks_router
from api.routes.knowledge    import router as knowledge_router
from api.routes.takeovers    import router as takeovers_router
from api.routes.browser      import router as browser_router
from api.routes.mobile       import router as mobile_router
from api.routes.reports      import router as reports_router
from api.routes.evals        import router as evals_router
from api.routes.exploit      import router as exploit_router
from api.routes.upgrades     import router as upgrades_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    print("\n🔍 BountyOS Tool Discovery starting...")
    from api.tools.discovery import discover_all_tools
    discover_all_tools()
    print("✅ Tool discovery complete\n")
    yield


app = FastAPI(
    title="BountyOS",
    description="Autonomous bug bounty — passive & aggressive modes",
    version=os.getenv("BOUNTYOS_VERSION", "6.0.0"),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(targets_router,      prefix="/api/v1")
app.include_router(scans_router,        prefix="/api/v1")
app.include_router(findings_router,     prefix="/api/v1")
app.include_router(approvals_router,    prefix="/api/v1")
app.include_router(ai_router,           prefix="/api/v1")
app.include_router(caido_router,        prefix="/api/v1")
app.include_router(integrations_router, prefix="/api/v1")
app.include_router(integration_config_router, prefix="/api/v1")
app.include_router(agent_router,        prefix="/api/v1")
app.include_router(live_router,         prefix="/api/v1")
app.include_router(programs_router,     prefix="/api/v1")
app.include_router(live_data_router,    prefix="/api/v1")
app.include_router(accounts_router,     prefix="/api/v1")
app.include_router(connector_health_router, prefix="/api/v1")
app.include_router(hunter_router, prefix="/api/v1")
app.include_router(quality_router, prefix="/api/v1")
app.include_router(runners_router, prefix="/api/v1")
app.include_router(debate_router, prefix="/api/v1")
app.include_router(skills_router, prefix="/api/v1")
app.include_router(tasks_router, prefix="/api/v1")
app.include_router(knowledge_router, prefix="/api/v1")
app.include_router(takeovers_router, prefix="/api/v1")
app.include_router(browser_router, prefix="/api/v1")
app.include_router(mobile_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(evals_router, prefix="/api/v1")
app.include_router(exploit_router, prefix="/api/v1")
app.include_router(upgrades_router, prefix="/api/v1")
app.include_router(ws_router)
app.include_router(live_ws_router)
app.include_router(runners_ws_router)


@app.get("/health")
def health():
    from api.tools.discovery import ALL_TOOLS, refresh_remote_tools
    from api.runners.manager import runner_manager
    refresh_remote_tools()
    from api.services.ai_router import provider_status
    from api.database import database_health
    from api.services.debate_engine import debate_enabled, debate_model
    from api.services.skill_registry import skill_count
    from api.services.takeover_monitor import takeover_enabled, verify_tls
    from api.services.browser_agent import browser_enabled
    return {
        "status": "ok",
        "version": os.getenv("BOUNTYOS_VERSION", "6.0.0"),
        "tools_available": len(ALL_TOOLS),
        "agent": "architect_moe",
        "ai": provider_status(),
        "program_radar": "enabled",
        "live_data": "enabled",
        "database": database_health(),
        "skill_registry": {"enabled": True, "skill_count": skill_count()},
        "agent_tasks": {"enabled": True},
        "knowledge_graph": {"enabled": True},
        "takeover_monitor": {"enabled": takeover_enabled(), "verify_tls": verify_tls()},
        "debate_engine": {"enabled": debate_enabled(), "model": debate_model()},
        "browser_agent": {"enabled": browser_enabled(), "mode": "metadata-only"},
        "mobile_apk": {"enabled": True, "mode": "metadata-only"},
        "report_builder": {"enabled": True},
        "evals": {"enabled": True},
    }


@app.get("/")
def root():
    index = "static/index.html"
    if os.path.exists(index):
        return FileResponse(index)
    return {"message": "BountyOS API", "dashboard": "static/index.html not found"}


if os.path.isdir("static"):
    app.mount("/assets", StaticFiles(directory="static/assets"), name="assets") if os.path.isdir("static/assets") else None


@app.get("/{full_path:path}")
def spa_fallback(full_path: str):
    """Serve static dashboard assets and fall back to React SPA index."""
    safe_path = posixpath.normpath(full_path).lstrip("/")
    if safe_path.startswith(".."):
        raise HTTPException(404, "Not found")

    static_root = os.path.realpath("static")
    candidate = os.path.join(static_root, safe_path)
    candidate_real = os.path.realpath(candidate)

    if os.path.commonpath([static_root, candidate_real]) != static_root:
        raise HTTPException(404, "Not found")

    if safe_path and os.path.isfile(candidate_real):
        return FileResponse(candidate_real)
    index = "static/index.html"
    if os.path.exists(index):
        return FileResponse(index)
    raise HTTPException(404, "Not found")
