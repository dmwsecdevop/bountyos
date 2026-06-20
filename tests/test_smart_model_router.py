from api.agents.model_router import ModelExpertRouter


def test_performance_router_uses_flash_for_api_recon():
    router = ModelExpertRouter()
    route = router.route(
        "plan passive recon for api.example.com swagger JWT",
        "start_passive_scan",
        target_context={"domain": "api.example.com", "scope": "OpenAPI and JWT endpoints"},
    )
    assert route.policy == "performance"
    assert route.model == "gemini-2.5-flash"
    assert route.target_profile == "api"
    assert "arjun" in route.selected_tools
    assert "swagger/openapi discovery" in route.selected_tools
    assert route.requires_approval is False


def test_performance_router_uses_pro_for_exploit_reasoning_with_approval():
    router = ModelExpertRouter()
    route = router.route(
        "validate IDOR proof of concept for high severity finding",
        "exploit_reasoning",
        has_scan_context=True,
        target_context={"domain": "app.example.com", "scope": "SaaS app with tenant roles"},
    )
    assert route.model == "gemini-2.5-pro"
    assert route.target_profile == "saas_web_app"
    assert route.requires_approval is True
    assert route.approval_reason
    assert "least-intrusive validation checklist" in route.selected_tools
