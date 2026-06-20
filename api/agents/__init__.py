# BountyOS agents package
# Route legacy imports of api.agents.model_router to the clean single-pass router.
import sys
from api.agents import model_router_clean as _model_router_clean
sys.modules.setdefault("api.agents.model_router", _model_router_clean)

from api.agents.coordinator       import run_ai_coordinator
from api.agents.exploit_agent     import run_exploit_agent, ExploitResult
from api.agents.passive_agent     import run_passive_agent
from api.agents.aggressive_agent  import run_aggressive_agent
from api.agents.hacker_mindset    import (
    get_hacker_mindset_prompt,
    infer_technologies_from_events,
    get_technology_playbook,
    TECHNOLOGY_PLAYBOOKS,
    HACKER_QUESTIONS,
    BUSINESS_LOGIC_PATTERNS,
    TRUST_ABUSE_PATTERNS,
    IMPACT_ESCALATION,
)
