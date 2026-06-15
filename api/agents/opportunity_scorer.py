
"""Program Opportunity Scorer for BountyOS.

Ranks bug bounty programs by effort vs reward using lightweight heuristics.
This is not a guarantee of bounty. It is a prioritization helper for authorized programs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional

from api.models import BountyProgram


def _json_list(raw: str) -> List[str]:
    try:
        data = json.loads(raw or "[]")
        if isinstance(data, list):
            return [str(x).strip() for x in data if str(x).strip()]
    except Exception:
        pass
    return []


def _raw_text(program: BountyProgram) -> str:
    return " ".join([
        program.name or "",
        program.platform or "",
        program.url or "",
        program.reward_hint or "",
        program.scope_raw or "",
        program.domains_json or "",
        program.status or "",
    ]).lower()


def _parse_reward_hint(text: str) -> int:
    numbers = []
    for m in re.findall(r"(?:\$|usd|eur|€|£)?\s*([0-9][0-9,]{2,})", text.lower()):
        try:
            numbers.append(int(m.replace(',', '')))
        except Exception:
            pass
    if not numbers:
        return 0
    high = max(numbers)
    if high >= 10000:
        return 12
    if high >= 5000:
        return 9
    if high >= 1000:
        return 6
    return 3


@dataclass
class OpportunityResult:
    program_id: str
    name: str
    platform: str
    url: Optional[str]
    offers_bounty: bool
    reward_hint: Optional[str]
    status: str
    score: int
    difficulty: str
    money_potential: str
    effort: str
    confidence: float
    scope_stats: Dict[str, Any]
    best_bug_classes: List[str]
    reasons: List[str]
    warnings: List[str]
    recommended_first_moves: List[str]
    summary: str

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProgramOpportunityScorer:
    ecommerce_terms = ["shop", "store", "cart", "checkout", "payment", "billing", "invoice", "subscription", "coupon", "order", "wallet", "bank", "pay", "commerce"]
    account_terms = ["account", "user", "team", "invite", "organization", "workspace", "role", "tenant", "admin", "member", "profile"]
    api_terms = ["api", "graphql", "rest", "v1", "v2", "v3", "mobile-api", "gateway"]
    mobile_terms = ["android", "ios", "mobile", "apk", "app store", "play store"]
    hardened_terms = ["google", "microsoft", "apple", "meta", "facebook", "amazon", "github", "cloudflare"]

    def score(self, program: BountyProgram) -> OpportunityResult:
        domains = _json_list(program.domains_json)
        text = _raw_text(program)
        score = 35
        reasons: List[str] = []
        warnings: List[str] = []
        bug_classes: List[str] = []

        wildcard_count = sum(1 for d in domains if "*" in d)
        api_count = sum(1 for d in domains if any(k in d.lower() for k in self.api_terms))
        www_only = len(domains) == 1 and (domains[0].startswith("www.") or domains[0].count('.') <= 1)

        if program.offers_bounty:
            score += 14; reasons.append("Bounty enabled / money-focused program.")
        else:
            score -= 16; warnings.append("No clear bounty signal; may be VDP/no reward.")

        if domains:
            if len(domains) >= 20:
                score += 14; reasons.append("Large scope with many assets.")
            elif len(domains) >= 6:
                score += 10; reasons.append("Good multi-asset scope.")
            elif len(domains) >= 2:
                score += 5; reasons.append("Multiple scope roots available.")
            else:
                score -= 4; warnings.append("Small scope; fewer places to find bugs.")
        else:
            score -= 12; warnings.append("No domains extracted yet; import/sync more data first.")

        if wildcard_count:
            score += min(14, 7 + wildcard_count * 2); reasons.append("Wildcard scope increases recon surface.")
        if api_count or any(k in text for k in self.api_terms):
            score += 12; reasons.append("API/GraphQL surface detected; good for IDOR/authz bugs."); bug_classes += ["IDOR", "broken access control", "GraphQL/API misconfig"]
        if any(k in text for k in self.mobile_terms):
            score += 8; reasons.append("Mobile/API clues detected; mobile APIs often expose useful endpoints."); bug_classes += ["mobile API authorization", "token/session issues"]
        if any(k in text for k in self.ecommerce_terms):
            score += 11; reasons.append("Payment/e-commerce/business logic surface detected."); bug_classes += ["payment logic", "coupon/order abuse", "IDOR"]
        if any(k in text for k in self.account_terms):
            score += 8; reasons.append("Accounts/teams/roles surface detected."); bug_classes += ["RBAC bypass", "invite abuse", "tenant isolation"]

        reward_boost = _parse_reward_hint(program.reward_hint or text)
        if reward_boost:
            score += reward_boost; reasons.append("Reward range looks worthwhile.")

        if "paused" in (program.status or "").lower() or "inactive" in (program.status or "").lower():
            score -= 16; warnings.append("Program status is not clearly active.")
        if www_only:
            score -= 8; warnings.append("Looks like mostly one marketing/www asset.")
        if any(k in text for k in self.hardened_terms):
            score -= 7; warnings.append("Very popular/hardened target; competition may be high.")
        if "out of scope" in text and ("automated" in text or "scanner" in text):
            score -= 5; warnings.append("Rules may limit automated scanning; review program policy first.")

        score = max(0, min(100, score))
        if score >= 82:
            difficulty, effort, money = "Easy-Medium", "Low-Medium", "High"
        elif score >= 68:
            difficulty, effort, money = "Medium", "Medium", "Medium-High"
        elif score >= 50:
            difficulty, effort, money = "Medium-Hard", "Medium-High", "Medium"
        else:
            difficulty, effort, money = "Hard", "High", "Low-Medium"

        if not bug_classes:
            bug_classes = ["recon exposure", "misconfiguration", "access control"]
        # Deduplicate while preserving order
        seen = set(); bug_classes = [x for x in bug_classes if not (x in seen or seen.add(x))]

        moves = [
            "Read program policy and confirm bounty + in-scope assets.",
            "Import top scope roots into BountyOS targets.",
            "Run passive recon first: CT logs, archived URLs, JS endpoint discovery.",
            "Prioritize API/auth/account flows before noisy scanning.",
            "Run Bug Hunter Brain after passive results to rank likely bug classes.",
        ]
        if api_count or any(k in text for k in self.api_terms):
            moves.append("Map object IDs, roles, teams, and API versions for IDOR/RBAC checks.")
        if any(k in text for k in self.ecommerce_terms):
            moves.append("Review order/payment/coupon/subscription state changes for business logic bugs.")

        summary = (
            f"{program.name} scores {score}/100. Difficulty: {difficulty}. "
            f"Money potential: {money}. Effort: {effort}. "
            "This is a probability ranking, not a bounty guarantee."
        )

        return OpportunityResult(
            program_id=program.id,
            name=program.name,
            platform=program.platform,
            url=program.url,
            offers_bounty=program.offers_bounty,
            reward_hint=program.reward_hint,
            status=program.status,
            score=score,
            difficulty=difficulty,
            money_potential=money,
            effort=effort,
            confidence=0.72 if domains else 0.55,
            scope_stats={
                "domains": len(domains),
                "wildcards": wildcard_count,
                "api_like_domains": api_count,
                "sample_domains": domains[:10],
            },
            best_bug_classes=bug_classes[:6],
            reasons=reasons[:8],
            warnings=warnings[:6],
            recommended_first_moves=moves,
            summary=summary,
        )

    def rank(self, programs: Iterable[BountyProgram], platform: Optional[str] = None, bounty_only: bool = True, limit: int = 20) -> List[Dict[str, Any]]:
        items = list(programs)
        if platform:
            items = [p for p in items if (p.platform or "").lower() == platform.lower()]
        if bounty_only:
            items = [p for p in items if p.offers_bounty]
        ranked = [self.score(p).as_dict() for p in items]
        ranked.sort(key=lambda x: (x["score"], x["scope_stats"]["domains"]), reverse=True)
        return ranked[: max(1, min(limit, 100))]


opportunity_scorer = ProgramOpportunityScorer()
