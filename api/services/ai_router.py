from __future__ import annotations

import asyncio
import os
from typing import Any

from api.ai import get_ai_client, provider_status as base_provider_status

PURPOSE_ENV = {
    "fast_chat": "BOUNTYOS_FAST_MODEL",
    "recon_summary": "BOUNTYOS_FAST_MODEL",
    "bug_reasoning": "BOUNTYOS_REASONING_MODEL",
    "debate_review": "BOUNTYOS_DEBATE_MODEL",
    "report_writing": "BOUNTYOS_REPORT_MODEL",
}
DEFAULT_MODELS = {
    "fast_chat": "gemini-2.5-flash",
    "recon_summary": "gemini-2.5-flash",
    "bug_reasoning": "gemini-2.5-pro",
    "debate_review": "gemini-2.5-flash",
    "report_writing": "gemini-2.5-pro",
}


def configured_provider() -> str:
    if os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "false").lower() in {"1", "true", "yes", "on"}:
        return "vertex"
    return os.getenv("BOUNTYOS_MAIN_PROVIDER", os.getenv("BOUNTYOS_AI_PROVIDER", "gemini")).strip().lower()


def select_model(purpose: str = "fast_chat") -> str:
    env_name = PURPOSE_ENV.get(purpose, "BOUNTYOS_MAIN_MODEL")
    return os.getenv(env_name) or os.getenv("BOUNTYOS_MAIN_MODEL") or DEFAULT_MODELS.get(purpose, "gemini-2.5-flash")


def provider_status() -> dict[str, Any]:
    base = base_provider_status()
    base.update({
        "provider": configured_provider(),
        "vertex_enabled": os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "false").lower() in {"1", "true", "yes", "on"},
        "models_by_purpose": {purpose: select_model(purpose) for purpose in PURPOSE_ENV},
    })
    return base


async def generate_text(prompt: str, *, purpose: str = "fast_chat", max_tokens: int = 1500, system: str | None = None) -> str:
    client = get_ai_client()
    response = await asyncio.to_thread(
        client.messages.create,
        model=select_model(purpose),
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    parts = getattr(response, "content", []) or []
    return "\n".join(str(getattr(part, "text", "")) for part in parts if getattr(part, "text", None))
