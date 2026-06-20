"""Async Gemini client used by Hunter Brain / Architect Agent.

This module keeps provider calls out of FastAPI routes and deliberately does
not provide canned AI responses. Callers get the Gemini text or an exception.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
from dataclasses import dataclass
from typing import Any, Iterable

import httpx


class GeminiClientError(RuntimeError):
    """Raised when Gemini cannot be called or returns an unusable response."""


@dataclass(frozen=True)
class GeminiResult:
    provider: str
    model: str
    text: str
    route: str


class GeminiClient:
    """Small async Gemini client with SDK-first and REST fallback transport."""

    def __init__(self, api_key: str | None = None, timeout_seconds: float = 60.0, retries: int = 2) -> None:
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.timeout_seconds = timeout_seconds
        self.retries = retries

    async def chat(self, transcript: str | Iterable[dict[str, Any]], *, context: dict[str, Any] | None = None, model: str | None = None) -> GeminiResult:
        selected = model or os.getenv("BOUNTYOS_CHAT_MODEL", os.getenv("BOUNTYOS_LIGHT_MODEL", "gemini-2.5-flash-lite"))
        prompt = self._prompt("General Hunter Brain chat", transcript, context)
        text = await self._generate(selected, prompt)
        return GeminiResult(provider="gemini", model=selected, text=text, route="light_chat")

    async def summarize_scan(self, transcript: str | Iterable[dict[str, Any]], *, context: dict[str, Any] | None = None, model: str | None = None) -> GeminiResult:
        selected = model or os.getenv("BOUNTYOS_RECON_MODEL", "gemini-2.5-flash")
        prompt = self._prompt("Summarize the selected bounty scan with risk, evidence, and next steps", transcript, context)
        text = await self._generate(selected, prompt)
        return GeminiResult(provider="gemini", model=selected, text=text, route="recon_summary")

    async def analyze_findings(self, transcript: str | Iterable[dict[str, Any]], *, context: dict[str, Any] | None = None, model: str | None = None) -> GeminiResult:
        selected = model or os.getenv("BOUNTYOS_VALIDATION_MODEL", os.getenv("BOUNTYOS_EXPLOIT_MODEL", "gemini-2.5-pro"))
        prompt = self._prompt("Analyze findings like a senior bug bounty researcher", transcript, context)
        text = await self._generate(selected, prompt)
        return GeminiResult(provider="gemini", model=selected, text=text, route="bug_reasoning")

    async def write_report(self, transcript: str | Iterable[dict[str, Any]], *, context: dict[str, Any] | None = None, model: str | None = None) -> GeminiResult:
        selected = model or os.getenv("BOUNTYOS_REPORT_MODEL", os.getenv("BOUNTYOS_MAIN_MODEL", "gemini-2.5-pro"))
        prompt = self._prompt("Write a clear bounty report with impact, reproduction, evidence, and remediation", transcript, context)
        text = await self._generate(selected, prompt)
        return GeminiResult(provider="gemini", model=selected, text=text, route="report_writing")

    async def _generate(self, model: str, prompt: str) -> str:
        if not self.api_key:
            raise GeminiClientError("GEMINI_API_KEY is not configured")

        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                if self._sdk_available():
                    return await self._generate_with_sdk(model, prompt)
                return await self._generate_with_rest(model, prompt)
            except Exception as exc:
                last_exc = exc
                if attempt >= self.retries:
                    break
                await asyncio.sleep(0.5 * (attempt + 1))
        raise GeminiClientError(str(last_exc) if last_exc else "Gemini request failed")

    @staticmethod
    def _sdk_available() -> bool:
        return importlib.util.find_spec("google.genai") is not None

    async def _generate_with_sdk(self, model: str, prompt: str) -> str:
        genai = importlib.import_module("google.genai")
        types = importlib.import_module("google.genai.types")

        def call_sdk() -> Any:
            client = genai.Client(api_key=self.api_key)
            return client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=float(os.getenv("BOUNTYOS_AI_TEMPERATURE", "0.2")),
                    max_output_tokens=4096,
                ),
            )

        raw = await asyncio.wait_for(asyncio.to_thread(call_sdk), timeout=self.timeout_seconds)
        return self._extract_sdk_text(raw)

    async def _generate_with_rest(self, model: str, prompt: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": float(os.getenv("BOUNTYOS_AI_TEMPERATURE", "0.2")),
                "maxOutputTokens": 4096,
            },
        }
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(url, params={"key": self.api_key}, json=payload)
            response.raise_for_status()
            data = response.json()
        return self._extract_rest_text(data)

    @staticmethod
    def _extract_sdk_text(raw: Any) -> str:
        direct = getattr(raw, "text", None)
        if direct:
            return str(direct).strip()
        parts: list[str] = []
        for candidate in getattr(raw, "candidates", None) or []:
            content = getattr(candidate, "content", None)
            for part in getattr(content, "parts", None) or []:
                text = getattr(part, "text", None)
                if text:
                    parts.append(str(text))
        text = "".join(parts).strip()
        if not text:
            raise GeminiClientError("Gemini returned no text")
        return text

    @staticmethod
    def _extract_rest_text(data: dict[str, Any]) -> str:
        parts: list[str] = []
        for candidate in data.get("candidates", []):
            for part in candidate.get("content", {}).get("parts", []):
                text = part.get("text")
                if text:
                    parts.append(str(text))
        text = "".join(parts).strip()
        if not text:
            raise GeminiClientError("Gemini returned no text")
        return text

    @staticmethod
    def _prompt(task: str, transcript: str | Iterable[dict[str, Any]], context: dict[str, Any] | None) -> str:
        if isinstance(transcript, str):
            conversation = transcript
        else:
            conversation = "\n".join(f"{m.get('role', 'user')}: {m.get('content', '')}" for m in transcript)
        return (
            "You are BountyOS v6 Hunter Brain, a Gemini-only autonomous bug bounty operating system for authorized work.\n"
            "Return concise operational guidance, not chatbot filler or verbose reasoning transcripts.\n"
            "For exploit validation, use existing evidence, least-intrusive checks first, and request explicit approval before active testing.\n"
            "Prefer structured summaries with exact next safe actions, selected tools, confidence, impact, and evidence needs.\n\n"
            f"Task: {task}\n\n"
            f"Context:\n{context or {}}\n\n"
            f"Transcript:\n{conversation}\n"
        )
