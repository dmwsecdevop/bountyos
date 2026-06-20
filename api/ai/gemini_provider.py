"""Gemini / Vertex AI compatibility provider for BountyOS.

BountyOS agents use a small ``messages.create`` compatibility interface.
This adapter intentionally exposes the small subset of that interface used by
BountyOS, while sending requests through Google's current ``google-genai`` SDK.
It lets the existing agent loops, tool dispatchers, approvals, and dashboard
continue working without a risky full rewrite.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, Iterable

from google import genai
from google.genai import errors, types


class AIProviderError(RuntimeError):
    """Normalized error raised by the configured AI provider."""


@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict[str, Any]
    type: str = "tool_use"


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class ProviderResponse:
    content: list[Any]
    stop_reason: str
    usage: Usage
    raw: Any = None


class _MessagesAPI:
    def __init__(self, owner: "GeminiCompatClient") -> None:
        self._owner = owner

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: list[dict[str, Any]],
        system: str | None = None,
        tools: list[dict[str, Any]] | None = None,
        **_: Any,
    ) -> ProviderResponse:
        return self._owner.generate(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            system=system,
            tools=tools,
        )


class GeminiCompatClient:
    def __init__(self) -> None:
        self.provider = os.getenv("BOUNTYOS_AI_PROVIDER", "vertex").strip().lower()
        self.project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
        self.location = os.getenv("GOOGLE_CLOUD_LOCATION", "global")
        self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.messages = _MessagesAPI(self)
        self._client: genai.Client | None = None

    def _get_client(self) -> genai.Client:
        if self._client is not None:
            return self._client

        try:
            if self.provider in {"vertex", "vertex_ai", "gcp"}:
                if not self.project:
                    raise AIProviderError(
                        "GOOGLE_CLOUD_PROJECT is required for Vertex AI mode"
                    )
                self._client = genai.Client(
                    vertexai=True,
                    project=self.project,
                    location=self.location,
                    http_options=types.HttpOptions(api_version="v1"),
                )
            elif self.provider in {"gemini", "developer", "developer_api"}:
                if not self.api_key:
                    raise AIProviderError(
                        "GEMINI_API_KEY is required for Gemini Developer API mode"
                    )
                self._client = genai.Client(api_key=self.api_key)
            else:
                raise AIProviderError(
                    f"Unsupported BOUNTYOS_AI_PROVIDER: {self.provider}"
                )
        except AIProviderError:
            raise
        except Exception as exc:  # credentials/config initialization
            raise AIProviderError(f"Unable to initialize Gemini client: {exc}") from exc

        return self._client

    @staticmethod
    def _tool_name_map(messages: Iterable[dict[str, Any]]) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for message in messages:
            if message.get("role") != "assistant":
                continue
            content = message.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                block_type = getattr(block, "type", None)
                if isinstance(block, dict):
                    block_type = block.get("type")
                    block_id = block.get("id")
                    block_name = block.get("name")
                else:
                    block_id = getattr(block, "id", None)
                    block_name = getattr(block, "name", None)
                if block_type == "tool_use" and block_id and block_name:
                    mapping[str(block_id)] = str(block_name)
        return mapping

    @staticmethod
    def _block_value(block: Any, key: str, default: Any = None) -> Any:
        if isinstance(block, dict):
            return block.get(key, default)
        return getattr(block, key, default)

    def _contents(self, messages: list[dict[str, Any]]) -> list[types.Content]:
        tool_names = self._tool_name_map(messages)
        contents: list[types.Content] = []

        for message in messages:
            role = str(message.get("role", "user"))
            raw_content = message.get("content", "")

            if isinstance(raw_content, str):
                contents.append(
                    types.Content(
                        role="model" if role == "assistant" else "user",
                        parts=[types.Part.from_text(text=raw_content)],
                    )
                )
                continue

            if not isinstance(raw_content, list):
                raw_content = [raw_content]

            if role == "assistant":
                parts: list[types.Part] = []
                for block in raw_content:
                    block_type = self._block_value(block, "type")
                    if block_type == "text":
                        text = str(self._block_value(block, "text", ""))
                        if text:
                            parts.append(types.Part.from_text(text=text))
                    elif block_type == "tool_use":
                        name = str(self._block_value(block, "name", ""))
                        args = self._block_value(block, "input", {}) or {}
                        parts.append(types.Part.from_function_call(name=name, args=args))
                if parts:
                    contents.append(types.Content(role="model", parts=parts))
                continue

            # BountyOS sends tool results as a user message containing tool_result blocks.
            tool_parts: list[types.Part] = []
            normal_parts: list[types.Part] = []
            for block in raw_content:
                block_type = self._block_value(block, "type")
                if block_type == "tool_result":
                    call_id = str(self._block_value(block, "tool_use_id", ""))
                    name = tool_names.get(call_id, "tool_result")
                    result = self._block_value(block, "content", "")
                    response = result if isinstance(result, dict) else {"result": str(result)}
                    tool_parts.append(
                        types.Part.from_function_response(name=name, response=response)
                    )
                elif block_type == "text":
                    normal_parts.append(
                        types.Part.from_text(
                            text=str(self._block_value(block, "text", ""))
                        )
                    )
                elif isinstance(block, str):
                    normal_parts.append(types.Part.from_text(text=block))

            if normal_parts:
                contents.append(types.Content(role="user", parts=normal_parts))
            if tool_parts:
                contents.append(types.Content(role="tool", parts=tool_parts))

        return contents

    @staticmethod
    def _tools(tools: list[dict[str, Any]] | None) -> list[types.Tool] | None:
        if not tools:
            return None
        declarations: list[types.FunctionDeclaration] = []
        for tool in tools:
            declarations.append(
                types.FunctionDeclaration(
                    name=str(tool["name"]),
                    description=str(tool.get("description", "")),
                    parameters_json_schema=tool.get("input_schema")
                    or {"type": "object", "properties": {}},
                )
            )
        return [types.Tool(function_declarations=declarations)]

    def generate(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: list[dict[str, Any]],
        system: str | None,
        tools: list[dict[str, Any]] | None,
    ) -> ProviderResponse:
        client = self._get_client()
        gemini_tools = self._tools(tools)
        config = types.GenerateContentConfig(
            system_instruction=system or None,
            max_output_tokens=max_tokens,
            temperature=float(os.getenv("BOUNTYOS_AI_TEMPERATURE", "0.2")),
            tools=gemini_tools,
            automatic_function_calling=types.AutomaticFunctionCallingConfig(
                disable=True
            ),
        )

        try:
            raw = client.models.generate_content(
                model=model,
                contents=self._contents(messages),
                config=config,
            )
        except errors.APIError as exc:
            raise AIProviderError(f"Gemini API error: {exc}") from exc
        except Exception as exc:
            raise AIProviderError(f"Gemini request failed: {exc}") from exc

        blocks: list[Any] = []
        candidate = raw.candidates[0] if getattr(raw, "candidates", None) else None
        parts = getattr(getattr(candidate, "content", None), "parts", None) or []
        for part in parts:
            if getattr(part, "text", None):
                blocks.append(TextBlock(text=part.text))
            function_call = getattr(part, "function_call", None)
            if function_call and getattr(function_call, "name", None):
                call_id = getattr(function_call, "id", None) or uuid.uuid4().hex
                blocks.append(
                    ToolUseBlock(
                        id=str(call_id),
                        name=str(function_call.name),
                        input=dict(function_call.args or {}),
                    )
                )

        has_tool_use = any(getattr(block, "type", "") == "tool_use" for block in blocks)
        stop_reason = "tool_use" if has_tool_use else "end_turn"
        usage_meta = getattr(raw, "usage_metadata", None)
        usage = Usage(
            input_tokens=int(getattr(usage_meta, "prompt_token_count", 0) or 0),
            output_tokens=int(getattr(usage_meta, "candidates_token_count", 0) or 0),
        )
        return ProviderResponse(
            content=blocks,
            stop_reason=stop_reason,
            usage=usage,
            raw=raw,
        )


def provider_status() -> dict[str, Any]:
    provider = os.getenv("BOUNTYOS_AI_PROVIDER", "vertex").strip().lower()
    return {
        "provider": provider,
        "project": os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT"),
        "location": os.getenv("GOOGLE_CLOUD_LOCATION", "global"),
        "main_model": os.getenv("BOUNTYOS_MAIN_MODEL", "gemini-2.5-pro"),
        "light_model": os.getenv("BOUNTYOS_LIGHT_MODEL", "gemini-2.5-flash"),
        "chat_model": os.getenv("BOUNTYOS_CHAT_MODEL", os.getenv("BOUNTYOS_LIGHT_MODEL", "gemini-2.5-flash")),
        "planner_model": os.getenv("BOUNTYOS_PLANNER_MODEL", "gemini-2.5-flash"),
        "parser_model": os.getenv("BOUNTYOS_PARSER_MODEL", "gemini-2.5-flash"),
        "validation_model": os.getenv("BOUNTYOS_VALIDATION_MODEL", os.getenv("BOUNTYOS_EXPLOIT_MODEL", "gemini-2.5-pro")),
        "report_model": os.getenv("BOUNTYOS_REPORT_MODEL", os.getenv("BOUNTYOS_MAIN_MODEL", "gemini-2.5-pro")),
        "recon_model": os.getenv("BOUNTYOS_RECON_MODEL", "gemini-2.5-flash"),
        "validation_model": os.getenv("BOUNTYOS_EXPLOIT_MODEL", "gemini-2.5-pro"),
        "configured": bool(
            (provider in {"vertex", "vertex_ai", "gcp"} and (os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")))
            or (provider in {"gemini", "developer", "developer_api"} and (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")))
        ),
    }


_client_singleton: GeminiCompatClient | None = None


def get_ai_client() -> GeminiCompatClient:
    global _client_singleton
    if _client_singleton is None:
        _client_singleton = GeminiCompatClient()
    return _client_singleton
