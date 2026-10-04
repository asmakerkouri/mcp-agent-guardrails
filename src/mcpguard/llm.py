"""Tool-calling LLM backends (OpenAI tool-call format).

- OpenAICompatible: Ollama, vLLM, OpenAI... (`/v1/chat/completions` with `tools`)
- Scripted: replays pre-written turns, for tests and the reproducible demo
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Protocol

import httpx


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class Reply:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLM(Protocol):
    name: str

    def chat(self, messages: list[dict], tools: list[dict]) -> Reply: ...


class OpenAICompatible:
    def __init__(self, model: str, base_url: str | None = None, api_key: str | None = None):
        self.name = model
        self.base_url = (base_url or os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")).rstrip("/")
        self.api_key = api_key or os.getenv("LLM_API_KEY", "ollama")
        self.http = httpx.Client(timeout=180)

    def chat(self, messages: list[dict], tools: list[dict]) -> Reply:
        r = self.http.post(f"{self.base_url}/chat/completions", headers={"Authorization": f"Bearer {self.api_key}"},
                           json={"model": self.name, "messages": messages, "tools": tools, "temperature": 0})
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        calls = [ToolCall(c["id"], c["function"]["name"], json.loads(c["function"]["arguments"] or "{}"))
                 for c in msg.get("tool_calls") or []]
        return Reply(msg.get("content") or "", calls)


class Scripted:
    """Each turn is either a final answer (str) or a list of (tool, arguments) calls."""

    def __init__(self, turns: list):
        self.name = "scripted"
        self.turns = list(turns)
        self.seen: list[list[dict]] = []

    def chat(self, messages: list[dict], tools: list[dict]) -> Reply:
        self.seen.append(list(messages))
        turn = self.turns.pop(0) if self.turns else "Done."
        if isinstance(turn, str):
            return Reply(turn)
        return Reply("", [ToolCall(f"call_{len(self.seen)}_{i}", n, a) for i, (n, a) in enumerate(turn)])
