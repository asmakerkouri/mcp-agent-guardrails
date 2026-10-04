"""Minimal tracing: one span per LLM call, policy decision and tool call, saved as JSONL."""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Span:
    kind: str  # llm | policy | tool | approval
    name: str
    start: float
    end: float = 0.0
    status: str = "ok"  # ok | denied | error | flagged | redacted
    detail: dict = field(default_factory=dict)

    @property
    def ms(self) -> float:
        return 1000 * (self.end - self.start)


class Tracer:
    def __init__(self) -> None:
        self.t0 = time.perf_counter()
        self.spans: list[Span] = []

    @contextmanager
    def span(self, kind: str, name: str, **detail):
        s = Span(kind, name, time.perf_counter() - self.t0, detail=detail)
        self.spans.append(s)
        try:
            yield s
        except Exception as e:
            s.status, s.detail["error"] = "error", str(e)
            raise
        finally:
            s.end = time.perf_counter() - self.t0

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(json.dumps(asdict(s) | {"ms": round(s.ms, 2)}) for s in self.spans) + "\n")
        return path

    def summary(self) -> dict:
        tools = [s for s in self.spans if s.kind == "tool"]
        return {"llm_calls": sum(s.kind == "llm" for s in self.spans), "tool_calls": len(tools),
                "denied": sum(s.status == "denied" for s in self.spans if s.kind == "policy"),
                "flagged_outputs": sum(s.status == "flagged" for s in tools),
                "redacted_outputs": sum("redacted" in s.detail for s in tools),
                "total_ms": round(1000 * max((s.end for s in self.spans), default=0), 1)}
