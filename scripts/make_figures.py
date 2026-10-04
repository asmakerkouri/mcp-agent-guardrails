"""README figures: trace of the red-team demo and red-team benchmark results."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "images"
COLORS = {"ok": "#2EA44F", "flagged": "#F0A500", "redacted": "#8250DF", "denied": "#E5534B",
          "approved": "#1E90FF", "ask": "#1E90FF"}


def trace_figure() -> None:
    spans = [json.loads(line) for line in (ROOT / "output" / "trace.jsonl").read_text().splitlines()]
    rows = []
    for s in spans:
        if s["kind"] == "llm":
            continue
        if s["kind"] == "policy" and s["status"] == "ok":
            continue  # allowed calls are shown by their tool span
        args = s["detail"].get("args", {})
        target = args.get("path") or args.get("url", "")
        status = "redacted" if s["kind"] == "tool" and s["detail"].get("redacted") else s["status"]
        if s["kind"] == "policy" and status == "ask":
            continue
        note = {"denied": s["detail"].get("reason", "refused"),
                "flagged": "prompt injection detected, output wrapped as untrusted",
                "redacted": "secret redacted: " + ", ".join(s["detail"].get("redacted", [])),
                "approved": "human approval requested and granted",
                "ok": "allowed"}.get(status, "")
        if s["kind"] == "tool" and status == "ok" and s["name"] == "write_file":
            continue
        call = f"{s['name']}({target})"
        rows.append((call if len(call) <= 46 else call[:43] + "…)", status, note))
    fig, ax = plt.subplots(figsize=(11, 0.48 * len(rows) + 1.1), dpi=120)
    ax.set_xlim(0, 10)
    ax.set_ylim(-0.6, len(rows))
    ax.axis("off")
    for i, (call, status, note) in enumerate(reversed(rows)):
        ax.add_patch(FancyBboxPatch((0.05, i - 0.3), 1.35, 0.6, boxstyle="round,pad=0.02,rounding_size=0.12",
                                    color=COLORS[status]))
        ax.text(0.72, i, status.upper(), ha="center", va="center", color="white", fontsize=8.5, fontweight="bold")
        ax.text(1.6, i, call, va="center", fontsize=9.5, family="monospace")
        ax.text(5.9, i, note, va="center", fontsize=9, color="#444")
        ax.text(9.95, i, f"#{len(rows) - i}", va="center", ha="right", fontsize=8, color="#999")
    ax.set_title("Trace of the red-team demo: a model hijacked by a prompt injection hidden in notes/meeting.md",
                 loc="left", fontsize=11)
    fig.tight_layout()
    fig.savefig(OUT / "trace.png")
    plt.close(fig)


def redteam_figure() -> None:
    r = json.loads((ROOT / "eval" / "results" / "redteam.json").read_text())
    cats = list(r["policy"])
    fig, ax = plt.subplots(figsize=(9, 3.6), dpi=120)
    for i, c in enumerate(cats):
        v = r["policy"][c]
        color = COLORS["approved"] if c == "legitimate" else COLORS["denied"]
        ax.barh(i, v["cases"], color="#E1E4E8", height=0.6)
        ax.barh(i, v["correct"], color=color, height=0.6)
        ax.text(v["correct"] + 0.15, i, f"{v['correct']}/{v['cases']}", va="center", fontweight="bold")
    ax.set_yticks(range(len(cats)), [("legitimate calls kept working" if c == "legitimate" else c + " blocked")
                                     for c in cats])
    ax.invert_yaxis()
    t = r["policy_total"]
    ax.set_title(f"Guardrail policy on {t['cases']} red-team and legitimate tool calls: {t['correct']}/{t['cases']} "
                 "correct decisions", loc="left", fontsize=10.5)
    ax.spines[["top", "right"]].set_visible(False)
    ax.set_xlabel("tool calls")
    fig.tight_layout()
    fig.savefig(OUT / "redteam.png")
    plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    trace_figure()
    redteam_figure()
    print("figures written to", OUT)
