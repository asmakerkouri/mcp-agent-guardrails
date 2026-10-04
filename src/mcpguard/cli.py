"""Run the guarded agent with a real LLM on a folder.

    python -m mcpguard.cli "Summarise the notes into report.md" --workspace demo_workspace \
        --llm qwen2.5:7b --base-url http://localhost:11434/v1
"""

from __future__ import annotations

import argparse
import asyncio
import json

from .agent import GuardedAgent, workspace_server
from .llm import OpenAICompatible
from .policy import Policy


def ask_human(tool: str, args: dict) -> bool:
    preview = json.dumps(args, ensure_ascii=False)[:300]
    return input(f"\nThe agent wants to call {tool}({preview}). Allow? [y/N] ").strip().lower() == "y"


async def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("task")
    p.add_argument("--workspace", default="demo_workspace")
    p.add_argument("--policy", default="policy.yaml")
    p.add_argument("--llm", default="qwen2.5:7b")
    p.add_argument("--base-url", default=None)
    p.add_argument("--trace", default="output/trace.jsonl")
    a = p.parse_args()
    async with GuardedAgent(OpenAICompatible(a.llm, a.base_url), Policy.load(a.policy),
                            [workspace_server(a.workspace)], approver=ask_human) as agent:
        res = await agent.run(a.task)
    print("\n" + res.answer)
    print(json.dumps(res.tracer.summary(), indent=2))
    print("trace:", res.tracer.save(a.trace))


if __name__ == "__main__":
    asyncio.run(main())
