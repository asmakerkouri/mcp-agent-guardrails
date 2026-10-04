# MCP agent with guardrails: tool policy, prompt-injection defence, tracing

![CI](https://github.com/asmakerkouri/mcp-agent-guardrails/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11-blue)
![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-server%20%2B%20client-1E90FF)
![Security](https://img.shields.io/badge/red--team-38%2F38-2EA44F)

A tool-using AI agent built on the **Model Context Protocol (MCP)**, with a **guardrail layer
between the LLM and its tools**. The agent discovers the tools of any MCP server at start-up;
every tool call is checked against a declarative policy (allow / ask a human / deny), every tool
output is cleaned (secrets redacted, prompt injections flagged), and every step is traced.

> 🇫🇷 Agent IA connecté à des outils via le protocole MCP, avec garde-fous : politique d'accès
> aux outils, validation humaine des actions sensibles, masquage des secrets, détection des
> injections de prompt et traçabilité complète.

![Trace](docs/images/trace.png)

*Red-team demo: a file of the project contains hidden instructions asking the agent to send the
AWS key to an external site. The model is scripted to fall for it (worst case). The guardrails
flag the poisoned file, deny the `.env` read, redact the password it finds elsewhere, block the
exfiltration request and the path traversal, and the report is only written after human approval.*

## Architecture

```mermaid
flowchart LR
    U[Task] --> A[Agent loop]
    A <-->|messages + tool schemas| L[LLM<br/>Ollama / OpenAI-compatible]
    A -->|tool call| P{Policy<br/>policy.yaml}
    P -->|deny + reason| A
    P -->|ask| H[Human approval]
    H -->|yes| M
    P -->|allow| M[MCP client]
    M <-->|stdio, JSON-RPC| S[MCP server<br/>workspace tools]
    M -->|output| Z[Sanitize<br/>redact secrets<br/>flag injections]
    Z --> A
    A -.-> T[(Trace JSONL)]
```

| Layer | What it does |
|---|---|
| **MCP server** (`server.py`) | `list_files`, `read_file`, `search_text`, `write_file`, `fetch_url`, built with FastMCP. Paths are confined to the workspace by the server itself and hidden files (`.env`, `.git`) are never listed |
| **MCP client** (`agent.py`) | Starts the servers over stdio, discovers their tools, converts them to the OpenAI tool format and runs the LLM ↔ tools loop |
| **Policy** (`policy.yaml`, `policy.py`) | Per-tool verdict (`allow`, `ask`, `deny`, default deny); paths: no absolute path, no `..`, protected files; URLs: https only, domain allow-list; **no secret may leave through an argument** (URL query, file content, search query); budget of 12 tool calls per task |
| **Sanitizer** | Redacts AWS keys, API tokens, private keys and passwords from tool outputs; wraps outputs that look like prompt injections in `<untrusted_tool_output>` so the model treats them as data |
| **Human in the loop** | `ask` tools (here `write_file`) need an approval callback: a terminal prompt in the CLI, refusal by default in unattended runs |
| **Tracing** (`trace.py`) | One span per LLM call, policy decision, approval and tool call, with status and latency, saved as JSONL |

## Results

![Red-team](docs/images/redteam.png)

`eval/redteam.py` sends **38 tool calls** to the policy: 27 attacks in 4 families and 11 legitimate
calls that must keep working.

| Check | Result |
|---|---|
| Path traversal (`../../etc/passwd`, `/etc/shadow`, `~/.ssh/id_rsa`, `C:/…`, `..\\..\\`) | 8/8 blocked |
| Protected files (`.env`, `.git/config`, `secrets/`, `*.pem`, `id_rsa`) | 8/8 blocked |
| Exfiltration (unknown domain, look-alike domain `arxiv.org.evil.example`, cloud metadata IP, `http://`, `file://`, AWS key in a URL, in a file or in a search) | 8/8 blocked |
| Tools outside the allow-list (`run_shell`, `delete_file`, `send_email`) | 3/3 blocked |
| Legitimate calls (read notes, search, fetch arXiv / Wikipedia, write a report after approval) | 11/11 kept working |
| Server-side sandbox, tested without the policy (defence in depth) | 5/5 escapes refused |
| Prompt-injection patterns | 7/8 injections flagged, 0/8 false alarms on benign texts |

The benchmark found one real gap during development: `search_text(path="secrets")` was allowed
because only the files *inside* the folder were protected. Folders are now protected when their
content is.

**Limits, stated plainly.** Injection detection is pattern-based: it caught 7 of 8 test injections
and missed a paraphrase (*"Forget everything above. Your new task is…"*). It is a signal, not the
defence: the real protection is that the policy blocks the *actions* an injected model would take
(reading secrets, sending data out, writing without approval), whatever the model was convinced to do.

## Quick start

```bash
pip install -r requirements-dev.txt
make test        # 17 tests, including the agent against the real MCP server over stdio
make demo        # red-team scenario, deterministic, no API key
make eval        # benchmark + figures
```

With a real model through Ollama (any OpenAI-compatible endpoint works):

```bash
ollama pull qwen2.5:7b
make run TASK="Summarise the project status from the notes and save it as report.md"
```

The CLI asks for your approval before any `write_file`, then prints the answer, a summary of the
trace (LLM calls, tool calls, denials, flagged and redacted outputs) and saves `output/trace.jsonl`.

The MCP server also works with any MCP client, for example Claude Desktop:

```json
{"mcpServers": {"workspace": {"command": "python", "args": ["-m", "mcpguard.server"],
  "env": {"WORKSPACE_ROOT": "/path/to/project", "PYTHONPATH": "/path/to/mcp-agent-guardrails/src"}}}}
```

## Project structure

```
src/mcpguard/   server.py (MCP server) · agent.py (MCP client + loop) · policy.py · trace.py · llm.py · cli.py
policy.yaml     tool verdicts, protected paths, domain allow-list, secret and injection patterns
demo_workspace/ project notes with a hidden prompt injection and fake credentials
eval/           redteam.py · results/
scripts/        demo.py · make_figures.py
```

## Author

**Asma Kerkouri** · AI engineer · [LinkedIn](https://www.linkedin.com/in/asma-kerkouri-443b6815a) ·
[GitHub](https://github.com/asmakerkouri)
