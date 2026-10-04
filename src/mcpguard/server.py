"""MCP server "workspace": file and web tools for an agent, exposed over the Model Context Protocol.

Run:  WORKSPACE_ROOT=demo_workspace python -m mcpguard.server     (stdio transport)

The server confines every path to WORKSPACE_ROOT by itself (defence in depth): even a client
without the guardrail layer cannot read /etc/passwd or ../../secrets through it.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

ROOT = Path(os.getenv("WORKSPACE_ROOT", "workspace")).resolve()
MAX_BYTES = 20_000

mcp = FastMCP("workspace", instructions="File tools confined to one project folder, plus HTTP GET.",
              log_level="WARNING")


def visible_files(base: Path):
    """Files under base, skipping hidden files and folders (.env, .git, .ssh...)."""
    for p in sorted(base.rglob("*")):
        if p.is_file() and not any(part.startswith(".") for part in p.relative_to(ROOT).parts):
            yield p


def safe_path(path: str) -> Path:
    p = (ROOT / path).resolve()
    if p != ROOT and ROOT not in p.parents:
        raise ValueError(f"path outside the workspace: {path}")
    return p


@mcp.tool()
def list_files(path: str = ".") -> list[str]:
    """List the files of a folder of the workspace (recursive, relative paths, hidden files skipped)."""
    base = safe_path(path)
    return [str(p.relative_to(ROOT)) for p in visible_files(base)]


@mcp.tool()
def read_file(path: str) -> str:
    """Read a text file of the workspace (first 20 kB)."""
    return safe_path(path).read_text(errors="replace")[:MAX_BYTES]


@mcp.tool()
def search_text(query: str, path: str = ".") -> list[str]:
    """Case-insensitive search of a text in the workspace files. Returns 'file:line: text' matches."""
    hits = []
    for f in visible_files(safe_path(path)):
        for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
            if query.lower() in line.lower():
                hits.append(f"{f.relative_to(ROOT)}:{i}: {line.strip()[:200]}")
    return hits[:50]


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Create or overwrite a text file of the workspace."""
    p = safe_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return f"wrote {len(content)} characters to {p.relative_to(ROOT)}"


@mcp.tool()
def fetch_url(url: str) -> str:
    """HTTP GET a web page and return its text (first 20 kB)."""
    r = httpx.get(url, timeout=15, follow_redirects=True)
    r.raise_for_status()
    return r.text[:MAX_BYTES]


if __name__ == "__main__":
    mcp.run()
