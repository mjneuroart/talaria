"""Searchable Catalogue of the Cherri actions this plugin can compile.

The catalogue ships with the plugin as JSON, generated from the compiler's own documentation, so
the model looks an action up instead of inventing one. Nothing here executes code.

Public surface:
    catalogue()                 -> the whole dict
    search(query, limit, family) -> trimmed entries, best match first
    get(name)                   -> one entry or None
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "actions.json")


class CatalogueMissing(RuntimeError):
    """The shipped catalogue file is absent or unreadable."""


@lru_cache(maxsize=1)
def catalogue() -> dict:
    if not os.path.isfile(DATA):
        raise CatalogueMissing(
            f"action catalogue not found at {DATA}. Reinstall the plugin; the file ships with it."
        )
    with open(DATA, encoding="utf-8") as handle:
        return json.load(handle)


def _score(entry: dict, needle: str) -> int:
    name = entry.get("name", "").lower()
    title = entry.get("title", "").lower()
    summary = entry.get("summary", "").lower()
    if name == needle:
        return 100
    if name.startswith(needle):
        return 80
    if needle in name:
        return 60
    if needle in title:
        return 40
    if needle in summary:
        return 20
    return 0


def search(query: str = "", limit: int = 12, family: str | None = None) -> list[dict]:
    """Return catalogue entries matching ``query``, trimmed for a tool result.

    Multi-word queries are scored token by token, so "http request" finds jsonRequest instead of
    returning nothing for want of a literal phrase match.
    """
    raw = (query or "").strip().lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", raw) if t]
    limit = max(1, min(int(limit or 12), 50))
    items = catalogue()["actions"]
    if family:
        wanted = family.strip().lower()
        items = [i for i in items if i["family"] == wanted or (wanted == "core" and i["family"] == "basic")]
    if tokens:
        scored = []
        for item in items:
            total = 0
            hits = 0
            for token in tokens:
                best = max(_score(item, token), _score_token(item, token))
                if best:
                    hits += 1
                    # Longer tokens are more specific: "clipboard" must outrank "read".
                    total += best * max(1, len(token) - 2)
            if hits:
                # A phrase match still wins; otherwise reward covering more of the query.
                scored.append((total + 25 * hits, item))
        scored.sort(key=lambda pair: (-pair[0], pair[1]["name"]))
        items = [item for _, item in scored]
    out = []
    for item in items[:limit]:
        out.append({
            "name": item["name"],
            "family": item["family"],
            "signature": item["signature"],
            "summary": item.get("summary") or "",
            "include": item.get("include"),
            "params": item.get("params") or [],
        })
    return out


def _score_token(entry: dict, token: str) -> int:
    """Partial credit for a token inside a compound name (jsonRequest contains 'request')."""
    name = entry.get("name", "").lower()
    summary = entry.get("summary", "").lower()
    if token in name:
        return 55
    if len(token) > 3 and token in summary:
        return 15
    return 0



def get(name: str) -> dict | None:
    target = (name or "").strip().lower()
    for item in catalogue()["actions"]:
        if item["name"].lower() == target:
            return item
    return None


def families() -> list[str]:
    return sorted({item["family"] for item in catalogue()["actions"]})
