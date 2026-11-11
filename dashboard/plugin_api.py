"""Desktop and dashboard backend for Talaria, mounted at /api/plugins/talaria/.

Read-only. It lists what ``talaria_build`` and ``talaria_sign`` stored in the artifact
library so the Shortcut Bench page can show it. No route here builds, signs, uploads,
deletes or reads a file outside the library.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from fastapi import APIRouter

_LIBRARY_FILE = Path(__file__).resolve().parent.parent / "talaria" / "library.py"

router = APIRouter()

MAX_ITEMS = 200


def _rows() -> dict:
    # library.py has no dependency on the rest of the engine, so it is loaded by file path:
    # the gateway's sys.path is left alone and nothing else of the plugin is imported here.
    spec = importlib.util.spec_from_file_location("_talaria_library_readonly", _LIBRARY_FILE)
    library = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(library)

    rows = library.listing(MAX_ITEMS)
    items = [
        {
            "id": row.get("id"),
            "name": row.get("name"),
            "signed": bool(row.get("signed")),
            "actions": row.get("actions") if isinstance(row.get("actions"), int) else 0,
            "sha256": row.get("sha256"),
            "bytes": row.get("bytes"),
            "at": row.get("created_at"),
        }
        for row in rows
    ]
    return {"ok": True, "home": str(library.home()), "count": len(items), "items": items}


@router.get("/items")
def items() -> dict:
    # A plain ``def`` handler runs in a worker thread, so the directory scan never blocks
    # the gateway event loop.
    try:
        return _rows()
    except Exception as exc:  # noqa: BLE001 - the page shows the reason instead of a bare 500
        return {"ok": False, "count": 0, "items": [], "message": f"{type(exc).__name__}: {exc}"}
