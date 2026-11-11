"""Filesystem layout for the Talaria artifact library.

Working state lives under TALARIA_HOME (default: Hermes's per-plugin data directory,
<hermes home>/plugin-data/talaria). The only other place written is the delivery folder,
<hermes home>/cache/documents/talaria, where the copy handed to the user goes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

_SLUG_RE = re.compile(r"[^a-z0-9]+")
_ID_RE = re.compile(r"^s?[0-9a-f]{15,16}$")


PLUGIN_NAME = "talaria"

#: What a tool tells the model next to a deliverable file.
DELIVER_HOW = (
    "To hand the file to the user, write the media_tag value alone on its own line in your "
    "reply, outside any code block. In a terminal session give the plain path instead."
)


def hermes_home() -> Path:
    """The active Hermes home. Inside Hermes it follows the active profile."""
    try:
        from plugins.plugin_storage import plugin_data_dir  # documented plugin storage helper

        # plugin_data_dir() is <hermes home>/plugin-data/<name>
        return Path(plugin_data_dir(PLUGIN_NAME)).parent.parent
    except Exception:  # noqa: BLE001 - outside Hermes (tests, a bare checkout)
        explicit = os.environ.get("HERMES_HOME")
        return Path(explicit).expanduser() if explicit else Path.home() / ".hermes"


def home() -> Path:
    """Root of the artifact library.

    $TALARIA_HOME when set, else Hermes's own per-plugin data directory
    (<hermes home>/plugin-data/talaria), which survives `hermes plugins update` and
    `remove` and follows the active profile.
    """
    explicit = os.environ.get("TALARIA_HOME")
    if explicit:
        return Path(explicit).expanduser().resolve()
    try:
        from plugins.plugin_storage import plugin_data_dir  # documented plugin storage helper

        return Path(plugin_data_dir(PLUGIN_NAME)).resolve()
    except Exception:  # noqa: BLE001 - outside Hermes
        return (hermes_home() / "plugin-data" / PLUGIN_NAME).resolve()


def bin_dir() -> Path:
    """Where `talaria_setup` installs the pinned compiler."""
    d = home() / "bin"
    d.mkdir(parents=True, exist_ok=True)
    return d


def deliver_dir() -> Path:
    """Where a file handed to the user is written.

    Hermes attaches a `MEDIA:` file only from a path it trusts. <hermes home>/cache/documents
    is trusted in every delivery mode, including strict mode and a home that sits under a
    denied prefix such as /root, so the copy the user receives always goes there.
    $TALARIA_DELIVER_DIR overrides it (tests, or an operator root listed in
    HERMES_MEDIA_ALLOW_DIRS).
    """
    explicit = os.environ.get("TALARIA_DELIVER_DIR")
    d = Path(explicit).expanduser() if explicit else hermes_home() / "cache" / "documents" / PLUGIN_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d.resolve()


def artifacts_dir() -> Path:
    d = home() / "artifacts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def jobs_dir() -> Path:
    d = home() / "jobs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def new_jobdir(name: str) -> Path:
    """A fresh, empty job directory.  Never reused, never world-writable."""
    slug = slugify(name) or "shortcut"
    stamp = time.strftime("%Y%m%dT%H%M%S")
    d = jobs_dir() / f"{slug}-{stamp}-{os.urandom(4).hex()}"
    d.mkdir(parents=True, exist_ok=False)
    os.chmod(d, 0o700)
    return d


def slugify(name: str) -> str:
    """Filesystem/argv safe base name.  No dots: Cherri truncates at the first one."""
    s = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-")
    return s[:48]


def check_id(artifact_id: str) -> str:
    if not isinstance(artifact_id, str) or not _ID_RE.match(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    return artifact_id


def artifact_path(artifact_id: str) -> Path:
    return artifacts_dir() / f"{check_id(artifact_id)}.shortcut"


def meta_path(artifact_id: str) -> Path:
    return artifacts_dir() / f"{check_id(artifact_id)}.json"


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def sha256_file(path: str | os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_meta(artifact_id: str, meta: dict) -> Path:
    p = meta_path(artifact_id)
    p.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(p, 0o600)
    return p


def read_meta(artifact_id: str) -> dict:
    p = meta_path(artifact_id)
    if not p.exists():
        raise FileNotFoundError(f"unknown artifact: {artifact_id}")
    return json.loads(p.read_text(encoding="utf-8"))


def listing(limit: int = 20) -> list[dict]:
    """Newest-first summary of stored artifacts.  Unreadable entries are skipped, never fatal."""
    out: list[dict] = []
    try:
        rows = sorted(artifacts_dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return out
    for path in rows:
        try:
            m = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        files = m.get("files") if isinstance(m.get("files"), dict) else {}
        primary = files.get("signed") or files.get("unsigned") or {}
        if not primary and m.get("sha256"):
            primary = {"sha256": m.get("sha256"), "bytes": m.get("bytes")}
        out.append({
            "id": path.stem,
            "name": m.get("name") or path.stem,
            "created_at": m.get("created_at") or m.get("built_at"),
            "signed": bool(m.get("signed") or files.get("signed")),
            "actions": m.get("action_count", m.get("actions")),
            "sha256": primary.get("sha256"),
            "bytes": primary.get("bytes"),
        })
        if len(out) >= max(1, int(limit or 20)):
            break
    return out


def publish(artifact_id: str) -> dict:
    """Copy a stored artifact into the delivery folder under a clean file name.

    Returns the path Hermes can attach and the ready-made `MEDIA:` line. The file name has
    no space: the gateway reads an unknown extension up to the first whitespace.
    """
    src = artifact_path(artifact_id)
    if not src.is_file():
        raise FileNotFoundError(f"unknown artifact: {artifact_id}")
    try:
        meta = read_meta(artifact_id)
    except (FileNotFoundError, ValueError):
        meta = {}
    base = slugify(str(meta.get("name") or "")) or "shortcut"
    dest = deliver_dir() / f"{base}.shortcut"
    blob = src.read_bytes()
    tmp = dest.with_name(f".{dest.name}.{os.urandom(4).hex()}.tmp")
    tmp.write_bytes(blob)
    os.chmod(tmp, 0o644)
    os.replace(tmp, dest)
    return {
        "path": str(dest),
        "file_name": dest.name,
        "bytes": len(blob),
        "sha256": sha256_bytes(blob),
        "media_tag": f"MEDIA:{dest}",
    }


def delete(artifact_id: str) -> bool:
    """Remove one artifact (file plus metadata).  Returns False when it was already gone."""
    removed = False
    for path in (artifact_path(artifact_id), meta_path(artifact_id)):
        if path.exists():
            path.unlink()
            removed = True
    return removed

