"""Compile Cherri source to an unsigned .shortcut, isolated, and prove the result.

Contract (SPEC.md 1, 3, 4, 5):
  * cherri is ALWAYS invoked with --skip-sign --no-ansi, never -o, never
    --derive-uuids, never --debug / --open / --import / --refs / --install;
  * the source file is the first argument and lives in a fresh job dir;
  * rc=0 is not proof: the produced file is re-read and the build fails when the
    plist is unreadable, holds zero actions, contains only no-op actions, or
    leaves a control-flow block open (measured failure modes of this compiler).
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from . import aea, library, sandbox

MAX_SOURCE_BYTES = 100_000
ALLOWED_INCLUDES = {
    "a11y", "calendar", "contacts", "crypto", "device", "documents", "dropbox",
    "images", "intelligence", "location", "mac", "math", "media", "music",
    "network", "pdf", "photos", "settings", "sharing", "shortcuts", "storage",
    "text", "translation", "web",
}

#: The exact form the compiler accepts for a category include: after `#include` it
#: skips one character, then needs a quote, then the path, then end of line.
_INCLUDE_OK = re.compile(r"[ \t]'actions/([a-z0-9]+)'[ \t]*(?:$|\r?\n)", re.MULTILINE)

#: Actions that produce nothing on the device.
NOOP_ACTIONS = {"is.workflow.actions.comment", "is.workflow.actions.nothing"}

#: Actions that open a control-flow block in the plist (WFControlFlowMode 0/1/2).
BLOCK_ACTIONS = {
    "is.workflow.actions.conditional",
    "is.workflow.actions.repeat.count",
    "is.workflow.actions.repeat.each",
    "is.workflow.actions.choosefrommenu",
}


class BuildError(RuntimeError):
    """The source did not produce a usable shortcut."""

    def __init__(self, message: str, diagnostics: dict | None = None):
        super().__init__(message)
        self.diagnostics = diagnostics or {}


def _iter_unquoted(source: str):
    """Yield (index, char) for characters outside string literals and comments."""
    i, n = 0, len(source)
    quote = ""
    while i < n:
        ch = source[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            i += 2
            while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                i += 1
            i += 2
            continue
        yield i, ch
        i += 1


def _balance_findings(source: str) -> list[dict]:
    """Catch the truncation shapes that compile green with steps missing.

    A source whose braces or parentheses do not balance is almost always a file
    that was cut in half or edited badly; the compiler accepts several of those
    and silently drops the rest of the workflow.
    """
    findings: list[dict] = []
    if source.count("/*") != source.count("*/"):
        findings.append({"rule": "unbalanced-comment", "why": "a /* block is never closed"})
    for opener, closer, label in (("{", "}", "brace"), ("(", ")", "parenthesis")):
        depth = 0
        for index, ch in _iter_unquoted(source):
            if ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth < 0:
                    findings.append({
                        "rule": f"unbalanced-{label}",
                        "line": source.count("\n", 0, index) + 1,
                        "why": f"a closing {closer} has no matching {opener}",
                    })
                    break
        else:
            if depth > 0:
                findings.append({
                    "rule": f"unbalanced-{label}",
                    "why": f"{depth} unclosed {opener} at end of source",
                })
    return findings


def prefilter(source: str) -> list[dict]:
    """Reject the source constructs that touch the host at compile time.

    Measured (facts/CHERRI.md Q5): embedFile reads any file, #include reads any
    *.cherri and is an existence oracle, #import opens a SQLite DB under $HOME,
    #define name writes wherever the text points.

    The compiler skips exactly ONE character after `#define` and after `#include`,
    so a filter that assumes whitespace is bypassed by `#defineXname` or
    `#includeX'/etc/passwd'`. This one mirrors the grammar: it looks at every
    occurrence and only accepts the single form a category include can take.
    The sandbox is the second barrier; this is the first.
    """
    findings: list[dict] = []
    if re.search(r"embedfile", source, re.IGNORECASE):
        findings.append({"rule": "embedFile", "why": "reads an arbitrary host file into the shortcut"})
    if re.search(r"#import", source):
        findings.append({"rule": "#import", "why": "opens the Shortcuts ToolKit database under $HOME"})
    if re.search(r"#define[\s\S]name", source):
        findings.append({"rule": "#define name", "why": "writes the output file at an attacker-chosen path"})
    for match in re.finditer(r"#include", source):
        ok = _INCLUDE_OK.match(source, match.end())
        if not ok or ok.group(1) not in ALLOWED_INCLUDES:
            line_no = source.count("\n", 0, match.start()) + 1
            got = source[match.end():source.find("\n", match.end()) if "\n" in source[match.end():] else len(source)]
            findings.append({
                "rule": "#include",
                "line": line_no,
                "why": (
                    "only \"#include 'actions/<category>'\" with a known category is allowed, "
                    f"got {got.strip()[:60]!r}"
                ),
            })
    findings.extend(_balance_findings(source))
    return findings


def _cherri_args(source_name: str) -> list[str]:
    # Order matters: the source file must be the FIRST argument.
    return [source_name, "--skip-sign", "--no-ansi"]


def read_actions(path: str | os.PathLike) -> tuple[dict, list[dict]]:
    """Parse an UNSIGNED shortcut (plain XML plist) -> (plist, actions)."""
    import plistlib

    blob = Path(path).read_bytes()
    if blob[:4] == aea.MAGIC:
        raise BuildError("artifact is AEA-signed, not the unsigned plist this builder produces")
    try:
        plist = plistlib.loads(blob)
    except Exception as exc:
        raise BuildError(f"produced file is not a readable plist: {type(exc).__name__}: {exc}") from exc
    if not isinstance(plist, dict):
        raise BuildError("produced plist is not a dictionary")
    actions = plist.get("WFWorkflowActions") or []
    if not isinstance(actions, list):
        raise BuildError("WFWorkflowActions is not a list")
    return plist, actions


def structural_problems(actions: list[dict]) -> list[str]:
    """The checks that catch a green compile of a broken shortcut."""
    problems: list[str] = []
    identifiers = [
        a.get("WFWorkflowActionIdentifier") if isinstance(a, dict) else None for a in actions
    ]
    if identifiers and all(i in NOOP_ACTIONS for i in identifiers):
        problems.append("the shortcut contains only no-op actions (comment/nothing)")

    open_groups: dict[str, int] = {}
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            continue
        if action.get("WFWorkflowActionIdentifier") not in BLOCK_ACTIONS:
            continue
        params = action.get("WFWorkflowActionParameters") or {}
        group = params.get("GroupingIdentifier")
        mode = params.get("WFControlFlowMode")
        if mode == 0:
            if group in open_groups:
                problems.append(f"block {group} opened twice at action {index} (else-if shape)")
            open_groups[group] = index
        elif mode == 2:
            if open_groups.pop(group, None) is None:
                problems.append(f"block {group} closed at action {index} without an opening")
    for group, index in open_groups.items():
        problems.append(f"block {group} opened at action {index} is never closed")
    return problems


def _inventory(actions: list[dict]) -> list[dict]:
    out = []
    for idx, action in enumerate(actions):
        ident = action.get("WFWorkflowActionIdentifier", "<missing>") if isinstance(action, dict) else "<not-a-dict>"
        params = action.get("WFWorkflowActionParameters", {}) if isinstance(action, dict) else {}
        out.append({"index": idx, "identifier": ident, "param_keys": sorted(params.keys()) if isinstance(params, dict) else []})
    return out


def build(source_text: str, name: str, timeout: float = 30.0) -> dict:
    """Compile source outside the network and return measured artifact facts."""
    if not isinstance(source_text, str) or not source_text.strip():
        raise BuildError("source is empty")
    if len(source_text.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise BuildError(f"source exceeds {MAX_SOURCE_BYTES} bytes")

    findings = prefilter(source_text)
    if findings:
        detail = "; ".join(
            (f"line {f['line']}: " if f.get("line") else "") + f"{f['rule']} ({f['why']})"
            for f in findings
        )
        raise BuildError(
            "source rejected before compiling: " + detail,
            {"prefilter": findings},
        )

    slug = library.slugify(name) or "shortcut"
    jobdir = library.new_jobdir(slug)
    try:
        source_name = f"{slug}.cherri"
        (jobdir / source_name).write_text(source_text, encoding="utf-8")

        result = sandbox.run(_cherri_args(source_name), jobdir, allow_network=False, timeout=timeout)
        diag = {
            "argv": result["argv"],
            "rc": result["rc"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "elapsed": result["elapsed"],
            "isolation": result["isolation"],
            "no_isolation": result["no_isolation"],
        }

        if result["rc"] != 0:
            raise BuildError(
                f"compiler exited {result['rc']}: {(result['stdout'] or result['stderr']).strip()[:800]}",
                diag,
            )

        produced = sorted(jobdir.glob("*_unsigned.shortcut"))
        if not produced:
            raise BuildError("compiler exited 0 but produced no *_unsigned.shortcut", diag)
        unsigned = produced[0]

        plist, actions = read_actions(unsigned)
        if not actions:
            raise BuildError(
                "compiler exited 0 but the plist contains zero actions "
                "(silent failure: rc=0 is not proof)",
                diag,
            )
        problems = structural_problems(actions)
        if problems:
            raise BuildError(
                "compiler exited 0 but the shortcut is malformed: " + "; ".join(problems),
                diag,
            )

        blob = unsigned.read_bytes()
        sha = library.sha256_bytes(blob)
        artifact_id = sha[:16]
        dest = library.artifact_path(artifact_id)
        shutil.copyfile(unsigned, dest)
        os.chmod(dest, 0o600)
    finally:
        # The job dir holds a copy of the source; nothing downstream reads it again.
        shutil.rmtree(jobdir, ignore_errors=True)

    diag["path"] = str(dest)
    meta = {
        "artifact_id": artifact_id,
        "name": slug,
        "display_name": name,
        "source_name": f"{slug}.cherri",
        "source": source_text,
        "sha256": sha,
        "bytes": len(blob),
        "actions": len(actions),
        "signed": False,
        "built_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S%z"),
        "diagnostics": diag,
    }
    library.write_meta(artifact_id, meta)

    return {
        "artifact_id": artifact_id,
        "name": name,
        "signed": False,
        "built_at": meta["built_at"],
        "path": str(dest),
        "sha256": sha,
        "bytes": len(blob),
        "actions": len(actions),
        "inventory": _inventory(actions),
        "diagnostics": diag,
        "metadata_keys": sorted(k for k in plist.keys()),
    }
