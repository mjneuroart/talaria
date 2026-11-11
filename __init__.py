"""talaria — iOS Shortcuts for Hermes: author, build, sign, audit.

This file is the registration entry point only. The engine lives in the
``talaria/`` package beside it (``env.py``, ``compile.py``, ``sign.py``,
``aea.py``, ``inspect.py``, ``lzfse.py``) and none of it is imported at module
import time: ``hermes plugins validate`` and ``hermes plugins doctor --ci``
import this file and run ``register()`` on machines that do not have the Cherri
compiler (the common case for a reviewer), so every path here degrades to a
clear JSON message instead of a traceback.

Engine contract expected from ``talaria/`` (first attribute that exists wins,
and keywords are filtered against the callee's signature, so a module that
takes fewer arguments still works)::

    env.status()                                    -> dict
    env.actions(query="", limit=20)                 -> dict
    compile.build(source=None, path=None, name="")  -> dict
    sign.sign(artifact_id="", consent=True)         -> dict
    inspect.inspect(path="")                        -> dict
    inspect.inspect_link(link="")                   -> dict
    setup.install(confirm=False)                    -> dict
    library.listing() / read_meta() / publish()     -> dict

Every handler returns a JSON string (`str`), never raises: the Hermes registry
turns an escaping exception into a bare error, and the point of these tools is
to tell the model what to do next.
"""

from __future__ import annotations

import importlib
import inspect
import json
import sys
from pathlib import Path

PLUGIN = "talaria"
SKILL_NAME = "shortcuts-authoring"

PLUGIN_DIR = Path(__file__).resolve().parent
ENGINE_DIR = PLUGIN_DIR / "talaria"
ENGINE_MODULES = ("env", "setup", "compile", "sign", "aea", "inspect", "icloud", "lzfse", "library")

# tool -> ordered candidate (module, attribute) pairs inside the talaria package
_ROUTES: dict[str, tuple[tuple[str, str], ...]] = {
    "talaria_status": (("env", "status"), ("env", "probe"), ("inspect", "status")),
    "talaria_actions": (
        ("actions", "search"),
        ("env", "actions"),
        ("inspect", "actions"),
        ("compile", "actions"),
    ),
    "talaria_build": (("compile", "build"), ("compile", "compile_source")),
    "talaria_sign": (("sign", "sign"), ("sign", "sign_artifact")),
    "talaria_inspect": (("inspect", "inspect"), ("inspect", "inspect_file"), ("aea", "inspect")),
    "talaria_inspect_link": (("inspect", "inspect_link"),),
    "talaria_setup": (("setup", "install"),),
}

_FALLBACK_REFUSAL = (
    "talaria_sign refused: consent is required in the same call. "
    "What leaves this machine when you set consent=true: the compiled shortcut, as an XML "
    "plist, containing every action, text field, URL and embedded value in the workflow, plus "
    "the shortcut name, in one HTTPS POST to https://hubsign.routinehub.services/sign "
    "(RoutineHub, a third party holding an Apple Developer certificate). Nothing else is sent. "
    "Retry with consent=true only after the user has seen what will be uploaded."
)


def _refusal_text() -> str:
    """One source of truth: the engine's own refusal string, with a static fallback."""
    try:
        return _load_engine("sign").REFUSAL
    except Exception:  # engine missing: the fallback still names the host and the payload
        return _FALLBACK_REFUSAL


def _schema(name: str, description: str, parameters: dict | None = None) -> dict:
    return {
        "name": name,
        "description": description,
        "parameters": parameters or {"type": "object", "properties": {}, "required": []},
    }


def _obj(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or []}


SCHEMAS = {
    "talaria_status": _schema(
        "talaria_status",
        "Report whether Talaria can actually work here: Cherri compiler present, pinned and "
        "its version, sandbox (bwrap) usable, decoder mode, signer reachability, artifact "
        "library path. Opens NO network connection unless probe_signer is true. Call this "
        "first. When it reports the compiler missing, call talaria_setup.",
        _obj(
            {
                "probe_signer": {
                    "type": "boolean",
                    "description": "When true, open one TCP connection to the signing host to "
                                   "report reachability. Default false: no network call.",
                },
            }
        ),
    ),
    "talaria_setup": _schema(
        "talaria_setup",
        "Install the pinned Cherri compiler (v2.4.0) that talaria_build needs, when talaria_status "
        "reports it missing. Downloads one archive from the compiler's official GitHub release, "
        "checks two sha256 checksums recorded in the plugin, and unpacks one file into the plugin "
        "data directory. Uploads nothing. Requires confirm=true: without it the tool makes no "
        "network call and returns exactly what it would download.",
        _obj(
            {
                "confirm": {
                    "type": "boolean",
                    "description": "Must be true to download. Ask the user first.",
                },
            }
        ),
    ),
    "talaria_actions": _schema(
        "talaria_actions",
        "Look up verified Cherri action signatures and their parameters from the compiled example "
        "corpus. Use it instead of guessing an action name or argument order. Returns exact "
        "signatures, the #include family an action needs, and whether a parameter takes a literal "
        "or a variable.",
        _obj(
            {
                "query": {
                    "type": "string",
                    "description": "Action name or keyword, e.g. 'alert', 'json', 'clipboard', 'date'.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of signatures to return (default 20).",
                },
            }
        ),
    ),
    "talaria_build": _schema(
        "talaria_build",
        "Compile Cherri source into an unsigned .shortcut inside a network-less sandbox. Before "
        "writing source, load the bundled skill with skill_view('talaria:shortcuts-authoring'): it "
        "holds the file shape, the verified actions and the rules that break a build. Returns the "
        "artifact id, output path, compiler diagnostics, the action inventory re-read from the "
        "produced plist, and its sha256. Never signs and never uploads. Fails when the plist is "
        "unreadable or holds zero actions even if the compiler exited 0.",
        _obj(
            {
                "source": {
                    "type": "string",
                    "description": "Cherri source text. Give this or 'path', not both.",
                },
                "path": {
                    "type": "string",
                    "description": "Absolute path to an existing .cherri file on this machine.",
                },
                "name": {
                    "type": "string",
                    "description": "Shortcut name used for the output file, e.g. 'meeting-note'.",
                },
            },
            ["name"],
        ),
    ),
    "talaria_sign": _schema(
        "talaria_sign",
        "Sign a built artifact with an Apple-issued certificate through RoutineHub HubSign, without a "
        "Mac. Requires consent=true in the same call; without it the tool refuses and states exactly "
        "what would be uploaded. Returns the signed .shortcut path, AEA header facts, certificate "
        "issuer, sha256, and a deliver block holding the MEDIA line that hands the file to the user.",
        _obj(
            {
                "artifact_id": {
                    "type": "string",
                    "description": "Artifact id returned by talaria_build or talaria_library.",
                },
                "consent": {
                    "type": "boolean",
                    "description": "Must be true. Confirms the source text may be uploaded to the signing service.",
                },
            },
            ["artifact_id", "consent"],
        ),
    ),
    "talaria_inspect": _schema(
        "talaria_inspect",
        "Audit a .shortcut before it reaches the phone, from a local path or from the public iCloud "
        "link someone shared: decode the action list (signed AEA1 or plain "
        "plist), give human action names, and report risk findings with severity (network writes, "
        "clipboard reads, file writes outside the shortcut container, URL-scheme launches, Run "
        "Shortcut recursion, health/location/contacts reads). Never executes anything.",
        _obj(
            {
                "path": {
                    "type": "string",
                    "description": "Absolute path to a .shortcut file (signed or unsigned).",
                },
                "url": {
                    "type": "string",
                    "description": "A public iCloud shortcut link, https://www.icloud.com/shortcuts/<id>. "
                                   "Talaria downloads the file from Apple and audits it; nothing is installed.",
                },
            }
        ),
    ),
    "talaria_library": _schema(
        "talaria_library",
        "List, fetch or deliver Talaria artifacts: ids, names, paths, sha256, timestamps and sign "
        "state. action=deliver returns the MEDIA line that hands a stored shortcut to the user. "
        "Nothing is stored outside the Hermes home.",
        _obj(
            {
                "action": {
                    "type": "string",
                    "enum": ["list", "get", "deliver", "save"],
                    "description": "list (default), get one artifact, deliver one (copy it where Hermes "
                                   "can attach it and return the MEDIA line), or save.",
                },
                "artifact_id": {
                    "type": "string",
                    "description": "Artifact id for action=get, deliver or save.",
                },
            },
            ["action"],
        ),
    ),
}


# ─── engine resolution ───────────────────────────────────────────────────────


def _load_engine(module_name: str):
    """Import the engine module ``talaria/<module_name>.py`` that ships beside this file.

    Inside Hermes this file is a package (``hermes_plugins.talaria``), so the engine is imported
    as its sub-package: ``sys.path`` is left alone and a plugin reload evicts the engine with it.
    A bare checkout (the test suite) has no package context; there, and only there, the plugin
    directory is put on ``sys.path``.
    """
    owner = sys.modules.get(__name__)
    if __package__ and owner is not None and hasattr(owner, "__path__"):
        return importlib.import_module(f"{__name__}.talaria.{module_name}")
    root = str(PLUGIN_DIR)
    if root not in sys.path:
        sys.path.insert(0, root)
    return importlib.import_module("talaria." + module_name)


def _resolve(tool: str):
    """Return ``(callable, error_message)`` for a tool; exactly one is None."""
    problems: list[str] = []
    for module_name, attr in _ROUTES.get(tool, ()):
        try:
            module = _load_engine(module_name)
        except Exception as exc:  # missing file, import error inside the engine, anything
            problems.append(f"talaria/{module_name}.py: {type(exc).__name__}: {exc}")
            continue
        func = getattr(module, attr, None)
        if callable(func):
            return func, ""
        problems.append(f"talaria/{module_name}.py has no callable {attr}()")
    detail = "; ".join(problems) or "no route is declared for this tool"
    return None, detail


def _engine_missing(tool: str, detail: str) -> str:
    expected = ", ".join(f"talaria/{m}.py" for m in ENGINE_MODULES)
    return json.dumps(
        {
            "ok": False,
            "tool": tool,
            "error": "talaria_engine_unavailable",
            "message": (
                f"{tool} did not run: Talaria's engine is not importable in this install. "
                "Nothing was compiled, signed, uploaded or written. "
                f"Looked in {ENGINE_DIR} for {expected}. "
                f"Detail: {detail}. "
                "Fix: reinstall with 'hermes plugins install mjneuroart/talaria', or for a source checkout "
                "confirm those modules sit beside __init__.py. The Cherri compiler is a separate "
                "optional binary: talaria_status reports whether it is present."
            ),
            "plugin_dir": str(PLUGIN_DIR),
            "engine_dir": str(ENGINE_DIR),
        },
        indent=2,
    )


def _call(tool: str, kwargs: dict, route: str = "", **ctx) -> str:
    """Resolve the engine callable, pass only the keywords it accepts, JSON out."""
    func, error = _resolve(route or tool)
    if func is None:
        return _engine_missing(tool, error)
    try:
        try:
            sig = inspect.signature(func)
        except (TypeError, ValueError):
            sig = None
        if sig is not None and not any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
        ):
            accepted = {
                name
                for name, p in sig.parameters.items()
                if p.kind
                in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
            }
            kwargs = {k: v for k, v in kwargs.items() if k in accepted}
        result = func(**kwargs)
        if isinstance(result, str):
            return result
        return json.dumps(result, indent=2, default=str)
    except TypeError as exc:
        return json.dumps(
            {
                "ok": False,
                "tool": tool,
                "error": "talaria_contract_mismatch",
                "message": (
                    f"{tool} reached the engine but the call did not fit: {exc}. "
                    "The tool arguments and the engine signature disagree; report this as a "
                    "Talaria bug rather than retrying with different arguments."
                ),
            },
            indent=2,
        )
    except Exception as exc:
        payload = {
            "ok": False,
            "tool": tool,
            "error": f"{type(exc).__name__}",
            "message": f"{tool} failed: {exc}",
        }
        detail = getattr(exc, "diagnostics", None)
        if detail:
            payload["diagnostics"] = detail
        return json.dumps(payload, indent=2)


# ─── tool handlers ───────────────────────────────────────────────────────────


def talaria_status(args: dict | None = None, **kwargs) -> str:
    args = args or {}
    return _call("talaria_status", {"probe_signer": bool(args.get("probe_signer"))}, **kwargs)


def talaria_setup(args: dict | None = None, **kwargs) -> str:
    args = args or {}
    return _call("talaria_setup", {"confirm": args.get("confirm") is True}, **kwargs)


def talaria_actions(args: dict | None = None, **kwargs) -> str:
    args = args or {}
    query = str(args.get("query") or "").strip()
    try:
        limit = int(args.get("limit") or 20)
    except (TypeError, ValueError):
        limit = 20
    raw = _call("talaria_actions", {"query": query, "limit": max(1, min(limit, 200))}, **kwargs)
    try:
        data = json.loads(raw)
    except ValueError:
        return raw
    if isinstance(data, list):
        return json.dumps(
            {"ok": True, "query": query, "count": len(data), "actions": data},
            indent=2,
            default=str,
        )
    return raw


def talaria_build(args: dict | None = None, **kwargs) -> str:
    args = args or {}
    source = args.get("source")
    path = args.get("path")
    name = str(args.get("name") or "shortcut").strip()

    text = str(source) if source else None
    if not text and path:
        candidate = Path(str(path)).expanduser()
        if not candidate.is_file():
            return json.dumps(
                {
                    "ok": False,
                    "tool": "talaria_build",
                    "error": "source_not_found",
                    "message": f"No .cherri file at {candidate}.",
                },
                indent=2,
            )
        if candidate.suffix.lower() != ".cherri":
            return json.dumps(
                {
                    "ok": False,
                    "tool": "talaria_build",
                    "error": "not_a_cherri_file",
                    "message": (
                        f"{candidate} is not a .cherri source file. Pass the source text in "
                        "'source', or point 'path' at a file whose name ends in .cherri."
                    ),
                },
                indent=2,
            )
        if candidate.stat().st_size > 100_000:
            return json.dumps(
                {
                    "ok": False,
                    "tool": "talaria_build",
                    "error": "source_too_large",
                    "message": f"{candidate} is larger than the 100000 byte source limit.",
                },
                indent=2,
            )
        try:
            text = candidate.read_text(encoding="utf-8")
        except OSError as exc:
            return json.dumps(
                {
                    "ok": False,
                    "tool": "talaria_build",
                    "error": "source_unreadable",
                    "message": f"Could not read {candidate}: {exc}",
                },
                indent=2,
            )
    if not text:
        return json.dumps(
            {
                "ok": False,
                "tool": "talaria_build",
                "error": "missing_source",
                "message": (
                    "Give 'source' (Cherri text) or 'path' (an existing .cherri file). "
                    "See the shortcuts-authoring skill for the file shape and verified actions."
                ),
            },
            indent=2,
        )
    return _call("talaria_build", {"source_text": text, "name": name}, **kwargs)


def talaria_sign(args: dict | None = None, **kwargs) -> str:
    args = args or {}
    if args.get("consent") is not True:
        return json.dumps(
            {
                "ok": False,
                "tool": "talaria_sign",
                "error": "consent_required",
                "message": _refusal_text(),
            },
            indent=2,
        )
    artifact_id = str(args.get("artifact_id") or "").strip()
    if not artifact_id:
        return json.dumps(
            {
                "ok": False,
                "tool": "talaria_sign",
                "error": "missing_artifact_id",
                "message": "Give the artifact_id returned by talaria_build.",
            },
            indent=2,
        )
    return _call("talaria_sign", {"artifact_id": artifact_id, "consent": True}, **kwargs)


def talaria_inspect(args: dict | None = None, **kwargs) -> str:
    args = args or {}
    path = str(args.get("path") or "").strip()
    url = str(args.get("url") or "").strip()
    target = url or path
    if not target:
        return json.dumps(
            {
                "ok": False,
                "tool": "talaria_inspect",
                "error": "missing_path",
                "message": (
                    "Give the absolute path of a .shortcut file, signed or unsigned, or the public "
                    "iCloud link someone shared (https://www.icloud.com/shortcuts/<id>)."
                ),
            },
            indent=2,
        )
    if target.lower().startswith(("http://", "https://")):
        # A link is fetched from Apple, never opened and never installed.
        return _call("talaria_inspect", {"link": target}, route="talaria_inspect_link", **kwargs)
    return _call("talaria_inspect", {"source": target, "path": target}, **kwargs)


def _as_json(obj) -> str:
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, indent=2, default=str)


def _library(action: str, artifact_id: str, **kwargs) -> str:
    """Library is a thin adapter over talaria/library.py primitives (list, get, save)."""
    try:
        lib = _load_engine("library")
    except Exception as exc:
        return _engine_missing("talaria_library", f"talaria/library.py: {type(exc).__name__}: {exc}")
    try:
        facade = getattr(lib, "library", None)
        if callable(facade):
            return _as_json(facade(action=action, artifact_id=artifact_id))
        limit = 20
        try:
            limit = max(1, min(int(kwargs.get("limit") or 20), 200))
        except (TypeError, ValueError):
            pass
        if action == "list":
            return _as_json({"ok": True, "home": str(lib.home()), "artifacts": lib.listing(limit)})
        if not artifact_id:
            return json.dumps(
                {
                    "ok": False,
                    "tool": "talaria_library",
                    "error": "missing_artifact_id",
                    "message": "Give artifact_id for action=get, deliver or save; action=list shows the ids.",
                },
                indent=2,
            )
        meta = lib.read_meta(artifact_id)
        path = lib.artifact_path(artifact_id)
        if action == "deliver":
            delivery = lib.publish(artifact_id)
            signed = bool(meta.get("signed"))
            handed = {
                "ok": True,
                "artifact_id": artifact_id,
                "name": meta.get("display_name") or meta.get("name"),
                "signed": signed,
                "sha256": delivery["sha256"],
                "deliver": {**delivery, "how": lib.DELIVER_HOW},
            }
            if not signed:
                handed["note"] = (
                    "This artifact is unsigned: iOS refuses to import an unsigned shortcut. "
                    "Sign it with talaria_sign before sending it to a phone."
                )
            return _as_json(handed)
        payload = {
            "ok": True,
            "home": str(lib.home()),
            "artifact": meta,
            "path": str(path),
            "exists": path.is_file(),
            "sha256": lib.sha256_file(path) if path.is_file() else None,
        }
        if action == "save":
            payload["note"] = (
                "Already persisted: talaria_build writes every artifact into the library directory, "
                "so save is a read-back of the stored record, not a copy."
            )
        return _as_json(payload)
    except FileNotFoundError as exc:
        return json.dumps(
            {
                "ok": False,
                "tool": "talaria_library",
                "error": "unknown_artifact",
                "message": f"{exc}. Use action=list to see the stored ids.",
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps(
            {
                "ok": False,
                "tool": "talaria_library",
                "error": f"{type(exc).__name__}",
                "message": f"talaria_library failed: {exc}",
            },
            indent=2,
        )


def talaria_library(args: dict | None = None, **kwargs) -> str:
    args = args or {}
    action = str(args.get("action") or "list").strip().lower()
    if action not in ("list", "get", "deliver", "save"):
        return json.dumps(
            {
                "ok": False,
                "tool": "talaria_library",
                "error": "bad_action",
                "message": "action must be one of: list, get, deliver, save.",
            },
            indent=2,
        )
    return _library(action, str(args.get("artifact_id") or "").strip(), **kwargs)


_HANDLERS = {
    "talaria_status": talaria_status,
    "talaria_setup": talaria_setup,
    "talaria_actions": talaria_actions,
    "talaria_build": talaria_build,
    "talaria_sign": talaria_sign,
    "talaria_inspect": talaria_inspect,
    "talaria_library": talaria_library,
}


def _on_pre_tool_call(tool_name: str = "", args: dict | None = None, **kwargs):
    """Ask a human before the two calls that reach the network for the user.

    Signing uploads the compiled shortcut; setup downloads the compiler. In both, the flag the
    model passes (consent=true, confirm=true) is only the first factor.

    The rule_key is per artifact, so answering "always" does not turn every future
    upload into a silent grant. Unattended runs then fail closed through Hermes's own
    approval policy instead of uploading with nobody present.
    """
    args = args or {}
    if tool_name == "talaria_setup" and args.get("confirm") is True:
        return {
            "action": "approve",
            "message": (
                "Talaria wants to download the Cherri compiler v2.4.0 (about 6 MB) from its "
                "official GitHub release and install it in the plugin data directory, after "
                "checking two sha256 checksums recorded in the plugin. Nothing is uploaded."
            ),
            "rule_key": "talaria_setup:cherri-v2.4.0",
        }
    if tool_name != "talaria_sign" or args.get("consent") is not True:
        return None
    artifact_id = str(args.get("artifact_id") or "").strip() or "unknown"
    return {
        "action": "approve",
        "message": (
            f"Talaria wants to upload shortcut {artifact_id} to "
            "https://hubsign.routinehub.services/sign for Apple signing. "
            "The compiled workflow leaves this machine: every action, text field, URL and "
            "embedded value in it."
        ),
        "rule_key": f"talaria_sign:{artifact_id}",
    }


def register(ctx) -> None:
    """Register the seven tools, the approval hook and the bundled skill. No engine import here."""
    for name, handler in _HANDLERS.items():
        ctx.register_tool(
            name=name,
            toolset=PLUGIN,
            schema=SCHEMAS[name],
            handler=handler,
        )
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    skill = PLUGIN_DIR / "skills" / SKILL_NAME / "SKILL.md"
    if skill.is_file():
        ctx.register_skill(
            SKILL_NAME,
            skill,
            description=(
                "How to write correct Cherri source for Talaria: file shape, verified action "
                "signatures, house patterns, and the rules that keep a build from silently breaking."
            ),
        )
