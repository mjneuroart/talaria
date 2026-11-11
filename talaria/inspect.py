"""Talaria inspect: decode a `.shortcut`, list its actions, report its risks.

Two container shapes, both handled here:

* **Unsigned** `.shortcut` - a plain XML or binary plist. `plistlib` reads it directly.
* **Apple-signed** `.shortcut` - an `AEA1` container: a 12-byte prologue
  (`AEA1`, 3-byte profile, 1-byte scheme, uint32 header length), an auth plist carrying
  `SigningCertificateChain`, an ECDSA signature, then an LZFSE/LZVN-compressed body
  holding an Apple archive whose payload is `Shortcut.wflow` (a plist with
  `WFWorkflowActions`).

Nothing here executes the shortcut, opens a URL, or leaves the machine. No subprocess
is spawned: the decoder and the certificate reader are both pure Python.

Verdict semantics, in plain words:

* `dangerous` - at least one high-severity finding.
* `review`    - no high finding, but at least one action Talaria has no rule for, or a
                medium/low finding. An action it cannot assess is flagged, never ignored:
                an audit that answers "clean" for what it did not understand fails open.
* `no-findings` - every action was recognised and none matched a risk rule.
"""

from __future__ import annotations

import plistlib
import re
from pathlib import Path
from typing import Any

from . import aea, lzfse

__all__ = ["inspect", "inspect_link", "InspectError", "SHORT_NAMES", "BENIGN_ACTIONS"]

AEA_MAGIC = b"AEA1"
XML_MAGIC = b"<?xml"
BPLIST_MAGIC = b"bplist00"
MAX_INPUT_BYTES = 32 * 1024 * 1024

PREFIX = "is.workflow.actions."


class InspectError(ValueError):
    """The bytes given are not a `.shortcut` we can decode."""


# Identifier -> human name. Every pair was confirmed against a compiled artifact; an
# identifier that is absent is reported as the raw identifier rather than guessed.
SHORT_NAMES: dict[str, str] = {
    PREFIX + "alert": "Show Alert",
    PREFIX + "ask": "Ask for Input",
    PREFIX + "choosefromlist": "Choose from List",
    PREFIX + "choosefrommenu": "Choose from Menu",
    PREFIX + "comment": "Comment",
    PREFIX + "conditional": "If",
    PREFIX + "count": "Count",
    PREFIX + "date": "Current Date",
    PREFIX + "delay": "Wait",
    PREFIX + "dictionary": "Dictionary",
    PREFIX + "documentpicker.open": "Get File",
    PREFIX + "documentpicker.save": "Save File",
    PREFIX + "downloadurl": "Get Contents of URL",
    PREFIX + "file": "File",
    PREFIX + "file.delete": "Delete Files",
    PREFIX + "format.date": "Format Date",
    PREFIX + "getbatterylevel": "Get Battery Level",
    PREFIX + "getclipboard": "Get Clipboard",
    PREFIX + "getcontacts": "Get Contacts",
    PREFIX + "getcurrentlocation": "Get Current Location",
    PREFIX + "gettext": "Text",
    PREFIX + "getvalueforkey": "Get Dictionary Value",
    PREFIX + "list": "List",
    PREFIX + "math": "Calculate",
    PREFIX + "nothing": "Nothing",
    PREFIX + "notification": "Show Notification",
    PREFIX + "number": "Number",
    PREFIX + "openapp": "Open App",
    PREFIX + "openpasswords": "Search Passwords",
    PREFIX + "openurl": "Open URL",
    PREFIX + "openxcallbackurl": "Open X-Callback URL",
    PREFIX + "repeat.count": "Repeat",
    PREFIX + "repeat.each": "Repeat with Each",
    PREFIX + "runsshscript": "Run Script Over SSH",
    PREFIX + "runworkflow": "Run Shortcut",
    PREFIX + "sendemail": "Send Email",
    PREFIX + "sendmessage": "Send Message",
    PREFIX + "setclipboard": "Set Clipboard",
    PREFIX + "setvariable": "Set Variable",
    PREFIX + "showresult": "Show Result",
    PREFIX + "showwebpage": "Show Web Page",
    PREFIX + "speaktext": "Speak Text",
    PREFIX + "url": "URL",
    PREFIX + "vibrate": "Vibrate Device",
}

#: Actions with no effect outside the shortcut itself. This is the allowlist: anything
#: outside it is reported as unassessed, so the audit never says "clean" about an action
#: it never looked at.
BENIGN_ACTIONS = {
    "alert", "ask", "choosefromlist", "choosefrommenu", "comment", "conditional",
    "count", "date", "delay", "dictionary", "format.date", "gettext", "getvalueforkey",
    "list", "math", "nothing", "notification", "number", "repeat.count", "repeat.each",
    "setvariable", "showresult", "speaktext", "vibrate", "url", "getitemfromlist",
    "appendvariable", "getvariable", "output", "exit", "wait",
}

#: Actions covered by a dedicated rule below (extended with NAMED_RISKS just after it).
#: An action in this set that produced no finding was looked at and judged, so it is never
#: reported as unassessed.
RULE_COVERED = {
    "openurl", "openxcallbackurl", "showwebpage", "downloadurl", "setclipboard",
    "getclipboard", "documentpicker.save", "file", "runworkflow", "getcurrentlocation",
    "selectphoto", "deletephotos",
}

#: Identifiers that carry a specific, named risk. Keyed by the short identifier.
NAMED_RISKS: dict[str, tuple[str, str]] = {
    "runsshscript": ("high", "SSH_EXEC"),
    "sendmessage": ("high", "SEND_MESSAGE"),
    "sendemail": ("high", "SEND_EMAIL"),
    "file.delete": ("high", "FILE_DELETE"),
    "deletephotos": ("high", "PHOTO_DELETE"),
    "openpasswords": ("high", "PASSWORD_ACCESS"),
    "runjavascriptonwebpage": ("high", "PAGE_SCRIPT"),
}

RULE_COVERED |= set(NAMED_RISKS)

NET_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

#: Non-web schemes hand control to another app, and some are an entry point into
#: Shortcuts itself.
RISKY_SCHEMES = {
    "shortcuts", "workflow", "prefs", "settings", "app-settings", "x-apple",
    "shortcuts-run", "tel", "facetime", "sms", "mailto", "mobilenotes", "data",
}

#: Where the URL actually lives, per opener action. `openURL()` compiles to
#: `openurl` with `WFInput`; `is.workflow.actions.url` is the passive URL value.
URL_OPENERS = {
    PREFIX + "openurl": "WFInput",
    PREFIX + "openxcallbackurl": "WFXCallbackURL",
    PREFIX + "showwebpage": "WFURL",
}

PARAM_KEYS = (
    "WFURL", "WFHTTPMethod", "WFHTTPBodyType", "WFFileDestinationPath", "WFFilePath",
    "WFAlertActionMessage", "WFAlertActionTitle", "WFAskActionPrompt",
    "WFTextActionText", "WFWorkflowName", "WFSerializationType", "WFInput",
)


def _truncate(value: Any, limit: int = 100) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 1] + "\u2026"
    return value


def _string_of(value: Any) -> str:
    """Text out of a plain string or a WFTextTokenString."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        inner = value.get("Value")
        if isinstance(inner, dict) and isinstance(inner.get("string"), str):
            return inner["string"]
        if isinstance(inner, str):
            return inner
    return ""


def _summarise(params: dict[str, Any]) -> dict[str, Any]:
    """Only the parameters that matter for reading the action, never the UUID noise."""
    out: dict[str, Any] = {}
    for key in PARAM_KEYS:
        if key in params:
            out[key] = _truncate(params[key])
    for key in ("WFJSONValues", "WFHTTPHeaders", "WFRequestVariable"):
        if key in params:
            out[key] = "<present>"
    for key in ("WFAlertActionMessage", "WFTextActionText", "Text", "WFInput"):
        literal = _string_of(params.get(key))
        if literal:
            out[key] = _truncate(literal)
    if not out:
        for key, val in params.items():
            if key not in ("UUID", "CustomOutputName", "GroupingIdentifier") and not isinstance(val, (dict, list)):
                out[key] = _truncate(val)
            if len(out) >= 4:
                break
    return out


def _walk_for_clipboard(value: Any, depth: int = 0) -> bool:
    """True when a parameter reads the clipboard through a variable attachment."""
    if depth > 12:
        return False
    if isinstance(value, dict):
        if value.get("Type") == "Clipboard":
            return True
        return any(_walk_for_clipboard(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return any(_walk_for_clipboard(v, depth + 1) for v in value)
    return False


def _has_runtime_attachments(value: Any) -> bool:
    """True when a dictionary carries attachmentsByRange, i.e. run-time data."""
    if isinstance(value, dict):
        if value.get("attachmentsByRange"):
            return True
        return any(_has_runtime_attachments(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_runtime_attachments(v) for v in value)
    return False


def _scheme_of(url: str) -> str:
    match = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*):", url.strip())
    return match.group(1).lower() if match else ""


def _parse_aea(blob: bytes) -> tuple[dict[str, Any], bytes]:
    hdr = aea.parse_header(blob)
    container = {
        "magic": "AEA1",
        "profile": hdr["flags"],
        "scheme": blob[7] if len(blob) > 7 else 0,
        "auth_len": hdr["header_len"],
        "chain_sizes": hdr["chain_sizes"],
        "issuers": hdr["issuers"],
        "subjects": hdr["subjects"],
        # `signed` means "an AEA1 container with a certificate chain is present".
        # The signature itself is NOT verified: no crypto library is used here.
        "signed": bool(hdr["chain_sizes"]),
        "signature_verified": False,
    }
    return container, aea.body(blob, hdr)


def _workflow_bytes(container: dict[str, Any], body: bytes) -> bytes:
    """Return a plist byte-string holding the workflow, decompressing when needed."""
    if body[:8] == BPLIST_MAGIC or body[:5] == XML_MAGIC:
        return body
    if lzfse.find_stream(body) != -1:
        decoded = lzfse.decompress(body)
        container["decompressed_bytes"] = len(decoded)
        container["compressed"] = "lzfse/lzvn"
        for marker in (BPLIST_MAGIC, XML_MAGIC):
            found = decoded.find(marker)
            if found != -1:
                return decoded[found:]
        return decoded
    # Last resort: a bare plist somewhere in the body (an unsigned file inside AEA, or
    # an unknown wrapper). Reported as an anomaly by the caller, never silently accepted.
    for marker in (BPLIST_MAGIC, XML_MAGIC):
        found = body.find(marker)
        if found != -1:
            container["compressed"] = "none"
            container["bare_plist_in_aea"] = True
            return body[found:]
    raise InspectError("AEA1 body holds no readable plist and no LZFSE/LZVN stream")


def _load_plist(raw: bytes) -> dict[str, Any]:
    try:
        obj = plistlib.loads(raw)
    except Exception as exc:  # noqa: BLE001 - surface as our own error
        raise InspectError(f"workflow plist does not parse: {exc}") from exc
    if not isinstance(obj, dict):
        raise InspectError("workflow plist is not a dictionary")
    if "WFWorkflowActions" not in obj:
        raise InspectError("plist has no WFWorkflowActions key; not a Shortcut")
    if not isinstance(obj["WFWorkflowActions"], list):
        raise InspectError("WFWorkflowActions is not a list")
    return obj


def _rules(index: int, ident: str, params: dict[str, Any], workflow: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    def add(severity: str, code: str, why: str, evidence: str) -> None:
        findings.append(
            {"severity": severity, "code": code, "action_index": index, "why": why, "evidence": evidence}
        )

    short = ident[len(PREFIX):] if ident.startswith(PREFIX) else ident

    if ident == PREFIX + "downloadurl":
        method = str(params.get("WFHTTPMethod") or "GET").upper()
        body_type = params.get("WFHTTPBodyType")
        has_body = bool(body_type) or "WFJSONValues" in params or "WFHTTPBody" in params
        url = _string_of(params.get("WFURL"))
        runtime_url = _has_runtime_attachments(params.get("WFURL"))
        if method in NET_METHODS or has_body or runtime_url:
            detail = f"method={method}"
            if body_type:
                detail += f" body={body_type}"
            if runtime_url and method not in NET_METHODS and not has_body:
                detail += " url assembled at run time"
            add("high", "NET_WRITE",
                f"writes data to a remote host ({detail}) and can send anything in scope",
                f"{detail} url={_truncate(url, 70) or '<variable>'}")
        else:
            add("medium", "NET_READ",
                "reads a remote URL; the response becomes shortcut input",
                f"GET url={_truncate(url, 70) or '<variable>'}")

    if ident in URL_OPENERS:
        raw = params.get(URL_OPENERS[ident])
        url = _string_of(raw)
        if not url:
            add("medium", "URL_OPEN_DYNAMIC",
                "opens a URL assembled at run time, so the destination is not in this file",
                ident)
        else:
            scheme = _scheme_of(url)
            if scheme and scheme not in ("http", "https"):
                severity = "high" if scheme in RISKY_SCHEMES else "medium"
                add(severity, "URL_SCHEME_OPEN",
                    f"opens the {scheme}: scheme and hands control to another app",
                    f"{scheme}: {_truncate(url, 60)}")

    if ident == PREFIX + "setclipboard":
        add("low", "CLIPBOARD_WRITE",
            "overwrites the user's clipboard and can be used to plant content",
            "Set Clipboard")

    if ident == PREFIX + "documentpicker.save":
        dest = _string_of(params.get("WFFileDestinationPath"))
        add("medium", "SAVE_TO_FILES",
            "writes a file into the user's Files storage, outside this shortcut's container",
            f"dest={_truncate(dest, 70) or '<asks user>'}")

    if ident == PREFIX + "file":
        add("high", "FILE_WRITE",
            "the File action writes, moves or overwrites paths in the Files provider",
            "File action")

    if ident == PREFIX + "runworkflow":
        target = _string_of(params.get("WFWorkflowName")) or _string_of(params.get("WFInput"))
        nested = params.get("WFWorkflow")
        if isinstance(nested, dict) and nested.get("isSelf") is True:
            add("medium", "RUN_SELF",
                "calls a function defined in this same shortcut (normal for a Cherri function)",
                "isSelf")
        elif target:
            add("medium", "RUN_SHORTCUT",
                "invokes another shortcut, so the real behaviour is not visible in this file",
                f"target={_truncate(target, 60)}")
        else:
            add("medium", "RUN_SHORTCUT",
                "invokes another shortcut chosen at run time",
                "<variable>")

    if "location" in ident.lower() and ident.startswith(PREFIX):
        add("medium", "LOCATION_ACCESS",
            "reads the device location, which identifies where the user is",
            ident)

    if "health" in ident.lower() or ident.startswith("com.apple.health"):
        add("medium", "HEALTH_ACCESS",
            "reads or writes Apple Health data, the most sensitive dataset on the device",
            ident)

    if "contacts" in ident.lower() and ident.startswith(PREFIX):
        add("medium", "CONTACTS_ACCESS",
            "reads the address book and can enumerate every contact",
            ident)

    if ident in (PREFIX + "selectphoto", PREFIX + "deletephotos"):
        add("high" if ident.endswith("deletephotos") else "medium",
            "PHOTO_DELETE" if ident.endswith("deletephotos") else "PHOTO_ACCESS",
            "selects or deletes photos from the user's library", ident)

    # Clipboard through a variable attachment, which no per-action rule can see.
    if ident != PREFIX + "getclipboard" and _walk_for_clipboard(params):
        add("high", "CLIPBOARD_VARIABLE_READ",
            "reads the clipboard through a variable and can send it anywhere",
            "parameter holds a Clipboard attachment")
    if ident == PREFIX + "getclipboard":
        add("medium", "CLIPBOARD_READ",
            "reads the system clipboard, which routinely holds passwords and codes",
            "Get Clipboard")

    if short in NAMED_RISKS:
        severity, code = NAMED_RISKS[short]
        add(severity, code, f"{SHORT_NAMES.get(ident, short)} has a side effect outside the shortcut", ident)

    if not findings and short not in BENIGN_ACTIONS and short not in RULE_COVERED:
        add("low", "UNASSESSED_ACTION",
            "Talaria has no rule for this action, so read it yourself before installing",
            ident)

    return findings


def inspect(source: str | Path | bytes | bytearray) -> dict[str, Any]:
    """Audit a `.shortcut`. Accepts a path or raw bytes; never executes anything."""
    if isinstance(source, (bytes, bytearray)):
        blob = bytes(source)
        origin = "<bytes>"
    else:
        path = Path(source).expanduser()
        if not path.is_file():
            raise InspectError(f"no such file: {path}")
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise InspectError(f"{path} is larger than the {MAX_INPUT_BYTES} byte limit")
        blob = path.read_bytes()
        origin = str(path)
    if not blob:
        raise InspectError(f"{origin} is empty")

    extra: list[dict[str, Any]] = []
    if blob[:4] == AEA_MAGIC:
        container, body = _parse_aea(blob)
        if not container["chain_sizes"]:
            extra.append({"severity": "high", "code": "CONTAINER_ANOMALY", "action_index": -1,
                          "why": "an AEA1 container with no certificate chain: Apple never produces this",
                          "evidence": "empty SigningCertificateChain"})
    elif blob[:8] == BPLIST_MAGIC:
        container, body = {"magic": "bplist00", "chain_sizes": [], "issuers": [],
                           "signed": False, "signature_verified": False}, blob
    elif blob[:5] == XML_MAGIC:
        container, body = {"magic": "xml", "chain_sizes": [], "issuers": [],
                           "signed": False, "signature_verified": False}, blob
    elif lzfse.find_stream(blob) != -1:
        container, body = {"magic": "lzfse", "chain_sizes": [], "issuers": [],
                           "signed": False, "signature_verified": False}, blob
    else:
        raise InspectError(
            f"{origin} is not a .shortcut container (first bytes {blob[:4].hex()}); "
            "expected AEA1, bplist00 or an XML plist"
        )

    body = _workflow_bytes(container, body)
    plist = _load_plist(body)
    if container.get("bare_plist_in_aea"):
        extra.append({"severity": "high", "code": "CONTAINER_ANOMALY", "action_index": -1,
                      "why": "an AEA1 container whose body is an uncompressed plist: not a real Apple signature",
                      "evidence": "body starts with a plist"})

    name = plist.get("WFWorkflowName")
    actions: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = list(extra)
    assessed = unassessed = 0
    for index, action in enumerate(plist.get("WFWorkflowActions") or []):
        if not isinstance(action, dict):
            continue
        ident = str(action.get("WFWorkflowActionIdentifier") or "<missing identifier>")
        params = action.get("WFWorkflowActionParameters") or {}
        if not isinstance(params, dict):
            params = {}
        actions.append({
            "index": index,
            "identifier": ident,
            "short": SHORT_NAMES.get(ident, ident),
            "params_summary": _summarise(params),
        })
        found = _rules(index, ident, params, plist)
        findings.extend(found)
        if any(f["code"] == "UNASSESSED_ACTION" for f in found):
            unassessed += 1
        else:
            assessed += 1

    if not actions:
        findings.append({"severity": "medium", "code": "EMPTY_SHORTCUT", "action_index": -1,
                         "why": "the shortcut holds no actions, so it does nothing",
                         "evidence": "WFWorkflowActions is empty"})

    severities = {f["severity"] for f in findings}
    if "high" in severities:
        verdict = "dangerous"
    elif severities & {"medium", "low"}:
        verdict = "review"
    else:
        verdict = "no-findings"

    return {
        "container": container,
        "workflow": {
            "name": name,
            "action_count": len(actions),
            "assessed": assessed,
            "unassessed": unassessed,
            "actions": actions,
        },
        "findings": findings,
        "verdict": verdict,
    }


# Convenience alias for host code that cannot import a module named `inspect`.
inspect_shortcut = inspect


def inspect_link(link: str) -> dict[str, Any]:
    """Audit the shortcut behind a public iCloud link, without installing it.

    Contacts Apple only (www.icloud.com, then the content host the record names), downloads
    the file the phone would install, and audits those exact bytes.
    """
    from . import icloud

    try:
        fetched = icloud.fetch(link)
    except icloud.LinkError as exc:
        raise InspectError(str(exc)) from exc
    report = inspect(fetched["blob"])
    report["origin"] = {
        key: fetched[key]
        for key in ("link", "name", "signing_status", "asset", "host", "bytes", "sha256")
    }
    return report
