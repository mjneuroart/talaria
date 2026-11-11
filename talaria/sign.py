"""Apple signing from Linux, via the compiler's own HubSign path.

What happens when consent is given (measured against ref/cherri v2.4.0,
signing.go:27-31 and 117-136): on a non-macOS host the compiler POSTs the whole
shortcut, as an XML plist string, to

    https://hubsign.routinehub.services/sign
    {"shortcutName": "<source file base name>", "shortcut": "<plist text>"}

and writes the AEA1 answer next to the source. The ONLY way to reach that path is
to invoke the compiler without --skip-sign; this module is the only place allowed
to do so, and only when `consent is True`.

The link between what was audited and what gets installed is enforced here: the
stored unsigned artifact must still match its recorded sha256, its source must
still pass the prefilter, and after signing the action list decoded from the
signed container is compared with the one the user saw.
"""

from __future__ import annotations

import os
import plistlib
import shutil
from pathlib import Path
from time import sleep

from . import aea, library, sandbox
from .compile import prefilter

SIGNER_URL = "https://hubsign.routinehub.services/sign"

REFUSAL = (
    "Refused: signing sends data off this machine and requires consent=True. "
    "What leaves the machine if you consent: the compiled shortcut, as an XML plist, "
    "containing every action, every text field, every URL and every embedded value in the "
    f"workflow, plus the shortcut name, in one HTTPS POST to {SIGNER_URL} (RoutineHub, a "
    "third party that holds an Apple Developer certificate). Nothing else is sent: no files "
    "from this machine, no environment, no keys. The signed file that comes back is the only "
    "thing returned. If the shortcut holds a secret in a header or a text action, that secret "
    "leaves the machine too."
)


class SignRefused(PermissionError):
    """consent was not exactly True.

    sign() itself returns a structured refusal instead of raising, so a caller that
    forgets the argument can never upload by accident. This exception is for callers
    that would rather fail hard: raise it from `require_consent`.
    """


class SignError(RuntimeError):
    """The signing path ran and did not produce a valid Apple-signed container."""


def require_consent(artifact_id: str, consent: bool = False) -> str:
    """Strict variant: raises SignRefused instead of returning a refusal."""
    result = sign(artifact_id, consent)
    if result.get("refused"):
        raise SignRefused(result["reason"])
    return result["signed_path"]


def _audited_identifiers(unsigned_path: Path) -> list[str]:
    blob = unsigned_path.read_bytes()
    plist = plistlib.loads(blob)
    return [
        str(a.get("WFWorkflowActionIdentifier"))
        for a in plist.get("WFWorkflowActions") or []
        if isinstance(a, dict)
    ]


def _signed_identifiers(blob: bytes) -> list[str] | None:
    """Action identifiers decoded from a signed container, or None when unreadable."""
    from . import inspect as audit

    try:
        report = audit.inspect(blob)
    except Exception:  # noqa: BLE001 - an unreadable body is reported as "not verified"
        return None
    return [a["identifier"] for a in report["workflow"]["actions"]]


def sign(artifact_id: str, consent: bool = False, timeout: float = 90.0) -> dict:
    """Sign a previously built artifact.

    Without consent this performs NO I/O and returns
    {"refused": True, "uploaded": False, "reason": <what would leave the machine>}.
    Only `consent is True` reaches the network.
    """
    if consent is not True:
        return {
            "refused": True,
            "uploaded": False,
            "consent": consent,
            "artifact_id": artifact_id,
            "signed_path": None,
            "sha256": None,
            "aea": None,
            "reason": REFUSAL,
        }

    library.check_id(artifact_id)
    meta = library.read_meta(artifact_id)
    unsigned_path = library.artifact_path(artifact_id)
    if not unsigned_path.is_file():
        raise SignError(
            f"artifact {artifact_id} has no stored file at {unsigned_path}; run talaria_build again"
        )

    recorded = meta.get("sha256")
    actual = library.sha256_file(unsigned_path)
    if recorded and actual != recorded:
        raise SignError(
            "the stored artifact no longer matches the sha256 recorded when it was built "
            f"({actual[:16]}... vs {recorded[:16]}...). Something changed it on disk; rebuild it."
        )

    source = meta.get("source")
    if not source:
        raise SignError(f"artifact {artifact_id} has no stored source to re-sign")
    findings = prefilter(source)
    if findings:
        raise SignError(
            "the stored source no longer passes the prefilter ("
            + ", ".join(f["rule"] for f in findings)
            + "); rebuild it rather than signing it"
        )

    slug = library.slugify(meta.get("name") or "") or "shortcut"
    jobdir = library.new_jobdir(f"sign-{slug}")
    source_name = f"{slug}.cherri"          # never taken from metadata
    try:
        (jobdir / source_name).write_text(source, encoding="utf-8")

        # Deliberately NO --skip-sign: this is the real signing branch.
        # The signing service sometimes answers with a text/plain error page instead of the
        # signed container (measured on 2026-11-11). That is transient, so retry it; a real
        # refusal (bad source, 4xx) is not retried.
        transient = ("Unsupported response type", "Failed to sign Shortcut", "connection reset")
        result = sandbox.run([source_name, "--no-ansi"], jobdir, allow_network=True, timeout=timeout)
        attempts = 1
        while (
            result["rc"] != 0
            and attempts < 3
            and any(t in (result["stdout"] + result["stderr"]) for t in transient)
        ):
            attempts += 1
            sleep(3 * attempts)
            result = sandbox.run(
                [source_name, "--no-ansi"], jobdir, allow_network=True, timeout=timeout
            )

        diag = {
            "argv": result["argv"],
            "rc": result["rc"],
            "attempts": attempts,
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "elapsed": result["elapsed"],
            "isolation": result["isolation"],
            "endpoint": SIGNER_URL,
            "skip_sign": False,
        }
        if result["rc"] != 0:
            raise SignError(
                f"signer path failed (rc={result['rc']}): "
                f"{(result['stdout'] or result['stderr']).strip()[:1000]}"
            )

        signed = [p for p in sorted(jobdir.glob("*.shortcut")) if "_unsigned" not in p.name]
        if not signed:
            raise SignError(
                "compiler exited 0 but wrote no signed .shortcut; "
                f"stdout={result['stdout'].strip()[:400]!r} stderr={result['stderr'].strip()[:400]!r}"
            )
        path = signed[0]
        blob = path.read_bytes()
    finally:
        shutil.rmtree(jobdir, ignore_errors=True)

    try:
        hdr = aea.parse_header(blob)
    except aea.AEAError as exc:
        raise SignError(f"output is not a parseable AEA1 container: {exc}") from exc
    if hdr["magic"] != "AEA1":
        raise SignError(f"bad magic: {hdr['magic']!r}")
    if len(hdr["chain_sizes"]) != 3:
        raise SignError(f"expected a 3-certificate chain, got {len(hdr['chain_sizes'])}")
    if not hdr["apple_issued"]:
        raise SignError(f"no Apple issuer in chain: {hdr['issuers']}")

    # What the user audited must be what they install.
    want = _audited_identifiers(unsigned_path)
    got = _signed_identifiers(blob)
    content_verified: bool | None = None if got is None else (got == want)
    if content_verified is False:
        raise SignError(
            "the signed container does not hold the action list that was audited; refusing to "
            f"hand it over (audited {len(want)} actions, signed {len(got)})"
        )

    sha = library.sha256_bytes(blob)
    signed_id = "s" + sha[:15]
    dest = library.artifact_path(signed_id)
    dest.write_bytes(blob)
    os.chmod(dest, 0o600)

    meta.update({
        "signed": True,
        "signed_artifact_id": signed_id,
        "signed_sha256": sha,
        "signed_bytes": len(blob),
        "sign_uploaded": True,
        "sign_endpoint": SIGNER_URL,
        "sign_diagnostics": diag,
        "content_verified": content_verified,
    })
    # The unsigned record keeps describing its own file; it only gains a pointer to the signed one.
    library.write_meta(artifact_id, {**meta, "signed": False})
    library.write_meta(signed_id, {**meta, "artifact_id": signed_id, "sha256": sha,
                                   "bytes": len(blob), "signed": True})

    # The copy the user receives lives where Hermes is allowed to attach a file from.
    delivery = library.publish(signed_id)

    return {
        "name": meta.get("display_name") or meta.get("name"),
        "signed": True,
        "deliver": {**delivery, "how": library.DELIVER_HOW},
        "signed_artifact_id": signed_id,
        "signed_path": str(dest),
        "sha256": sha,
        "bytes": len(blob),
        "uploaded": True,
        "endpoint": SIGNER_URL,
        "content_verified": content_verified,
        "aea": {
            "magic": hdr["magic"],
            "chain_sizes": hdr["chain_sizes"],
            "issuers": hdr["issuers"],
            "subjects": hdr["subjects"],
            "apple_issued": hdr["apple_issued"],
            "signature_verified": False,
            "body_len": hdr["total_len"] - hdr["body_offset"],
        },
        "diagnostics": diag,
    }


def inspect_signed(path: str | os.PathLike) -> dict:
    """Header facts for any signed .shortcut on disk (no decompression)."""
    return aea.summary(Path(path).read_bytes())
