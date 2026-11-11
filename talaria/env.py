"""Measured environment facts: compiler, sandbox, signer, decoder.

Every field here is the result of an actual probe performed by this module.
Nothing is cached and nothing is assumed: a missing binary reports present=False
with the error that proved it.

No network call happens unless the caller asks for one. `status()` is silent by
default; `status(probe_signer=True)` opens one TCP connection to the signing host
and says so in its result.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

from .library import home as _library_home, sha256_file

COMPILER_ENV = "TALARIA_CHERRI"
ALLOW_UNPINNED_ENV = "TALARIA_ALLOW_UNPINNED"
SIGNER_HOST = "hubsign.routinehub.services"
SIGNER_PORT = 443

#: sha256 of every compiler build whose behaviour this plugin was audited against.
#: Only the Linux x86-64 build of v2.4.0 was audited; a different binary is refused
#: unless TALARIA_ALLOW_UNPINNED=1, because the prefilter and the argv rules are
#: statements about this exact compiler.
PINNED: dict[str, str] = {
    "07c0e9f9ccfca541795b41d31a4e0ff8ced953f545bdd3df5823e787002f03f7": "2.4.0 linux-x86_64",
}


class CompilerNotPinned(RuntimeError):
    """The compiler on this machine is not a build this plugin was audited against."""


def managed_compiler() -> Path:
    """Where `talaria_setup` installs the pinned compiler. The file may not exist."""
    return _library_home() / "bin" / "cherri"


def compiler_path() -> Path | None:
    """Locate the Cherri binary: $TALARIA_CHERRI, then the copy talaria_setup installed, then PATH."""
    explicit = os.environ.get(COMPILER_ENV)
    if explicit:
        p = Path(explicit).expanduser()
        return p if p.is_file() else None
    managed = managed_compiler()
    if managed.is_file():
        return managed
    on_path = shutil.which("cherri")
    return Path(on_path) if on_path else None


def is_pinned(digest: str) -> bool:
    return digest in PINNED


def assert_pinned_compiler(path: str | os.PathLike) -> str:
    """Return the digest, or raise when the binary is not an audited build."""
    digest = sha256_file(path)
    if digest in PINNED:
        return digest
    if os.environ.get(ALLOW_UNPINNED_ENV) == "1":
        return digest
    known = ", ".join(f"{v} ({k[:12]})" for k, v in PINNED.items()) or "none"
    raise CompilerNotPinned(
        f"the Cherri compiler at {path} is not a build Talaria was audited against "
        f"(sha256 {digest[:16]}..., known builds: {known}). Talaria pins the compiler because "
        f"its source filter and its compile flags are statements about one exact version. "
        f"Install the pinned release, or set {ALLOW_UNPINNED_ENV}=1 to accept the risk explicitly."
    )


def _compiler_status() -> dict:
    path = compiler_path()
    out = {"present": False, "path": None, "version": None, "sha256": None,
           "pinned": False, "error": None}
    if path is None:
        out["error"] = (
            "cherri not found: call talaria_setup with confirm=true to install the pinned build, "
            f"or put it on PATH, or set ${COMPILER_ENV} to its full path"
        )
        return out
    out["path"] = str(path)
    out["sha256"] = sha256_file(path)
    out["pinned"] = out["sha256"] in PINNED
    if not out["pinned"] and os.environ.get(ALLOW_UNPINNED_ENV) != "1":
        # A binary Talaria does not recognise is never executed, not even for --version.
        out["present"] = True
        out["error"] = (
            "a cherri binary is present but it is not a build Talaria was audited against, so "
            "it was not executed. Call talaria_setup with confirm=true to install the pinned build."
        )
        return out
    try:
        # --version returns rc=0, touches no network and writes no file.
        proc = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            env={"HOME": os.environ.get("HOME", "/tmp"), "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    text = (proc.stdout or "") + (proc.stderr or "")
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)   # --version colours its output
    out["present"] = proc.returncode == 0
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("cherri compiler"):
            out["version"] = line.replace("Cherri Compiler ", "").strip()
            break
    if out["version"] is None:
        out["error"] = f"unexpected --version output: {text.strip()[:200]!r}"
    return out


def _sandbox_status() -> dict:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return {
            "available": False,
            "mode": "unavailable",
            "bwrap_path": None,
            "reason": (
                "bwrap is not installed: every compile will be refused. "
                "Install the 'bubblewrap' package."
            ),
        }
    # A real probe: does bwrap actually work on this kernel (userns allowed)?
    try:
        # The same read-only system mounts the sandbox gives a helper binary. On a
        # merged-/usr distribution /bin and /lib64 are symlinks into /usr: binding /usr
        # alone leaves no /bin/true and no dynamic loader, and the probe then reports
        # "unusable" on a machine whose sandbox works (measured on Arch).
        probe = subprocess.run(
            [bwrap, "--unshare-all", "--die-with-parent",
             "--ro-bind", "/usr", "/usr",
             "--ro-bind-try", "/bin", "/bin", "--ro-bind-try", "/sbin", "/sbin",
             "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
             "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--remount-ro", "/",
             shutil.which("true") or "/bin/true"],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "mode": "unavailable", "bwrap_path": bwrap,
                "reason": f"{type(exc).__name__}: {exc}"}
    if probe.returncode != 0:
        return {
            "available": False,
            "mode": "unavailable",
            "bwrap_path": bwrap,
            "reason": f"bwrap present but unusable: {(probe.stderr or probe.stdout).strip()[:300]}",
        }
    return {"available": True, "mode": "bwrap", "bwrap_path": bwrap, "reason": "userns probe ok"}


def _decoder_status() -> dict:
    """The LZFSE decoder is pure Python now: nothing to install, nothing to find."""
    try:
        from . import lzfse

        return {"present": True, "mode": "pure-python", "error": None,
                "detail": lzfse.DESCRIPTION}
    except Exception as exc:  # noqa: BLE001 - report, never raise from a status probe
        return {"present": False, "mode": "unavailable", "error": f"{type(exc).__name__}: {exc}",
                "detail": None}


def _signer_status(timeout: float = 3.0) -> dict:
    out = {
        "reachable": False,
        "checked": True,
        "host": SIGNER_HOST,
        "port": SIGNER_PORT,
        "url": f"https://{SIGNER_HOST}/sign",
        "latency_ms": None,
        "error": None,
    }
    started = time.monotonic()
    try:
        with socket.create_connection((SIGNER_HOST, SIGNER_PORT), timeout=timeout):
            pass
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    out["reachable"] = True
    out["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
    return out


def status(probe_signer: bool = False) -> dict:
    """{compiler, sandbox, signer, decoder} - all measured now.

    With the default `probe_signer=False` this function opens NO socket. Pass
    `probe_signer=True` to test that the signing host is reachable; the result
    says so either way.
    """
    signer = _signer_status() if probe_signer else {
        "reachable": None,
        "checked": False,
        "host": SIGNER_HOST,
        "port": SIGNER_PORT,
        "url": f"https://{SIGNER_HOST}/sign",
        "latency_ms": None,
        "error": (
            "not probed: Talaria makes no network call unless you ask for one. "
            "Call talaria_status with probe_signer=true to test reachability."
        ),
    }
    return {
        "compiler": _compiler_status(),
        "sandbox": _sandbox_status(),
        "decoder": _decoder_status(),
        "signer": signer,
    }


if __name__ == "__main__":  # pragma: no cover - manual probe
    import json
    import sys

    print(json.dumps(status(probe_signer="--probe" in sys.argv), indent=2))
