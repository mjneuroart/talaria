"""Install the pinned Cherri compiler, on request.

Talaria ships no compiler (the plugin catalog refuses a compiled binary in the tree) and never
fetches one on its own. `talaria_setup` downloads exactly one archive from the compiler's
official GitHub release, checks it against a sha256 recorded in this file, unpacks one member,
checks that member against a second recorded sha256, and only then writes it into the plugin's
data directory. Nothing is executed before both checksums match, and nothing is written when
either one differs.

Without confirm=True this module performs no network call: it returns what it would download.
"""

from __future__ import annotations

import hashlib
import io
import os
import platform
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from . import env, library

RELEASE = "v2.4.0"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_BINARY_BYTES = 32 * 1024 * 1024
USER_AGENT = "talaria-setup (Hermes plugin; pinned download)"

#: One entry per compiler build this plugin was audited against. Sizes and checksums were
#: measured on 2026-11-10 from https://github.com/electrikmilk/cherri/releases/tag/v2.4.0 .
BUILDS: dict[str, dict] = {
    "linux-x86_64": {
        "url": "https://github.com/electrikmilk/cherri/releases/download/v2.4.0/cherri_linux-x86_64.zip",
        "archive_bytes": 5989885,
        "archive_sha256": "160c2d71c2a3653a20f0b80a1e7505ee846137ef17e209f511c873e4471b8e44",
        "member": "cherri",
        "binary_bytes": 14327968,
        "binary_sha256": "07c0e9f9ccfca541795b41d31a4e0ff8ced953f545bdd3df5823e787002f03f7",
    },
}


class SetupError(RuntimeError):
    """The compiler could not be installed. Nothing was left half-written."""


def platform_key() -> str:
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "aarch64": "arm64"}.get(machine, machine)
    return f"{platform.system().lower()}-{machine}"


def official_host(url: str) -> bool:
    """True for an https URL on github.com or one of GitHub's own asset hosts."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    return parts.scheme == "https" and (host == "github.com" or host.endswith(".githubusercontent.com"))


class _OfficialRedirects(urllib.request.HTTPRedirectHandler):
    """GitHub answers a release download with a redirect to its asset host. Follow that only."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not official_host(newurl):
            host = urllib.parse.urlsplit(newurl).hostname
            raise SetupError(f"refused a redirect to {host!r}: not a GitHub host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str) -> bytes:
    if not official_host(url):
        raise SetupError(f"refused to download from {url!r}: not a GitHub host")
    opener = urllib.request.build_opener(_OfficialRedirects)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=60) as response:
            blob = response.read(MAX_ARCHIVE_BYTES + 1)
    except (urllib.error.URLError, OSError) as exc:
        raise SetupError(f"download failed: {type(exc).__name__}: {exc}") from exc
    if len(blob) > MAX_ARCHIVE_BYTES:
        raise SetupError(f"the archive is larger than {MAX_ARCHIVE_BYTES} bytes; not kept")
    return blob


def plan() -> dict:
    """What `install(confirm=True)` would do on this machine. Performs no I/O."""
    key = platform_key()
    build = BUILDS.get(key)
    out = {
        "platform": key,
        "supported": build is not None,
        "release": RELEASE,
        "installs_to": str(env.managed_compiler()),
    }
    if build:
        out.update({
            "url": build["url"],
            "archive_bytes": build["archive_bytes"],
            "archive_sha256": build["archive_sha256"],
            "binary_sha256": build["binary_sha256"],
        })
    return out


def _refusal(build: dict, target) -> str:
    return (
        "Refused: installing the compiler downloads a file and requires confirm=True. "
        f"What happens if you confirm: one HTTPS GET to {build['url']} "
        f"({build['archive_bytes']} bytes), the compiler's official GitHub release. Nothing is "
        f"uploaded. The archive must match sha256 {build['archive_sha256']}; the single file "
        f"unpacked from it must match sha256 {build['binary_sha256']}; only then is it written "
        f"to {target}. Nothing runs before both checksums match."
    )


def install(confirm: bool = False) -> dict:
    """Install the pinned compiler into the plugin data directory.

    Returns at once, with no network call, when a pinned compiler is already usable or when
    `confirm` is not exactly True.
    """
    current = env.compiler_path()
    if current is not None:
        digest = library.sha256_file(current)
        if env.is_pinned(digest):
            return {
                "installed": True,
                "already_present": True,
                "downloaded": False,
                "path": str(current),
                "sha256": digest,
                "compiler": env._compiler_status(),
            }

    key = platform_key()
    build = BUILDS.get(key)
    if build is None:
        raise SetupError(
            f"no audited Cherri build for {key}: Talaria pins one compiler build per platform and "
            f"only {', '.join(sorted(BUILDS))} is recorded. Install Cherri {RELEASE} yourself and "
            f"point ${env.COMPILER_ENV} at it; a build outside the pin also needs "
            f"${env.ALLOW_UNPINNED_ENV}=1."
        )

    target = env.managed_compiler()
    if confirm is not True:
        return {
            "installed": False,
            "refused": True,
            "downloaded": False,
            "reason": _refusal(build, target),
            "plan": plan(),
        }

    blob = _download(build["url"])
    digest = hashlib.sha256(blob).hexdigest()
    if digest != build["archive_sha256"]:
        raise SetupError(
            f"checksum mismatch on the downloaded archive (got {digest[:16]}..., expected "
            f"{build['archive_sha256'][:16]}...). Nothing was written."
        )
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            info = archive.getinfo(build["member"])
            if info.file_size != build["binary_bytes"] or info.file_size > MAX_BINARY_BYTES:
                raise SetupError("the archive member has an unexpected size. Nothing was written.")
            data = archive.read(info)
    except (KeyError, zipfile.BadZipFile) as exc:
        raise SetupError(
            f"the archive is not the expected release file: {type(exc).__name__}: {exc}"
        ) from exc
    binary_digest = hashlib.sha256(data).hexdigest()
    if binary_digest != build["binary_sha256"]:
        raise SetupError(
            f"checksum mismatch on the unpacked compiler (got {binary_digest[:16]}..., expected "
            f"{build['binary_sha256'][:16]}...). Nothing was written."
        )

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.{os.urandom(4).hex()}.tmp")
    try:
        tmp.write_bytes(data)
        os.chmod(tmp, 0o700)
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            tmp.unlink()

    return {
        "installed": True,
        "already_present": False,
        "downloaded": True,
        "path": str(target),
        "sha256": binary_digest,
        "bytes": len(data),
        "source": build["url"],
        "release": RELEASE,
        "compiler": env._compiler_status(),
    }
