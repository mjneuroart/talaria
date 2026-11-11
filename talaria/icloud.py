"""Read a public iCloud shortcut link, so it can be audited before it is installed.

One link shape is accepted: https://www.icloud.com/shortcuts/<32 hex digits>. Two hosts are
contacted, both Apple's: www.icloud.com for the public record, then the *.icloud-content.com
host that record names for the file. Only GET requests are made, with no cookie and no
account; nothing about the user or the machine is sent. A record that points anywhere else is
refused before any download.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

LINK_RE = re.compile(r"^https://www\.icloud\.com/shortcuts/([0-9a-fA-F]{32})/?(?:[?#].*)?$")
RECORD_URL = "https://www.icloud.com/shortcuts/api/records/"
MAX_RECORD_BYTES = 512_000
MAX_FILE_BYTES = 32 * 1024 * 1024
USER_AGENT = "talaria-audit (Hermes plugin; read-only)"

#: Record field -> file name Apple expects in the download URL template. The signed file is
#: tried first because it is what a phone installs.
ASSETS = (("signedShortcut", "signed.shortcut"), ("shortcut", "shortcut.plist"))


class LinkError(ValueError):
    """The link is not a public iCloud shortcut link, or Apple did not serve a shortcut for it."""


def is_link(text: str) -> bool:
    return isinstance(text, str) and LINK_RE.match(text.strip()) is not None


def record_id(link: str) -> str:
    match = LINK_RE.match((link or "").strip())
    if not match:
        raise LinkError(
            "not a public iCloud shortcut link: expected https://www.icloud.com/shortcuts/ "
            "followed by 32 hexadecimal digits"
        )
    return match.group(1).lower()


def _host(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()


def record_host(url: str) -> bool:
    return urllib.parse.urlsplit(url).scheme == "https" and _host(url) == "www.icloud.com"


def content_host(url: str) -> bool:
    return urllib.parse.urlsplit(url).scheme == "https" and _host(url).endswith(".icloud-content.com")


class _AppleRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only when it stays on one of the two Apple hosts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not (record_host(newurl) or content_host(newurl)):
            raise LinkError(f"refused a redirect to {_host(newurl)!r}: not an Apple iCloud host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url: str, limit: int) -> bytes:
    opener = urllib.request.build_opener(_AppleRedirects)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with opener.open(request, timeout=25) as response:
            blob = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        raise LinkError(f"Apple answered HTTP {exc.code} for this link") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise LinkError(f"could not reach Apple: {type(exc).__name__}: {exc}") from exc
    if len(blob) > limit:
        raise LinkError(f"the answer is larger than {limit} bytes; not kept")
    return blob


def fetch(link: str) -> dict:
    """Download the shortcut behind a public link. Returns its bytes and the record facts."""
    rid = record_id(link)
    raw = _get(RECORD_URL + rid, MAX_RECORD_BYTES)
    try:
        record = json.loads(raw)
    except ValueError as exc:
        raise LinkError("Apple did not return a shortcut record for this link") from exc
    fields = record.get("fields") if isinstance(record, dict) else None
    if not isinstance(fields, dict):
        raise LinkError("Apple did not return a shortcut record for this link")

    def value(key: str):
        entry = fields.get(key)
        return entry.get("value") if isinstance(entry, dict) else None

    name = value("name")
    status = value("signingStatus")
    for field, filename in ASSETS:
        asset = value(field)
        url = asset.get("downloadURL") if isinstance(asset, dict) else None
        if not isinstance(url, str) or not url:
            continue
        url = url.replace("${f}", filename)
        if not content_host(url):
            raise LinkError(
                f"the record points at {_host(url)!r}, which is not an Apple iCloud content host; "
                "nothing was downloaded"
            )
        blob = _get(url, MAX_FILE_BYTES)
        if not blob:
            raise LinkError("Apple served an empty file for this link")
        return {
            "blob": blob,
            "link": "https://www.icloud.com/shortcuts/" + rid,
            "name": name if isinstance(name, str) else None,
            "signing_status": status if isinstance(status, str) else None,
            "asset": field,
            "host": _host(url),
            "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
        }
    raise LinkError("the record holds no downloadable shortcut")
