"""Talaria: compile + sign Apple Shortcuts from Linux, without a Mac.

Public surface is intentionally small; every fact returned by this package is
measured at call time (never a constant baked into the code).
"""

from . import aea, compile, env, sandbox, sign  # noqa: F401
from . import inspect as audit  # noqa: F401  (lane B: AUDIT engine)
from .compile import BuildError, prefilter  # noqa: F401
from .inspect import InspectError, inspect_shortcut  # noqa: F401
from .lzfse import LZFSEError, decompress  # noqa: F401
from .sign import SignError, SignRefused  # noqa: F401

__all__ = [
    "aea",
    "compile",
    "env",
    "sandbox",
    "sign",
    "audit",
    "BuildError",
    "SignError",
    "SignRefused",
    "InspectError",
    "LZFSEError",
    "prefilter",
    "inspect_shortcut",
    "decompress",
]
__version__ = "0.1.0"
