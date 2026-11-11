"""Process isolation for the compiler.

There is one mode: bubblewrap. If bubblewrap is missing or cannot build the
namespace, the run is REFUSED rather than executed on the host with the user's
own filesystem and network. A silent fallback to "run it anyway" is exactly the
failure this module exists to prevent.

What the sandbox gives the child: its own network, pid, ipc, uts, user and
cgroup namespaces; a read-only root (remounted after the mounts are created); a
tmpfs /tmp and a tmpfs $HOME that hold nothing and survive nothing; the compiler
bound read-only at /usr/bin/cherri; and exactly one writable path, the job
directory, bound at /job.

Measured on this host: `bwrap ... --unshare-all` with the compiler bound at
/usr/bin/cherri compiles a source and returns rc=0, and a source that tries to
write outside /job now fails with "read-only file system".
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

from . import env

# Where the compiler lands inside the sandbox.
_EXEC = "/usr/bin/cherri"


class SandboxUnavailable(RuntimeError):
    """No usable bubblewrap: Talaria refuses to run the compiler on the host."""


def available() -> bool:
    return shutil.which("bwrap") is not None


def _bwrap_argv(
    args: list[str],
    jobdir: str,
    executable: str,
    allow_network: bool,
    minimal: bool,
) -> list[str]:
    argv = [
        shutil.which("bwrap") or "bwrap",
        "--unshare-all",                    # net, pid, ipc, uts, user, cgroup...
        "--die-with-parent",
        "--new-session",
        "--cap-drop", "ALL",
    ]
    if allow_network:
        # --unshare-all removed the net namespace; put it back for signing only.
        argv.append("--share-net")
    if minimal:
        # Only the compiler binary, the job dir, and two empty tmpfs are visible.
        argv += [
            "--ro-bind", executable, _EXEC,
            "--bind", jobdir, "/job",
            "--tmpfs", "/tmp",
            "--tmpfs", "/home",
            "--chdir", "/job",
            "--proc", "/proc",
            "--dev", "/dev",
        ]
        if allow_network:
            # The signer speaks HTTPS to a hostname: without the resolver config and the
            # CA bundle every attempt dies at DNS/TLS setup.
            for path in ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
                         "/etc/ssl", "/etc/ca-certificates", "/etc/pki"):
                argv += ["--ro-bind-try", path, path]
        argv += [
            # After the mounts, close the whole root read-only. The compiler can then
            # only write in /job (and in the two tmpfs, which vanish with the process).
            "--remount-ro", "/",
            "--clearenv",
            "--setenv", "HOME", "/home",
            _EXEC,
        ]
    else:
        # A helper binary (curl in the isolation test, a decoder) with read-only system
        # dirs at their real paths. Never `--ro-bind / /`: on a read-only root bwrap
        # cannot create the /job mount point, measured as "can't create file /job:
        # read-only file system".
        argv += [
            "--ro-bind", "/usr", "/usr",
            "--ro-bind-try", "/bin", "/bin",
            "--ro-bind-try", "/sbin", "/sbin",
            "--ro-bind-try", "/lib", "/lib",
            "--ro-bind-try", "/lib64", "/lib64",
            "--ro-bind-try", "/etc", "/etc",
            "--tmpfs", "/home",
            "--dir", "/job",
            "--bind", jobdir, "/job",
            "--chdir", "/job",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
            "--clearenv",
            "--setenv", "HOME", "/home",
            "--setenv", "PATH", "/usr/bin:/bin",
            executable,
        ]
    return argv + list(args)


def run(
    args: list[str],
    jobdir: str | os.PathLike,
    allow_network: bool = False,
    timeout: float = 20.0,
    executable: str | None = None,
) -> dict:
    """Run `executable args...` isolated, cwd=/job (the job directory).

    Returns {rc, stdout, stderr, elapsed, isolation, argv, no_isolation}.
    `isolation` is always "bwrap" and `no_isolation` always False: a run that
    could not be isolated raises SandboxUnavailable instead of returning.
    """
    jobdir = str(Path(jobdir).resolve())
    if not os.path.isdir(jobdir):
        raise FileNotFoundError(f"job dir does not exist: {jobdir}")

    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise SandboxUnavailable(
            "bubblewrap (bwrap) is not installed, so Talaria will not run the compiler: "
            "it refuses to execute a compiler on your machine without a namespace around it. "
            "Install it with your package manager (package 'bubblewrap', in Debian/Ubuntu, "
            "Fedora, Arch) and retry, or run talaria_status to confirm the sandbox state."
        )

    compiler = env.compiler_path()
    exe = executable or (str(compiler) if compiler else None)
    if exe is None:
        raise RuntimeError("no executable to run: compiler not found")
    if executable is None:
        env.assert_pinned_compiler(exe)

    # minimal mode only when we are running the compiler itself
    minimal = executable is None
    argv = _bwrap_argv(args, jobdir, exe, allow_network, minimal)
    started = time.monotonic()
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    if proc.returncode != 0 and (proc.stderr or "").lstrip().startswith("bwrap:"):
        raise SandboxUnavailable(
            f"bubblewrap could not build the sandbox: {(proc.stderr or '').strip()[:300]}"
        )

    return {
        "rc": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
        "elapsed": round(time.monotonic() - started, 3),
        "isolation": "bwrap",
        "argv": argv,
        "no_isolation": False,
    }
