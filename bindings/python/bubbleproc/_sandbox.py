"""
Internal sandbox implementation.
Handles the high-level API, path resolution, and subprocess patching.
"""

from __future__ import annotations

import subprocess
import shlex
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, List, Dict, Union

# Import the Rust extension module (compiled by maturin)
try:
    from bubbleproc import _bubbleproc_rs as _rs
    RustSandbox = _rs.Sandbox
except ImportError:
    try:
        import bubbleproc_rs as _rs
        RustSandbox = _rs.Sandbox
    except ImportError:
        RustSandbox = None

__all__ = [
    "Sandbox",
    "SandboxError",
    "run",
    "check_output",
    "patch_subprocess",
    "unpatch_subprocess",
    "create_aider_sandbox",
]


class SandboxError(Exception):
    """Raised when sandbox cannot be configured or executed."""
    pass


# Paths that are ALWAYS blocked (overlaid with empty tmpfs)
SECRET_PATHS = [
    ".ssh", ".gnupg", ".pki",
    ".aws", ".azure", ".gcloud", ".config/gcloud",
    ".kube", ".docker", ".helm",
    ".npmrc", ".yarnrc", ".pypirc", ".netrc",
    ".gem/credentials", ".cargo/credentials", ".cargo/credentials.toml",
    ".composer/auth.json",
    ".password-store", ".local/share/keyrings",
    ".config/op", ".config/keybase",
    ".config/gh", ".config/hub", ".config/netlify",
    ".config/heroku", ".config/doctl",
    ".mozilla", ".config/google-chrome", ".config/chromium",
    ".config/BraveSoftware", ".config/vivaldi",
    ".secrets", ".credentials", ".private",
    ".bash_history", ".zsh_history", ".python_history",
    ".psql_history", ".mysql_history", ".node_repl_history",
]

# System paths that cannot be written to
FORBIDDEN_WRITE = [
    "/", "/bin", "/boot", "/etc", "/lib", "/lib64", "/lib32",
    "/opt", "/root", "/sbin", "/sys", "/usr", "/var",
]


def _resolve_path(path: str) -> str:
    """Expand ~ and resolve to absolute path."""
    return str(Path(path).expanduser().resolve())


def _validate_rw_path(path: str) -> str:
    """Validate that a path can be mounted read-write."""
    resolved = _resolve_path(path)
    for forbidden in FORBIDDEN_WRITE:
        if resolved == forbidden or resolved.startswith(forbidden + "/"):
            if forbidden in ("/var", "/opt"):
                try:
                    if os.access(path, os.W_OK) and os.stat(path).st_uid == os.getuid():
                        return resolved
                except OSError:
                    pass
            raise SandboxError(f"Write access to '{resolved}' is forbidden (system path)")
    return resolved


@dataclass
class Sandbox:
    """
    Configurable bubblewrap sandbox for subprocess execution.

    Args:
        ro: Paths to mount read-only (in addition to system paths)
        rw: Paths to mount read-write
        network: Allow network access (default: False)
        gpu: Allow GPU access (default: False)
        share_home: Mount $HOME read-only with secrets blocked (default: False)
        env: Additional environment variables
        env_passthrough: Environment variables to pass from host
        allow_secrets: Secret paths to allow (e.g., [".gnupg"] for signing)
        timeout: Command timeout in seconds
        cwd: Working directory for commands

    Example:
        sb = Sandbox(rw=["~/project"], network=True)
        result = sb.run("make test")
    """
    ro: List[str] = field(default_factory=list)
    rw: List[str] = field(default_factory=list)
    network: bool = False
    gpu: bool = False
    share_home: bool = False
    env: Dict[str, str] = field(default_factory=dict)
    env_passthrough: List[str] = field(default_factory=list)
    allow_secrets: List[str] = field(default_factory=list)
    timeout: Optional[float] = None
    cwd: Optional[str] = None

    _rs_sandbox: Any = field(init=False, repr=False, default=None)
    _use_rust: bool = field(init=False, repr=False, default=False)

    def __post_init__(self):
        # Check bwrap exists
        if not shutil.which("bwrap"):
            raise SandboxError(
                "bubblewrap (bwrap) not found. Install with: apt install bubblewrap"
            )

        # Validate rw paths
        for path in self.rw:
            _validate_rw_path(path)

        # Try to use Rust backend
        if RustSandbox is not None:
            try:
                self._rs_sandbox = RustSandbox(
                    ro=self.ro,
                    rw=self.rw,
                    network=self.network,
                    gpu=self.gpu,
                    share_home=self.share_home,
                    env=self.env,
                    env_passthrough=self.env_passthrough,
                    allow_secrets=self.allow_secrets,
                    cwd=self.cwd,
                )
                self._use_rust = True
            except Exception:
                self._use_rust = False

    def _build_bwrap_args(self, command: str, cwd: Optional[str] = None) -> List[str]:
        """Build the bwrap command line arguments (Python fallback)."""
        bwrap_path = shutil.which("bwrap")
        args = [bwrap_path]
        home = os.environ.get("HOME", "/tmp")

        # Namespace isolation
        args.extend([
            "--unshare-user", "--unshare-pid", "--unshare-uts",
            "--unshare-ipc", "--unshare-cgroup"
        ])
        if not self.network:
            args.append("--unshare-net")

        # Security
        args.extend([
            "--cap-drop", "ALL",
            "--no-new-privs",
            "--new-session",
            "--die-with-parent",
            "--hostname", "sandbox",
        ])

        # /proc and /dev
        args.extend(["--proc", "/proc", "--dev", "/dev"])
        for dev in ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty"]:
            if os.path.exists(dev):
                args.extend(["--dev-bind-try", dev, dev])

        # Base system (read-only)
        for d in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32"]:
            if os.path.isdir(d):
                args.extend(["--ro-bind", d, d])

        # Essential /etc files
        etc_files = [
            "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/passwd", "/etc/group",
            "/etc/hosts", "/etc/resolv.conf", "/etc/localtime",
            "/etc/ssl", "/etc/ca-certificates", "/etc/terminfo", "/etc/alternatives",
        ]
        for f in etc_files:
            if os.path.exists(f):
                args.extend(["--ro-bind-try", f, f])

        # Ephemeral mounts
        args.extend(["--tmpfs", "/tmp", "--tmpfs", "/var/tmp", "--tmpfs", "/run"])

        # Home directory
        if self.share_home:
            args.extend(["--ro-bind", home, home])
            for secret in SECRET_PATHS:
                if secret in self.allow_secrets:
                    continue
                secret_path = os.path.join(home, secret)
                if os.path.exists(secret_path):
                    args.extend(["--tmpfs", secret_path])
        else:
            args.extend([
                "--tmpfs", home,
                "--dir", f"{home}/.cache",
                "--dir", f"{home}/.config",
                "--dir", f"{home}/.local/share",
            ])

        # User-specified mounts
        for path in self.ro:
            resolved = _resolve_path(path)
            if os.path.exists(resolved):
                args.extend(["--ro-bind", resolved, resolved])

        for path in self.rw:
            resolved = _resolve_path(path)
            if os.path.exists(resolved):
                args.extend(["--bind", resolved, resolved])

        # GPU access
        if self.gpu:
            if os.path.isdir("/dev/dri"):
                args.extend(["--dev-bind", "/dev/dri", "/dev/dri"])
            import glob
            for nv in glob.glob("/dev/nvidia*"):
                args.extend(["--dev-bind", nv, nv])

        # Environment
        user = os.environ.get("USER", "sandbox")
        env_vars = {
            "HOME": home,
            "USER": user,
            "LOGNAME": user,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TERM": os.environ.get("TERM", "xterm-256color"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "TMPDIR": "/tmp",
        }

        for var in self.env_passthrough:
            if var in os.environ:
                env_vars[var] = os.environ[var]

        env_vars.update(self.env)

        for key, value in env_vars.items():
            args.extend(["--setenv", key, value])

        # Working directory
        workdir = cwd or self.cwd
        if not workdir:
            if self.rw:
                workdir = _resolve_path(self.rw[0])
            elif self.ro:
                workdir = _resolve_path(self.ro[0])
            else:
                workdir = "/tmp"
        else:
            workdir = _resolve_path(workdir)
        args.extend(["--chdir", workdir])

        # Command
        args.extend(["--", "sh", "-c", command])

        return args

    def run(
        self,
        command: str,
        *,
        capture_output: bool = False,
        text: bool = True,
        check: bool = False,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess:
        """
        Run a command in the sandbox.

        This is a drop-in replacement for subprocess.run() with sandboxing.
        """
        effective_timeout = timeout if timeout is not None else self.timeout

        if self._use_rust and self._rs_sandbox is not None:
            try:
                parts = shlex.split(command)
                if not parts:
                    raise ValueError("Command string is empty")

                cmd = parts[0]
                args = parts[1:]

                code, stdout, stderr = self._rs_sandbox.run(cmd, args)

                result = subprocess.CompletedProcess(
                    args=parts,
                    returncode=code,
                    stdout=stdout if text else stdout.encode('utf-8'),
                    stderr=stderr if text else stderr.encode('utf-8'),
                )

                if check and code != 0:
                    raise subprocess.CalledProcessError(
                        code, command, output=result.stdout, stderr=result.stderr
                    )

                return result

            except Exception as e:
                if "SecurityViolation" in str(e):
                    raise SandboxError(str(e)) from e
                # Fall through to Python implementation

        # Python fallback implementation
        bwrap_args = self._build_bwrap_args(command, cwd=cwd)

        return subprocess.run(
            bwrap_args,
            capture_output=capture_output,
            text=text,
            check=check,
            timeout=effective_timeout,
            **kwargs,
        )

    def check_output(
        self,
        command: str,
        *,
        text: bool = True,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> Union[str, bytes]:
        """Run command and return its output. Raises on non-zero exit."""
        result = self.run(
            command,
            capture_output=True,
            text=text,
            check=True,
            cwd=cwd,
            timeout=timeout,
            **kwargs,
        )
        return result.stdout

    def Popen(
        self,
        command: str,
        *,
        cwd: Optional[str] = None,
        **kwargs: Any,
    ) -> subprocess.Popen:
        """Start a sandboxed process without waiting."""
        bwrap_args = self._build_bwrap_args(command, cwd=cwd)
        return subprocess.Popen(bwrap_args, **kwargs)


# === Convenience functions ===

def run(
    command: str,
    *,
    ro: Optional[List[str]] = None,
    rw: Optional[List[str]] = None,
    network: bool = False,
    share_home: bool = False,
    env: Optional[Dict[str, str]] = None,
    env_passthrough: Optional[List[str]] = None,
    capture_output: bool = False,
    text: bool = True,
    check: bool = False,
    cwd: Optional[str] = None,
    timeout: Optional[float] = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """
    Run a command in a sandbox.

    Example:
        from bubbleproc import run
        result = run("ls -la", rw=["/home/user/project"])
    """
    sb = Sandbox(
        ro=ro or [],
        rw=rw or [],
        network=network,
        share_home=share_home,
        env=env or {},
        env_passthrough=env_passthrough or [],
        cwd=cwd,
        timeout=timeout,
    )
    return sb.run(
        command,
        capture_output=capture_output,
        text=text,
        check=check,
        **kwargs,
    )


def check_output(
    command: str,
    *,
    ro: Optional[List[str]] = None,
    rw: Optional[List[str]] = None,
    network: bool = False,
    text: bool = True,
    cwd: Optional[str] = None,
    timeout: Optional[float] = None,
    **kwargs: Any,
) -> Union[str, bytes]:
    """Run a sandboxed command and return its output."""
    sb = Sandbox(
        ro=ro or [],
        rw=rw or [],
        network=network,
        cwd=cwd,
        timeout=timeout,
    )
    return sb.check_output(command, text=text, **kwargs)


# === Subprocess monkey-patching ===

_original_subprocess_run = subprocess.run
_original_subprocess_popen = subprocess.Popen
_patched = False
_patch_config: Dict[str, Any] = {}


def patch_subprocess(
    *,
    rw: Optional[List[str]] = None,
    network: bool = False,
    share_home: bool = True,
    env_passthrough: Optional[List[str]] = None,
    allow_secrets: Optional[List[str]] = None,
) -> None:
    """
    Monkey-patch subprocess.run() to use sandboxing.

    After calling this, all subprocess.run() calls with shell=True
    will be sandboxed automatically.

    Example:
        from bubbleproc import patch_subprocess
        patch_subprocess(rw=["/home/user/project"], network=True)

        # Now this is sandboxed:
        subprocess.run("rm -rf /", shell=True)  # Blocked!
    """
    global _patched, _patch_config

    if _patched:
        return

    _patch_config = {
        "rw": rw or [],
        "network": network,
        "share_home": share_home,
        "env_passthrough": env_passthrough or [
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
            "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY",
            "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
            "TERM", "COLORTERM",
        ],
        "allow_secrets": allow_secrets or [],
    }

    def sandboxed_run(args, **kwargs):
        if kwargs.get("shell") and isinstance(args, str):
            sb = Sandbox(
                rw=_patch_config["rw"],
                network=_patch_config["network"],
                share_home=_patch_config["share_home"],
                env_passthrough=_patch_config["env_passthrough"],
                allow_secrets=_patch_config["allow_secrets"],
                cwd=kwargs.pop("cwd", None),
            )
            return sb.run(
                args,
                capture_output=kwargs.pop("capture_output", False),
                text=kwargs.pop("text", kwargs.pop("universal_newlines", False)),
                check=kwargs.pop("check", False),
                timeout=kwargs.pop("timeout", None),
                **{k: v for k, v in kwargs.items() if k not in ("shell",)},
            )
        return _original_subprocess_run(args, **kwargs)

    subprocess.run = sandboxed_run
    _patched = True


def unpatch_subprocess() -> None:
    """Remove the subprocess monkey-patch."""
    global _patched
    subprocess.run = _original_subprocess_run
    _patched = False


# === Aider integration helper ===

def create_aider_sandbox(
    project_dir: str,
    *,
    network: bool = True,
    allow_gpg: bool = False,
) -> Sandbox:
    """
    Create a sandbox configured for Aider CLI usage.

    Example:
        from bubbleproc import create_aider_sandbox

        sb = create_aider_sandbox("/home/user/myproject")
        result = sb.run("aider --message 'add docstrings'")
    """
    allow_secrets = [".gnupg"] if allow_gpg else []

    return Sandbox(
        rw=[project_dir],
        network=network,
        share_home=True,
        env_passthrough=[
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
            "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY", "GEMINI_API_KEY",
            "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
            "TERM", "COLORTERM", "CLICOLOR", "FORCE_COLOR",
            "AIDER_MODEL", "AIDER_DARK_MODE", "AIDER_AUTO_COMMITS",
        ],
        allow_secrets=allow_secrets,
    )