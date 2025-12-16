"""
bubblepy - Bubblewrap sandboxing for Python

A drop-in replacement for subprocess.run() that executes commands in a
bubblewrap sandbox, blocking access to secrets and limiting filesystem access.

Usage:
    from bubblepy import run, Sandbox
    
    # Simple - run a command with default protections
    result = run("ls -la", cwd="/home/user/project")
    
    # With explicit read-write access
    result = run("python script.py", rw=["/home/user/project"])
    
    # Configure and reuse
    sb = Sandbox(rw=["/home/user/project"], network=True)
    result = sb.run("npm install")
    result = sb.run("npm test")

For MCP tools / Aider integration:
    from bubblepy import patch_subprocess
    patch_subprocess()  # Now subprocess.run() is sandboxed
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__version__ = "1.0.0"
__all__ = ["Sandbox", "run", "check_output", "patch_subprocess", "SandboxError"]


class SandboxError(Exception):
    """Raised when sandbox cannot be configured or executed."""
    pass


# Paths that are ALWAYS blocked (overlaid with empty tmpfs)
SECRET_PATHS = [
    # SSH and GPG keys
    ".ssh", ".gnupg", ".pki",
    # Cloud provider credentials
    ".aws", ".azure", ".gcloud", ".config/gcloud",
    # Container/orchestration
    ".kube", ".docker", ".helm",
    # Package manager tokens
    ".npmrc", ".yarnrc", ".pypirc", ".netrc",
    ".gem/credentials", ".cargo/credentials", ".cargo/credentials.toml",
    ".composer/auth.json",
    # Password managers
    ".password-store", ".local/share/keyrings",
    ".config/op", ".config/keybase",
    # CLI tokens  
    ".config/gh", ".config/hub", ".config/netlify",
    ".config/heroku", ".config/doctl",
    # Browsers (cookies, passwords)
    ".mozilla", ".config/google-chrome", ".config/chromium",
    ".config/BraveSoftware", ".config/vivaldi",
    # Generic secrets
    ".secrets", ".credentials", ".private",
    # History files (can leak secrets in commands)
    ".bash_history", ".zsh_history", ".python_history",
    ".psql_history", ".mysql_history", ".node_repl_history",
]

# System paths that cannot be written to
FORBIDDEN_WRITE = [
    "/", "/bin", "/boot", "/etc", "/lib", "/lib64", "/lib32",
    "/opt", "/root", "/sbin", "/sys", "/usr", "/var",
]


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
    ro: list[str] = field(default_factory=list)
    rw: list[str] = field(default_factory=list)
    network: bool = False
    gpu: bool = False
    share_home: bool = False
    env: dict[str, str] = field(default_factory=dict)
    env_passthrough: list[str] = field(default_factory=list)
    allow_secrets: list[str] = field(default_factory=list)
    timeout: float | None = None
    cwd: str | None = None
    
    # Internal
    _bwrap_path: str | None = field(default=None, repr=False)
    
    def __post_init__(self):
        self._bwrap_path = shutil.which("bwrap")
        if not self._bwrap_path:
            raise SandboxError(
                "bubblewrap (bwrap) not found. Install with: apt install bubblewrap"
            )
    
    def _resolve_path(self, path: str) -> str:
        """Expand ~ and resolve to absolute path."""
        return str(Path(path).expanduser().resolve())
    
    def _validate_rw_path(self, path: str) -> str:
        """Validate that a path can be mounted read-write."""
        resolved = self._resolve_path(path)
        for forbidden in FORBIDDEN_WRITE:
            if resolved == forbidden or resolved.startswith(forbidden + "/"):
                # Exception: allow if it's a user-owned subdir
                if forbidden in ("/var", "/opt"):
                    try:
                        if os.access(path, os.W_OK) and os.stat(path).st_uid == os.getuid():
                            return resolved
                    except OSError:
                        pass
                raise SandboxError(f"Write access to '{resolved}' is forbidden (system path)")
        return resolved
    
    def _build_bwrap_args(self, command: str, cwd: str | None = None) -> list[str]:
        """Build the bwrap command line arguments."""
        args = [self._bwrap_path]
        home = os.environ.get("HOME", "/tmp")
        
        # === Namespace isolation ===
        args.extend([
            "--unshare-user", "--unshare-pid", "--unshare-uts",
            "--unshare-ipc", "--unshare-cgroup"
        ])
        if not self.network:
            args.append("--unshare-net")
        
        # === Security ===
        args.extend([
            "--cap-drop", "ALL",
            "--no-new-privs",
            "--new-session",
            "--die-with-parent",
            "--hostname", "sandbox",
        ])
        
        # === /proc and /dev ===
        args.extend(["--proc", "/proc", "--dev", "/dev"])
        for dev in ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty"]:
            if os.path.exists(dev):
                args.extend(["--dev-bind-try", dev, dev])
        
        # === Base system (read-only) ===
        for d in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32"]:
            if os.path.isdir(d):
                args.extend(["--ro-bind", d, d])
        
        # === Essential /etc files ===
        etc_files = [
            "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/passwd", "/etc/group",
            "/etc/hosts", "/etc/resolv.conf", "/etc/localtime",
            "/etc/ssl", "/etc/ca-certificates", "/etc/terminfo", "/etc/alternatives",
        ]
        for f in etc_files:
            if os.path.exists(f):
                args.extend(["--ro-bind-try", f, f])
        
        # === Ephemeral mounts ===
        args.extend(["--tmpfs", "/tmp", "--tmpfs", "/var/tmp", "--tmpfs", "/run"])
        
        # === Home directory ===
        if self.share_home:
            args.extend(["--ro-bind", home, home])
            # Block secrets by overlaying with tmpfs
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
        
        # === User-specified mounts ===
        for path in self.ro:
            resolved = self._resolve_path(path)
            if os.path.exists(resolved):
                args.extend(["--ro-bind", resolved, resolved])
        
        for path in self.rw:
            resolved = self._validate_rw_path(path)
            if os.path.exists(resolved):
                args.extend(["--bind", resolved, resolved])
        
        # === GPU access ===
        if self.gpu:
            if os.path.isdir("/dev/dri"):
                args.extend(["--dev-bind", "/dev/dri", "/dev/dri"])
            # NVIDIA
            import glob
            for nv in glob.glob("/dev/nvidia*"):
                args.extend(["--dev-bind", nv, nv])
        
        # === Environment ===
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
        
        # Pass through requested env vars
        for var in self.env_passthrough:
            if var in os.environ:
                env_vars[var] = os.environ[var]
        
        # Add user-specified env vars
        env_vars.update(self.env)
        
        for key, value in env_vars.items():
            args.extend(["--setenv", key, value])
        
        # === Working directory ===
        workdir = cwd or self.cwd
        if not workdir:
            # Auto-detect best working directory
            if self.rw:
                workdir = self._resolve_path(self.rw[0])
            elif self.ro:
                workdir = self._resolve_path(self.ro[0])
            else:
                workdir = "/tmp"
        else:
            workdir = self._resolve_path(workdir)
        args.extend(["--chdir", workdir])
        
        # === Command ===
        args.extend(["--", "sh", "-c", command])
        
        return args
    
    def run(
        self,
        command: str,
        *,
        capture_output: bool = False,
        text: bool = True,
        check: bool = False,
        cwd: str | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess:
        """
        Run a command in the sandbox.
        
        This is a drop-in replacement for subprocess.run() with sandboxing.
        
        Args:
            command: Shell command to execute
            capture_output: Capture stdout/stderr
            text: Return strings instead of bytes
            check: Raise on non-zero exit
            cwd: Working directory (overrides sandbox default)
            timeout: Timeout in seconds (overrides sandbox default)
            **kwargs: Additional arguments passed to subprocess.run()
        
        Returns:
            subprocess.CompletedProcess with the result
        """
        bwrap_args = self._build_bwrap_args(command, cwd=cwd)
        
        effective_timeout = timeout if timeout is not None else self.timeout
        
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
        cwd: str | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> str | bytes:
        """
        Run command and return its output.
        
        Raises subprocess.CalledProcessError on non-zero exit.
        """
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
        cwd: str | None = None,
        **kwargs: Any,
    ) -> subprocess.Popen:
        """
        Start a sandboxed process without waiting.
        
        Returns a Popen object for the sandboxed process.
        """
        bwrap_args = self._build_bwrap_args(command, cwd=cwd)
        return subprocess.Popen(bwrap_args, **kwargs)


# === Convenience functions ===

# Default sandbox instance (configured for safety)
_default_sandbox: Sandbox | None = None


def _get_default_sandbox(**kwargs) -> Sandbox:
    """Get or create the default sandbox with given overrides."""
    global _default_sandbox
    if kwargs or _default_sandbox is None:
        return Sandbox(**kwargs)
    return _default_sandbox


def run(
    command: str,
    *,
    ro: list[str] | None = None,
    rw: list[str] | None = None,
    network: bool = False,
    share_home: bool = False,
    env: dict[str, str] | None = None,
    env_passthrough: list[str] | None = None,
    capture_output: bool = False,
    text: bool = True,
    check: bool = False,
    cwd: str | None = None,
    timeout: float | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """
    Run a command in a sandbox.
    
    This is the simplest way to run a sandboxed command:
    
        from bubblepy import run
        result = run("ls -la", rw=["/home/user/project"])
    
    Args:
        command: Shell command to execute
        ro: Paths to mount read-only
        rw: Paths to mount read-write
        network: Allow network access
        share_home: Mount $HOME read-only (secrets blocked)
        env: Environment variables to set
        env_passthrough: Environment variables to pass from host
        capture_output: Capture stdout/stderr
        text: Return strings instead of bytes
        check: Raise on non-zero exit
        cwd: Working directory
        timeout: Timeout in seconds
    
    Returns:
        subprocess.CompletedProcess
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
    ro: list[str] | None = None,
    rw: list[str] | None = None,
    network: bool = False,
    text: bool = True,
    cwd: str | None = None,
    timeout: float | None = None,
    **kwargs: Any,
) -> str | bytes:
    """
    Run a sandboxed command and return its output.
    
    Raises subprocess.CalledProcessError on non-zero exit.
    """
    sb = Sandbox(
        ro=ro or [],
        rw=rw or [],
        network=network,
        cwd=cwd,
        timeout=timeout,
    )
    return sb.check_output(command, text=text, **kwargs)


# === Subprocess monkey-patching for integration ===

_original_subprocess_run = subprocess.run
_original_subprocess_popen = subprocess.Popen
_patched = False
_patch_config: dict[str, Any] = {}


def patch_subprocess(
    *,
    rw: list[str] | None = None,
    network: bool = False,
    share_home: bool = True,
    env_passthrough: list[str] | None = None,
    allow_secrets: list[str] | None = None,
) -> None:
    """
    Monkey-patch subprocess.run() to use sandboxing.
    
    After calling this, all subprocess.run() calls with shell=True
    will be sandboxed automatically.
    
    Example:
        from bubblepy import patch_subprocess
        patch_subprocess(rw=["/home/user/project"], network=True)
        
        # Now this is sandboxed:
        subprocess.run("rm -rf /", shell=True)  # Blocked!
    
    Args:
        rw: Paths to mount read-write
        network: Allow network access  
        share_home: Mount $HOME read-only with secrets blocked
        env_passthrough: Environment variables to pass through
        allow_secrets: Secret paths to allow (e.g., [".gnupg"])
    """
    global _patched, _patch_config
    
    if _patched:
        return
    
    _patch_config = {
        "rw": rw or [],
        "network": network,
        "share_home": share_home,
        "env_passthrough": env_passthrough or [
            # Common API keys for aider/MCP
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
            "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY",
            # Git
            "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
            # Terminal
            "TERM", "COLORTERM",
        ],
        "allow_secrets": allow_secrets or [],
    }
    
    def sandboxed_run(args, **kwargs):
        # Only sandbox shell commands
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
        from bubblepy import create_aider_sandbox
        
        sb = create_aider_sandbox("/home/user/myproject")
        result = sb.run("aider --message 'add docstrings'")
    
    Args:
        project_dir: The project directory to work in (read-write)
        network: Allow network for API calls (default: True)
        allow_gpg: Allow GPG for signed commits (default: False)
    
    Returns:
        Configured Sandbox instance
    """
    allow_secrets = [".gnupg"] if allow_gpg else []
    
    return Sandbox(
        rw=[project_dir],
        network=network,
        share_home=True,
        env_passthrough=[
            # API keys
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
            "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY", "GEMINI_API_KEY",
            # Git identity
            "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
            # Terminal
            "TERM", "COLORTERM", "CLICOLOR", "FORCE_COLOR",
            # Aider config
            "AIDER_MODEL", "AIDER_DARK_MODE", "AIDER_AUTO_COMMITS",
        ],
        allow_secrets=allow_secrets,
    )


# === CLI interface ===

def main():
    """Simple CLI for testing the sandbox."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Run a command in a bubblewrap sandbox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bubblepy.py --rw ~/project -- ls -la
  python bubblepy.py --network --rw ~/project -- curl https://example.com
  python bubblepy.py --share-home -- grep -r "TODO" ~/code
        """,
    )
    parser.add_argument("--ro", action="append", default=[], help="Read-only mount")
    parser.add_argument("--rw", action="append", default=[], help="Read-write mount")
    parser.add_argument("--network", action="store_true", help="Allow network")
    parser.add_argument("--share-home", action="store_true", help="Share home (secrets blocked)")
    parser.add_argument("--timeout", type=float, help="Timeout in seconds")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run")
    
    args = parser.parse_args()
    
    if not args.command or args.command[0] == "--":
        args.command = args.command[1:] if args.command else []
    
    if not args.command:
        parser.error("No command specified")
    
    command = " ".join(args.command)
    
    try:
        sb = Sandbox(
            ro=args.ro,
            rw=args.rw,
            network=args.network,
            share_home=args.share_home,
            timeout=args.timeout,
        )
        result = sb.run(command)
        raise SystemExit(result.returncode)
    except SandboxError as e:
        print(f"Sandbox error: {e}", file=__import__("sys").stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
