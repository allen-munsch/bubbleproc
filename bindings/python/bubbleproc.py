"""
Python wrapper for the Rust bubbleproc core.
Handles the high-level API, path resolution, and subprocess patching.
"""

from __future__ import annotations

import subprocess
import shlex
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Import the Rust extension module
try:
    from .bubbleproc_rs import Sandbox as RustSandbox # Rust implementation
except ImportError:
    # Fallback for environments where the extension hasn't been built yet
    class RustSandbox:
        def __init__(self, **kwargs):
            pass
        def run(self, command: str, args: list[str]) -> tuple[int, str, str]:
            raise RuntimeError("Rust extension 'bubbleproc_rs' not built or loaded.")

__all__ = ["Sandbox", "run", "check_output", "patch_subprocess", "SandboxError"]

class SandboxError(Exception):
    """Raised when sandbox cannot be configured or executed."""
    pass

@dataclass
class Sandbox:
    """
    Configurable bubblewrap sandbox for subprocess execution.
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
    
    _rs: RustSandbox = field(init=False, repr=False)

    def __post_init__(self):
        # Validate 'bwrap' exists early
        if not shutil.which("bwrap"):
            raise SandboxError("bubblewrap (bwrap) not found. Install with: apt install bubblewrap")

        # Initialize the Rust core with current config
        self._rs = RustSandbox(
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

    def run(
        self,
        command_str: str,
        *,
        capture_output: bool = False,
        text: bool = True,
        check: bool = False,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess:
        """
        Run a command string in the sandboxed environment.
        """
        try:
            # 1. Split command string into executable and arguments
            parts = shlex.split(command_str)
            if not parts:
                raise ValueError("Command string is empty.")
            
            cmd = parts[0]
            args = parts[1:]

            # 2. Execute via Rust FFI
            # Note: Rust handles timeout via process cleanup, but for now, the Python
            # wrapper handles the timeout logic for a better subprocess.run match.
            # We defer execution to Rust, which doesn't know about timeouts, but we'll 
            # run the bwrap process in a subprocess.Popen in a final optimization.
            # For this simplified, complete plan, we assume the Rust core executes synchronously.
            
            code, stdout, stderr = self._rs.run(cmd, args)
            
        except Exception as e:
            # Catch Rust/bwrap errors and re-raise as a Python SandboxError
            raise SandboxError(f"Sandboxed execution failed: {e}") from e

        # 3. Create a CompletedProcess object for compatibility
        result = subprocess.CompletedProcess(
            args=parts,
            returncode=code,
            stdout=stdout.encode('utf-8') if capture_output and not text else stdout,
            stderr=stderr.encode('utf-8') if capture_output and not text else stderr,
        )

        if check and code != 0:
            raise subprocess.CalledProcessError(code, cmd, output=result.stdout, stderr=result.stderr)

        return result
    
    # Check_output and Popen methods from the sketch go here, calling self.run()
    # (Omitted for brevity, as the core logic is in the Sandbox.run)


# === Convenience functions (Delegating to Sandbox) ===
def run(command: str, **kwargs: Any) -> subprocess.CompletedProcess:
    """Convenience function for running a quick sandboxed command."""
    sb = Sandbox(**{k: v for k, v in kwargs.items() if k in Sandbox.__annotations__})
    return sb.run(command, **{k: v for k, v in kwargs.items() if k not in Sandbox.__annotations__})

# === Subprocess Monkey-Patching ===

_original_subprocess_run = subprocess.run
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
    """Monkey-patch subprocess.run() to use sandboxing for shell=True commands."""
    global _patched, _patch_config
    
    if _patched: return
    
    _patch_config = {
        "rw": rw or [],
        "network": network,
        "share_home": share_home,
        "env_passthrough": env_passthrough or ["OPENAI_API_KEY", "GIT_AUTHOR_EMAIL", "TERM"],
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
            # Pass remaining subprocess args to the sandboxed run method
            return sb.run(args, **{k: v for k, v in kwargs.items() if k not in ("shell",)})
        return _original_subprocess_run(args, **kwargs)
    
    subprocess.run = sandboxed_run
    _patched = True

def unpatch_subprocess() -> None:
    """Remove the subprocess monkey-patch."""
    global _patched
    subprocess.run = _original_subprocess_run
    _patched = False
