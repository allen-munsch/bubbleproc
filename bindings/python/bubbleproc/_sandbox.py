"""
bubbleproc - Bubblewrap sandboxing for Python

Thin wrapper around the Rust core.
"""

from __future__ import annotations

import subprocess
import os
from dataclasses import dataclass, field
from typing import Any, Optional, List, Dict, Union

# Import Rust extension
from bubbleproc import _bubbleproc_rs as _rs

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


@dataclass
class Sandbox:
    """
    Configurable bubblewrap sandbox for subprocess execution.
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

    def __post_init__(self):
        try:
            self._rs_sandbox = _rs.Sandbox(
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
        except RuntimeError as e:
            raise SandboxError(str(e)) from e

    def run(
        self,
        command: str,
        *,
        capture_output: bool = False,
        text: bool = True,
        check: bool = False,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess:
        """Run a shell command in the sandbox."""
        try:
            exit_code, stdout, stderr = self._rs_sandbox.run(command)
        except RuntimeError as e:
            raise SandboxError(str(e)) from e

        if text:
            result = subprocess.CompletedProcess(
                args=command,
                returncode=exit_code,
                stdout=stdout,
                stderr=stderr,
            )
        else:
            result = subprocess.CompletedProcess(
                args=command,
                returncode=exit_code,
                stdout=stdout.encode('utf-8'),
                stderr=stderr.encode('utf-8'),
            )

        if check and exit_code != 0:
            raise subprocess.CalledProcessError(
                exit_code, command, output=result.stdout, stderr=result.stderr
            )

        return result

    def check_output(
        self,
        command: str,
        *,
        text: bool = True,
        **kwargs: Any,
    ) -> Union[str, bytes]:
        """Run command and return its output. Raises on non-zero exit."""
        result = self.run(command, capture_output=True, text=text, check=True, **kwargs)
        return result.stdout


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
    """Run a command in a sandbox."""
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
    **kwargs: Any,
) -> Union[str, bytes]:
    """Run a sandboxed command and return its output."""
    sb = Sandbox(
        ro=ro or [],
        rw=rw or [],
        network=network,
        cwd=cwd,
    )
    return sb.check_output(command, text=text, **kwargs)


# === Subprocess Patching ===

_original_subprocess_run = subprocess.run
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
    """Monkey-patch subprocess.run() to use sandboxing for shell commands."""
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
            )
        return _original_subprocess_run(args, **kwargs)

    subprocess.run = sandboxed_run
    _patched = True


def unpatch_subprocess() -> None:
    """Remove the subprocess monkey-patch."""
    global _patched
    subprocess.run = _original_subprocess_run
    _patched = False


def create_aider_sandbox(
    project_dir: str,
    *,
    network: bool = True,
    allow_gpg: bool = False,
) -> Sandbox:
    """Create a sandbox configured for Aider CLI usage."""
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
        ],
        allow_secrets=allow_secrets,
    )
