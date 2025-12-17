"""
bubbleproc - Bubblewrap sandboxing for Python

Thin wrapper around the Rust core with comprehensive subprocess patching.
"""

from __future__ import annotations

import subprocess
import shlex
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Optional, List, Dict, Union, Sequence, Mapping, IO
from threading import Thread
from queue import Queue

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
    "is_patched",
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
        input: Optional[Union[str, bytes]] = None,
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
                stdout=stdout if capture_output else "",
                stderr=stderr if capture_output else "",
            )
        else:
            result = subprocess.CompletedProcess(
                args=command,
                returncode=exit_code,
                stdout=stdout.encode('utf-8') if capture_output else b"",
                stderr=stderr.encode('utf-8') if capture_output else b"",
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


# === Helper Functions ===

def _args_to_shell_command(args: Union[str, Sequence[str]]) -> str:
    """Convert args to a shell command string."""
    if isinstance(args, str):
        return args
    return shlex.join(args)


def _is_shell_command(args, shell: bool) -> bool:
    """Check if this is a shell command that should be sandboxed."""
    return shell and isinstance(args, str)


def _should_sandbox(args, shell: bool, env: Optional[Mapping] = None) -> bool:
    """
    Determine if a subprocess call should be sandboxed.
    
    We sandbox when:
    - shell=True and args is a string (shell command)
    - OR args is a list but shell=True
    
    We don't sandbox when:
    - shell=False (direct executable, safer)
    - Explicitly disabled via env
    """
    if env and env.get("BUBBLEPROC_DISABLE"):
        return False
    return shell


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

# Store all original functions
_originals: Dict[str, Any] = {}
_patched = False
_patch_config: Dict[str, Any] = {}


def _get_sandbox() -> Sandbox:
    """Create a sandbox with current patch config."""
    return Sandbox(
        rw=_patch_config.get("rw", []),
        network=_patch_config.get("network", False),
        share_home=_patch_config.get("share_home", True),
        env_passthrough=_patch_config.get("env_passthrough", []),
        allow_secrets=_patch_config.get("allow_secrets", []),
    )


def _create_sandboxed_run():
    """Create a sandboxed version of subprocess.run."""
    original_run = _originals["run"]
    
    def sandboxed_run(
        args,
        bufsize=-1,
        executable=None,
        stdin=None,
        stdout=None,
        stderr=None,
        preexec_fn=None,
        close_fds=True,
        shell=False,
        cwd=None,
        env=None,
        universal_newlines=None,
        startupinfo=None,
        creationflags=0,
        restore_signals=True,
        start_new_session=False,
        pass_fds=(),
        *,
        capture_output=False,
        timeout=None,
        check=False,
        encoding=None,
        errors=None,
        text=None,
        input=None,
        **kwargs,
    ):
        # Determine if we should use text mode
        use_text = text or universal_newlines or encoding or errors
        
        # Only sandbox shell commands
        if _should_sandbox(args, shell, env):
            command = _args_to_shell_command(args)
            sb = Sandbox(
                rw=_patch_config.get("rw", []),
                network=_patch_config.get("network", False),
                share_home=_patch_config.get("share_home", True),
                env_passthrough=_patch_config.get("env_passthrough", []),
                allow_secrets=_patch_config.get("allow_secrets", []),
                cwd=cwd,
            )
            return sb.run(
                command,
                capture_output=capture_output,
                text=bool(use_text),
                check=check,
                timeout=timeout,
                input=input,
            )
        
        # Not a shell command - use original
        return original_run(
            args,
            bufsize=bufsize,
            executable=executable,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            preexec_fn=preexec_fn,
            close_fds=close_fds,
            shell=shell,
            cwd=cwd,
            env=env,
            universal_newlines=universal_newlines,
            startupinfo=startupinfo,
            creationflags=creationflags,
            restore_signals=restore_signals,
            start_new_session=start_new_session,
            pass_fds=pass_fds,
            capture_output=capture_output,
            timeout=timeout,
            check=check,
            encoding=encoding,
            errors=errors,
            text=text,
            input=input,
            **kwargs,
        )
    
    return sandboxed_run


def _create_sandboxed_call():
    """Create a sandboxed version of subprocess.call."""
    original_call = _originals["call"]
    
    def sandboxed_call(args, *, timeout=None, **kwargs):
        shell = kwargs.get("shell", False)
        env = kwargs.get("env")
        
        if _should_sandbox(args, shell, env):
            command = _args_to_shell_command(args)
            cwd = kwargs.pop("cwd", None)
            sb = Sandbox(
                rw=_patch_config.get("rw", []),
                network=_patch_config.get("network", False),
                share_home=_patch_config.get("share_home", True),
                env_passthrough=_patch_config.get("env_passthrough", []),
                allow_secrets=_patch_config.get("allow_secrets", []),
                cwd=cwd,
            )
            result = sb.run(command, capture_output=False, timeout=timeout)
            return result.returncode
        
        return original_call(args, timeout=timeout, **kwargs)
    
    return sandboxed_call


def _create_sandboxed_check_call():
    """Create a sandboxed version of subprocess.check_call."""
    original_check_call = _originals["check_call"]
    
    def sandboxed_check_call(args, *, timeout=None, **kwargs):
        shell = kwargs.get("shell", False)
        env = kwargs.get("env")
        
        if _should_sandbox(args, shell, env):
            command = _args_to_shell_command(args)
            cwd = kwargs.pop("cwd", None)
            sb = Sandbox(
                rw=_patch_config.get("rw", []),
                network=_patch_config.get("network", False),
                share_home=_patch_config.get("share_home", True),
                env_passthrough=_patch_config.get("env_passthrough", []),
                allow_secrets=_patch_config.get("allow_secrets", []),
                cwd=cwd,
            )
            result = sb.run(command, capture_output=False, check=True, timeout=timeout)
            return result.returncode
        
        return original_check_call(args, timeout=timeout, **kwargs)
    
    return sandboxed_check_call


def _create_sandboxed_check_output():
    """Create a sandboxed version of subprocess.check_output."""
    original_check_output = _originals["check_output"]
    
    def sandboxed_check_output(args, *, timeout=None, **kwargs):
        shell = kwargs.get("shell", False)
        env = kwargs.get("env")
        
        if _should_sandbox(args, shell, env):
            command = _args_to_shell_command(args)
            cwd = kwargs.pop("cwd", None)
            text = kwargs.pop("text", kwargs.pop("universal_newlines", None))
            encoding = kwargs.pop("encoding", None)
            errors = kwargs.pop("errors", None)
            
            use_text = text or encoding or errors
            
            sb = Sandbox(
                rw=_patch_config.get("rw", []),
                network=_patch_config.get("network", False),
                share_home=_patch_config.get("share_home", True),
                env_passthrough=_patch_config.get("env_passthrough", []),
                allow_secrets=_patch_config.get("allow_secrets", []),
                cwd=cwd,
            )
            result = sb.run(command, capture_output=True, check=True, text=bool(use_text), timeout=timeout)
            return result.stdout
        
        return original_check_output(args, timeout=timeout, **kwargs)
    
    return sandboxed_check_output


def _create_sandboxed_getstatusoutput():
    """Create a sandboxed version of subprocess.getstatusoutput."""
    original_getstatusoutput = _originals["getstatusoutput"]
    
    def sandboxed_getstatusoutput(cmd):
        # getstatusoutput always uses shell
        sb = Sandbox(
            rw=_patch_config.get("rw", []),
            network=_patch_config.get("network", False),
            share_home=_patch_config.get("share_home", True),
            env_passthrough=_patch_config.get("env_passthrough", []),
            allow_secrets=_patch_config.get("allow_secrets", []),
        )
        result = sb.run(cmd, capture_output=True, text=True)
        # getstatusoutput returns combined stdout+stderr with trailing newline stripped
        output = (result.stdout or "") + (result.stderr or "")
        if output.endswith('\n'):
            output = output[:-1]
        return result.returncode, output
    
    return sandboxed_getstatusoutput


def _create_sandboxed_getoutput():
    """Create a sandboxed version of subprocess.getoutput."""
    
    def sandboxed_getoutput(cmd):
        # getoutput always uses shell, returns just output
        sb = Sandbox(
            rw=_patch_config.get("rw", []),
            network=_patch_config.get("network", False),
            share_home=_patch_config.get("share_home", True),
            env_passthrough=_patch_config.get("env_passthrough", []),
            allow_secrets=_patch_config.get("allow_secrets", []),
        )
        result = sb.run(cmd, capture_output=True, text=True)
        output = (result.stdout or "") + (result.stderr or "")
        if output.endswith('\n'):
            output = output[:-1]
        return output
    
    return sandboxed_getoutput


class SandboxedPopen:
    """
    A Popen-like wrapper that runs commands in a sandbox.
    
    This provides a compatible interface with subprocess.Popen for shell commands,
    while delegating to the actual Popen for non-shell commands.
    """
    
    def __init__(
        self,
        args,
        bufsize=-1,
        executable=None,
        stdin=None,
        stdout=None,
        stderr=None,
        preexec_fn=None,
        close_fds=True,
        shell=False,
        cwd=None,
        env=None,
        universal_newlines=None,
        startupinfo=None,
        creationflags=0,
        restore_signals=True,
        start_new_session=False,
        pass_fds=(),
        *,
        group=None,
        extra_groups=None,
        user=None,
        umask=-1,
        encoding=None,
        errors=None,
        text=None,
        pipesize=-1,
        process_group=None,
    ):
        self._sandbox_mode = _should_sandbox(args, shell, env)
        self._completed = False
        self._returncode = None
        self._stdout_data = None
        self._stderr_data = None
        self._text_mode = text or universal_newlines or encoding or errors
        
        if self._sandbox_mode:
            # Run in sandbox
            command = _args_to_shell_command(args)
            sb = Sandbox(
                rw=_patch_config.get("rw", []),
                network=_patch_config.get("network", False),
                share_home=_patch_config.get("share_home", True),
                env_passthrough=_patch_config.get("env_passthrough", []),
                allow_secrets=_patch_config.get("allow_secrets", []),
                cwd=cwd,
            )
            
            # Execute immediately (sandbox doesn't support true async)
            try:
                exit_code, stdout_str, stderr_str = sb._rs_sandbox.run(command)
                self._returncode = exit_code
                
                if self._text_mode:
                    self._stdout_data = stdout_str
                    self._stderr_data = stderr_str
                else:
                    self._stdout_data = stdout_str.encode('utf-8') if stdout_str else b''
                    self._stderr_data = stderr_str.encode('utf-8') if stderr_str else b''
                    
            except Exception as e:
                self._returncode = 1
                self._stderr_data = str(e) if self._text_mode else str(e).encode('utf-8')
                self._stdout_data = "" if self._text_mode else b""
            
            self._completed = True
            
            # Create file-like objects for stdout/stderr if requested
            self.stdin = None
            self.stdout = self._make_pipe(self._stdout_data, stdout)
            self.stderr = self._make_pipe(self._stderr_data, stderr)
            self.pid = -1  # Fake PID for sandboxed process
            self.args = args
        else:
            # Use real Popen
            OriginalPopen = _originals["Popen"]
            
            # Build kwargs, handling version differences
            popen_kwargs = dict(
                bufsize=bufsize,
                executable=executable,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                preexec_fn=preexec_fn,
                close_fds=close_fds,
                shell=shell,
                cwd=cwd,
                env=env,
                universal_newlines=universal_newlines,
                startupinfo=startupinfo,
                creationflags=creationflags,
                restore_signals=restore_signals,
                start_new_session=start_new_session,
                pass_fds=pass_fds,
                encoding=encoding,
                errors=errors,
                text=text,
            )
            
            # Add newer parameters if supported (Python 3.9+)
            if sys.version_info >= (3, 9):
                popen_kwargs["group"] = group
                popen_kwargs["extra_groups"] = extra_groups
                popen_kwargs["user"] = user
                popen_kwargs["umask"] = umask
            
            # pipesize added in 3.10
            if sys.version_info >= (3, 10):
                popen_kwargs["pipesize"] = pipesize
            
            # process_group added in 3.11
            if sys.version_info >= (3, 11):
                popen_kwargs["process_group"] = process_group
            
            self._real_popen = OriginalPopen(args, **popen_kwargs)
            self.stdin = self._real_popen.stdin
            self.stdout = self._real_popen.stdout
            self.stderr = self._real_popen.stderr
            self.pid = self._real_popen.pid
            self.args = self._real_popen.args
    
    def _make_pipe(self, data, pipe_request) -> Optional[IO]:
        """Create a file-like object if pipe was requested."""
        if pipe_request == subprocess.PIPE:
            if self._text_mode:
                import io
                return io.StringIO(data or "")
            else:
                import io
                return io.BytesIO(data or b"")
        return None
    
    @property
    def returncode(self) -> Optional[int]:
        if self._sandbox_mode:
            return self._returncode
        return self._real_popen.returncode
    
    def poll(self) -> Optional[int]:
        if self._sandbox_mode:
            return self._returncode
        return self._real_popen.poll()
    
    def wait(self, timeout=None) -> int:
        if self._sandbox_mode:
            return self._returncode
        return self._real_popen.wait(timeout=timeout)
    
    def communicate(self, input=None, timeout=None):
        if self._sandbox_mode:
            return (self._stdout_data, self._stderr_data)
        return self._real_popen.communicate(input=input, timeout=timeout)
    
    def send_signal(self, sig):
        if self._sandbox_mode:
            pass  # Already completed
        else:
            self._real_popen.send_signal(sig)
    
    def terminate(self):
        if self._sandbox_mode:
            pass  # Already completed
        else:
            self._real_popen.terminate()
    
    def kill(self):
        if self._sandbox_mode:
            pass  # Already completed
        else:
            self._real_popen.kill()
    
    def __enter__(self):
        if self._sandbox_mode:
            return self
        return self._real_popen.__enter__()
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._sandbox_mode:
            # Close our fake pipes
            if self.stdout:
                self.stdout.close()
            if self.stderr:
                self.stderr.close()
            return False
        return self._real_popen.__exit__(exc_type, exc_val, exc_tb)


def patch_subprocess(
    *,
    rw: Optional[List[str]] = None,
    network: bool = False,
    share_home: bool = True,
    env_passthrough: Optional[List[str]] = None,
    allow_secrets: Optional[List[str]] = None,
) -> None:
    """
    Monkey-patch subprocess module to use sandboxing for shell commands.
    
    This patches:
    - subprocess.run
    - subprocess.call
    - subprocess.check_call
    - subprocess.check_output
    - subprocess.Popen
    - subprocess.getstatusoutput
    - subprocess.getoutput
    
    Only shell commands (shell=True with string args) are sandboxed.
    Direct executable calls (shell=False or list args) pass through unchanged.
    """
    global _patched, _patch_config, _originals

    if _patched:
        return

    # Store originals
    _originals = {
        "run": subprocess.run,
        "call": subprocess.call,
        "check_call": subprocess.check_call,
        "check_output": subprocess.check_output,
        "Popen": subprocess.Popen,
        "getstatusoutput": subprocess.getstatusoutput,
        "getoutput": subprocess.getoutput,
    }
    
    # Store config
    _patch_config = {
        "rw": rw or [],
        "network": network,
        "share_home": share_home,
        "env_passthrough": env_passthrough or [
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
            "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY",
            "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
            "TERM", "COLORTERM", "PATH", "HOME", "USER", "LANG",
        ],
        "allow_secrets": allow_secrets or [],
    }

    # Apply patches
    subprocess.run = _create_sandboxed_run()
    subprocess.call = _create_sandboxed_call()
    subprocess.check_call = _create_sandboxed_check_call()
    subprocess.check_output = _create_sandboxed_check_output()
    subprocess.Popen = SandboxedPopen
    subprocess.getstatusoutput = _create_sandboxed_getstatusoutput()
    subprocess.getoutput = _create_sandboxed_getoutput()
    
    _patched = True


def unpatch_subprocess() -> None:
    """Remove all subprocess monkey-patches and restore originals."""
    global _patched, _originals
    
    if not _patched or not _originals:
        return
    
    subprocess.run = _originals["run"]
    subprocess.call = _originals["call"]
    subprocess.check_call = _originals["check_call"]
    subprocess.check_output = _originals["check_output"]
    subprocess.Popen = _originals["Popen"]
    subprocess.getstatusoutput = _originals["getstatusoutput"]
    subprocess.getoutput = _originals["getoutput"]
    
    _originals = {}
    _patched = False


def is_patched() -> bool:
    """Check if subprocess is currently patched."""
    return _patched


def create_aider_sandbox(
    project_dir: str,
    *,
    network: bool = True,
    allow_gpg: bool = False,
    allow_ssh: bool = False,
) -> Sandbox:
    """Create a sandbox configured for Aider CLI usage."""
    allow_secrets = []
    if allow_gpg:
        allow_secrets.append(".gnupg")
    if allow_ssh:
        allow_secrets.append(".ssh")

    return Sandbox(
        rw=[project_dir, "/tmp"],
        network=network,
        share_home=True,
        env_passthrough=[
            # API Keys
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY",
            "GOOGLE_API_KEY", "AZURE_OPENAI_API_KEY", "GEMINI_API_KEY",
            "AZURE_API_KEY", "AZURE_API_BASE", "AZURE_API_VERSION",
            "DEEPSEEK_API_KEY", "GROQ_API_KEY", "COHERE_API_KEY",
            "MISTRAL_API_KEY", "OLLAMA_API_BASE",
            "OPENAI_API_BASE", "OPENAI_API_TYPE", "OPENAI_API_VERSION",
            # Git
            "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
            "GIT_SSH_COMMAND", "GIT_ASKPASS",
            # Terminal
            "TERM", "COLORTERM", "CLICOLOR", "FORCE_COLOR", "NO_COLOR",
            # System
            "PATH", "HOME", "USER", "LANG", "LC_ALL",
            "PYTHONPATH", "VIRTUAL_ENV",
            # Editor
            "EDITOR", "VISUAL",
        ],
        allow_secrets=allow_secrets,
    )