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
from typing import Any, Optional, List, Dict, Union, Sequence, Mapping, IO

from bubbleproc import _bubbleproc_rs as _rs

__all__ = [
    "Sandbox",
    "run",
    "check_output",
    "patch_subprocess",
    "unpatch_subprocess",
    "SandboxError",
    "SandboxedPopen",
]

# =============================================================================
# CONSTANTS
# =============================================================================

# Essential environment variables that must ALWAYS be passed for basic shell functionality
ESSENTIAL_ENV_VARS = [
    "PATH",  # CRITICAL: Without this, can't find any executables
    "HOME",  # Required by many programs
    "USER",  # Required by many programs
    "SHELL",  # Default shell
    "TERM",  # Terminal type
    "LANG",  # Locale
    "LC_ALL",  # Locale override
    "LC_CTYPE",  # Character types
    "TMPDIR",  # Temp directory
    "TEMP",  # Windows-style temp
    "TMP",  # Windows-style temp
]

# Default passthrough for patching - essentials plus common useful vars
DEFAULT_ENV_PASSTHROUGH = ESSENTIAL_ENV_VARS + [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "COLORTERM",
]


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

    _rs: _rs.Sandbox = field(init=False, repr=False)

    def __post_init__(self):
        # Validate 'bwrap' exists early
        if not shutil.which("bwrap"):
            raise SandboxError(
                "bubblewrap (bwrap) not found. Install with: apt install bubblewrap"
            )

        # Initialize the Rust core with current config
        self._rs = _rs.Sandbox(
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
            # Directly execute the command string via Rust FFI
            # The Rust backend expects a single shell command string.
            code, stdout, stderr = self._rs.run(command_str)

        except Exception as e:
            # Catch Rust/bwrap errors and re-raise as a Python SandboxError
            raise SandboxError(f"Sandboxed execution failed: {e}") from e

        # 3. Create a CompletedProcess object for compatibility
        # Always capture - the Rust side always returns output
        # We just choose whether to include it in the result
        if text:
            stdout_result = stdout if capture_output else ""
            stderr_result = stderr if capture_output else ""
        else:
            stdout_result = stdout.encode("utf-8") if capture_output else b""
            stderr_result = stderr.encode("utf-8") if capture_output else b""

        result = subprocess.CompletedProcess(
            args=[command_str],  # Use the full command string for args
            returncode=code,
            stdout=stdout_result,
            stderr=stderr_result,
        )

        if check and code != 0:
            raise subprocess.CalledProcessError(
                code, command_str, output=result.stdout, stderr=result.stderr
            )

        return result

    # Check_output and Popen methods from the sketch go here, calling self.run()
    # (Omitted for brevity, as the core logic is in the Sandbox.run)


# === Convenience functions (Delegating to Sandbox) ===
def run(command: str, **kwargs: Any) -> subprocess.CompletedProcess:
    """Convenience function for running a quick sandboxed command."""
    sb = Sandbox(**{k: v for k, v in kwargs.items() if k in Sandbox.__annotations__})
    return sb.run(
        command, **{k: v for k, v in kwargs.items() if k not in Sandbox.__annotations__}
    )


# === Subprocess Monkey-Patching ===

_original_subprocess_run = subprocess.run
_original_subprocess_call = subprocess.call
_original_subprocess_check_call = subprocess.check_call
_original_subprocess_check_output = subprocess.check_output
_original_subprocess_Popen = subprocess.Popen
_original_subprocess_getoutput = subprocess.getoutput
_original_subprocess_getstatusoutput = subprocess.getstatusoutput

_patched = False
_patch_config: dict[str, Any] = {}
_originals: Dict[str, Any] = {}


def _should_sandbox(
    args: Union[str, Sequence[str]],
    shell: bool,
    env: Optional[Mapping[str, str]] = None,
) -> bool:
    """Determine if a command should be sandboxed."""
    if env is not None:
        # If a custom env is provided, we can't reliably sandbox,
        # as it would override our bwrap env settings.
        # This is a limitation; bwrap --setenv requires specific env vars.
        return False

    # We only sandbox shell=True commands for now
    return shell and isinstance(args, str)


def _create_sandbox_from_config(cwd: Optional[str] = None) -> Sandbox:
    """
    Create a Sandbox instance using the current patch configuration.

    This ensures essential environment variables are always included,
    preventing silent failures when PATH/HOME are missing.
    """
    env_passthrough = list(
        _patch_config.get("env_passthrough", DEFAULT_ENV_PASSTHROUGH)
    )

    # Ensure essential vars are present (deduplicated)
    for var in ESSENTIAL_ENV_VARS:
        if var not in env_passthrough:
            env_passthrough.append(var)

        return sandboxed_run

    import io


class SandboxedPopen(subprocess.Popen):
    """
    A sandboxed version of subprocess.Popen.
    This class is not fully implemented for all Popen features,
    but aims to cover the common use cases required for sandboxing.
    """

    _sandboxed_result: Optional[subprocess.CompletedProcess] = None

    def __init__(
        self,
        args: Union[str, Sequence[str]],
        bufsize: int = -1,
        executable: Optional[Union[str, Path]] = None,
        stdin: Optional[Union[int, IO]] = None,
        stdout: Optional[Union[int, IO]] = None,
        stderr: Optional[Union[int, IO]] = None,
        preexec_fn: Optional[Any] = None,
        close_fds: bool = True,
        shell: bool = False,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Mapping[str, str]] = None,
        universal_newlines: Optional[bool] = None,
        startupinfo: Optional[Any] = None,
        creationflags: int = 0,
        restore_signals: bool = True,
        start_new_session: bool = False,
        pass_fds: Sequence[int] = (),
        *,
        text: bool = False,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
    ):
        if _should_sandbox(args, shell, env):
            command_str = args
            # Using our custom _create_sandbox_from_config
            sb = _create_sandbox_from_config(cwd=str(cwd) if cwd else None)

            # Popen typically runs asynchronously.
            # For simplicity and immediate sandboxing, we run synchronously via sb.run
            # and store the result to mimic Popen's interface (poll, wait, communicate).
            # A full async Popen would require running sb.run in a separate thread/process
            # and managing pipes, which is complex.
            try:
                self._sandboxed_result = sb.run(
                    command_str,
                    capture_output=True,  # Always capture for Popen to allow communicate()
                    text=text or (encoding is not None) or (universal_newlines is True),
                    check=False,  # Popen doesn't check by default
                )
                self.returncode = self._sandboxed_result.returncode
            except SandboxError:
                self.returncode = 127  # Command not found or sandbox failed
                self._sandboxed_result = subprocess.CompletedProcess(
                    args=[command_str],
                    returncode=self.returncode,
                    stdout=b"",
                    stderr=b"Sandboxed Popen failed to execute.\n",
                )

            # Mimic stdout/stderr pipes
            if stdout == subprocess.PIPE:
                self.stdout = io.BytesIO(
                    self._sandboxed_result.stdout.encode()
                    if isinstance(self._sandboxed_result.stdout, str)
                    else self._sandboxed_result.stdout
                )
            else:
                self.stdout = None

            if stderr == subprocess.PIPE:
                self.stderr = io.BytesIO(
                    self._sandboxed_result.stderr.encode()
                    if isinstance(self._sandboxed_result.stderr, str)
                    else self._sandboxed_result.stderr
                )
            else:
                self.stderr = None

            self.pid = 0  # No real PID in this synchronous mimicry

        else:
            # Fallback to original Popen for non-sandboxed commands
            super().__init__(
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
                text=text,
                encoding=encoding,
                errors=errors,
            )

    def poll(self) -> Optional[int]:
        if self._sandboxed_result:
            return self.returncode
        return super().poll()

    def wait(self, timeout: Optional[float] = None) -> int:
        if self._sandboxed_result:
            # For synchronous sb.run, wait is effectively instantaneous after __init__
            return self.returncode
        return super().wait(timeout=timeout)

    def communicate(
        self, input: Optional[Union[bytes, str]] = None, timeout: Optional[float] = None
    ) -> Tuple[Optional[bytes], Optional[bytes]]:
        if self._sandboxed_result:
            # Input is not supported in this synchronous Popen mimicry
            if input is not None:
                raise ValueError("Sending input to sandboxed Popen is not supported.")

            stdout_data = self._sandboxed_result.stdout
            stderr_data = self._sandboxed_result.stderr

            if isinstance(stdout_data, str):
                stdout_data = stdout_data.encode()
            if isinstance(stderr_data, str):
                stderr_data.encode()

            return stdout_data, stderr_data
        return super().communicate(input=input, timeout=timeout)

    def terminate(self) -> None:
        if self._sandboxed_result:
            return  # Already finished
        super().terminate()

    def kill(self) -> None:
        if self._sandboxed_result:
            return  # Already finished
        super().kill()

    def send_signal(self, signal: int) -> None:
        if self._sandboxed_result:
            return  # Already finished
        super().send_signal(signal)


def _create_sandboxed_run():
    """Create a sandboxed version of subprocess.run."""

    original_run = _originals["run"]

    def sandboxed_run(
        args: Union[str, Sequence[str]],
        *,
        bufsize: int = -1,
        executable: Optional[Union[str, Path]] = None,
        stdin: Optional[Union[int, IO]] = None,
        stdout: Optional[Union[int, IO]] = None,
        stderr: Optional[Union[int, IO]] = None,
        preexec_fn: Optional[Any] = None,
        close_fds: bool = True,
        shell: bool = False,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Mapping[str, str]] = None,
        universal_newlines: Optional[bool] = None,
        startupinfo: Optional[Any] = None,
        creationflags: int = 0,
        restore_signals: bool = True,
        start_new_session: bool = False,
        pass_fds: Sequence[int] = (),
        capture_output: bool = False,
        timeout: Optional[float] = None,
        check: bool = False,
        text: bool = False,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        if _should_sandbox(args, shell, env):
            command_str = args  # Already a string if _should_sandbox is True

            sb = _create_sandbox_from_config(cwd=str(cwd) if cwd else None)

            # Use sb.run arguments that map to subprocess.run

            # Note: input, encoding, errors are not directly handled by sb.run

            # We assume for now that sb.run handles similar to subprocess.run defaults

            try:
                # sb.run returns a CompletedProcess object

                return sb.run(
                    command_str,
                    capture_output=capture_output
                    or (stdout == subprocess.PIPE)
                    or (stderr == subprocess.PIPE),
                    text=text or (encoding is not None) or (universal_newlines is True),
                    check=check,
                    timeout=timeout,
                )

            except SandboxError as e:
                # If sandbox failed, re-raise as CalledProcessError if check=True

                if check:
                    raise subprocess.CalledProcessError(
                        1, command_str, stderr=str(e).encode()
                    )

                return subprocess.CompletedProcess(
                    args=[command_str], returncode=1, stdout=b"", stderr=str(e).encode()
                )

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
            text=text,
            encoding=encoding,
            errors=errors,
        )

        return sandboxed_run

    def _create_sandboxed_call():
        """Create a sandboxed version of subprocess.call."""

        original_call = _originals["call"]

        def sandboxed_call(
            args: Union[str, Sequence[str]],
            *,
            bufsize: int = -1,
            executable: Optional[Union[str, Path]] = None,
            stdin: Optional[Union[int, IO]] = None,
            stdout: Optional[Union[int, IO]] = None,
            stderr: Optional[Union[int, IO]] = None,
            preexec_fn: Optional[Any] = None,
            close_fds: bool = True,
            shell: bool = False,
            cwd: Optional[Union[str, Path]] = None,
            env: Optional[Mapping[str, str]] = None,
            universal_newlines: Optional[bool] = None,
            startupinfo: Optional[Any] = None,
            creationflags: int = 0,
            restore_signals: bool = True,
            start_new_session: bool = False,
            pass_fds: Sequence[int] = (),
            timeout: Optional[float] = None,
        ) -> int:
            if _should_sandbox(args, shell, env):
                command_str = args

                sb = _create_sandbox_from_config(cwd=str(cwd) if cwd else None)

                try:
                    result = sb.run(command_str, check=False, timeout=timeout)

                    return result.returncode

                except SandboxError:
                    return 1  # Indicate failure if sandbox setup itself fails

            return original_call(
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
                timeout=timeout,
            )

            return sandboxed_call

        def _create_sandboxed_check_call():
            """Create a sandboxed version of subprocess.check_call."""

            original_check_call = _originals["check_call"]

            def sandboxed_check_call(
                args: Union[str, Sequence[str]],
                *,
                bufsize: int = -1,
                executable: Optional[Union[str, Path]] = None,
                stdin: Optional[Union[int, IO]] = None,
                stdout: Optional[Union[int, IO]] = None,
                stderr: Optional[Union[int, IO]] = None,
                preexec_fn: Optional[Any] = None,
                close_fds: bool = True,
                shell: bool = False,
                cwd: Optional[Union[str, Path]] = None,
                env: Optional[Mapping[str, str]] = None,
                universal_newlines: Optional[bool] = None,
                startupinfo: Optional[Any] = None,
                creationflags: int = 0,
                restore_signals: bool = True,
                start_new_session: bool = False,
                pass_fds: Sequence[int] = (),
                timeout: Optional[float] = None,
            ) -> int:
                if _should_sandbox(args, shell, env):
                    command_str = args

                    sb = _create_sandbox_from_config(cwd=str(cwd) if cwd else None)

                    result = sb.run(command_str, check=True, timeout=timeout)

                    return result.returncode

                return original_check_call(
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
                    timeout=timeout,
                )

                return sandboxed_check_call

            def _create_sandboxed_check_output():
                """Create a sandboxed version of subprocess.check_output."""

                original_check_output = _originals["check_output"]

                def sandboxed_check_output(
                    args: Union[str, Sequence[str]],
                    *,
                    bufsize: int = -1,
                    executable: Optional[Union[str, Path]] = None,
                    stdin: Optional[Union[int, IO]] = None,
                    stderr: Optional[Union[int, IO]] = None,
                    preexec_fn: Optional[Any] = None,
                    close_fds: bool = True,
                    shell: bool = False,
                    cwd: Optional[Union[str, Path]] = None,
                    env: Optional[Mapping[str, str]] = None,
                    universal_newlines: Optional[bool] = None,
                    startupinfo: Optional[Any] = None,
                    creationflags: int = 0,
                    restore_signals: bool = True,
                    start_new_session: bool = False,
                    pass_fds: Sequence[int] = (),
                    timeout: Optional[float] = None,
                    text: bool = False,
                    encoding: Optional[str] = None,
                    errors: Optional[str] = None,
                ) -> Union[str, bytes]:
                    if _should_sandbox(args, shell, env):
                        command_str = args

                        sb = _create_sandbox_from_config(cwd=str(cwd) if cwd else None)

                        result = sb.run(
                            command_str,
                            capture_output=True,
                            check=True,
                            timeout=timeout,
                            text=text
                            or (encoding is not None)
                            or (universal_newlines is True),
                        )

                        return result.stdout

                    return original_check_output(
                        args,
                        bufsize=bufsize,
                        executable=executable,
                        stdin=stdin,
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
                        timeout=timeout,
                        text=text,
                        encoding=encoding,
                        errors=errors,
                    )

                    return sandboxed_check_output

                def _create_sandboxed_getoutput():
                    """Create a sandboxed version of subprocess.getoutput."""

                    original_getoutput = _originals["getoutput"]

                    def sandboxed_getoutput(
                        cmd: str,
                        globals: Optional[Mapping[str, Any]] = None,
                        locals: Optional[Mapping[str, Any]] = None,
                    ) -> str:
                        if _should_sandbox(
                            cmd, shell=True, env=None
                        ):  # getoutput always uses shell=True
                            sb = _create_sandbox_from_config()

                            result = sb.run(
                                cmd, capture_output=True, check=True, text=True
                            )

                            return result.stdout

                        return original_getoutput(cmd, globals=globals, locals=locals)

                        return sandboxed_getoutput

                    def _create_sandboxed_getstatusoutput():
                        """Create a sandboxed version of subprocess.getstatusoutput."""

                        original_getstatusoutput = _originals["getstatusoutput"]

                        def sandboxed_getstatusoutput(
                            cmd: str,
                            globals: Optional[Mapping[str, Any]] = None,
                            locals: Optional[Mapping[str, Any]] = None,
                        ) -> Tuple[int, str]:
                            if _should_sandbox(
                                cmd, shell=True, env=None
                            ):  # getstatusoutput always uses shell=True
                                sb = _create_sandbox_from_config()

                                result = sb.run(
                                    cmd, capture_output=True, check=False, text=True
                                )

                                return result.returncode, result.stdout

                            return original_getstatusoutput(
                                cmd, globals=globals, locals=locals
                            )

                        return sandboxed_getstatusoutput


def patch_subprocess(
    *,
    rw: Optional[List[str]] = None,
    network: bool = False,
    share_home: bool = True,
    env_passthrough: Optional[List[str]] = None,
    allow_secrets: Optional[List[str]] = None,
) -> None:
    """Monkey-patch subprocess module to use sandboxing for shell commands."""
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
        "getoutput": subprocess.getoutput,
        "getstatusoutput": subprocess.getstatusoutput,
    }

    # Store config - ensure essential vars are always included
    final_env_passthrough = list(env_passthrough or DEFAULT_ENV_PASSTHROUGH)
    for var in ESSENTIAL_ENV_VARS:
        if var not in final_env_passthrough:
            final_env_passthrough.append(var)

    _patch_config = {
        "rw": rw or [],
        "network": network,
        "share_home": share_home,
        "env_passthrough": final_env_passthrough,
        "allow_secrets": allow_secrets or [],
    }

    # Apply patches
    subprocess.run = _create_sandboxed_run()
    # Popen is a class, so direct assignment is fine
    subprocess.Popen = SandboxedPopen

    # For others, we create wrapper functions
    subprocess.call = _create_sandboxed_call()
    subprocess.check_call = _create_sandboxed_check_call()
    subprocess.check_output = _create_sandboxed_check_output()
    subprocess.getoutput = _create_sandboxed_getoutput()
    subprocess.getstatusoutput = _create_sandboxed_getstatusoutput()

    _patched = True


def unpatch_subprocess() -> None:
    """Remove the subprocess monkey-patch."""
    global _patched, _originals
    if not _patched:
        return

    subprocess.run = _originals["run"]
    subprocess.call = _originals["call"]
    subprocess.check_call = _originals["check_call"]
    subprocess.check_output = _originals["check_output"]
    subprocess.Popen = _originals["Popen"]
    subprocess.getoutput = _originals["getoutput"]
    subprocess.getstatusoutput = _originals["getstatusoutput"]

    _patched = False
    _originals = {}  # Clear originals
