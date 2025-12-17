"""
bubbleproc - Bubblewrap sandboxing for Python

Usage:
    from bubbleproc import run, Sandbox
    result = run("ls -la", rw=["/home/user/project"])

    # Patch all subprocess calls
    from bubbleproc import patch_subprocess
    patch_subprocess(rw=["/path/to/project"], network=True)

    # Now subprocess.run, Popen, call, etc. are sandboxed
    import subprocess
    subprocess.run("rm -rf /", shell=True)  # Blocked!
"""

from bubbleproc._sandbox import (
    Sandbox,
    SandboxError,
    run,
    check_output,
    patch_subprocess,
    unpatch_subprocess,
    create_aider_sandbox,
    is_patched,
    SandboxedPopen,
)

__version__ = "1.0.4"

__all__ = [
    # Core classes
    "Sandbox",
    "SandboxError",
    "SandboxedPopen",
    # Convenience functions
    "run",
    "check_output",
    # Subprocess patching
    "patch_subprocess",
    "unpatch_subprocess",
    "is_patched",
    # Preset configurations
    "create_aider_sandbox",
]


# Optional: Check if sandbox is available at import time
def is_available() -> bool:
    """Check if the bubbleproc Rust extension is available."""
    try:
        from bubbleproc import _bubbleproc_rs

        return True
    except ImportError:
        return False


__all__.append("is_available")
