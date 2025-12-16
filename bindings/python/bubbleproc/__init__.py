"""
bubbleproc - Bubblewrap sandboxing for Python

Usage:
    from bubbleproc import run, Sandbox
    result = run("ls -la", rw=["/home/user/project"])
"""

from bubbleproc._sandbox import (
    Sandbox,
    SandboxError,
    run,
    check_output,
    patch_subprocess,
    unpatch_subprocess,
    create_aider_sandbox,
)

__version__ = "1.0.0"
__all__ = [
    "Sandbox",
    "SandboxError",
    "run",
    "check_output",
    "patch_subprocess",
    "unpatch_subprocess",
    "create_aider_sandbox",
]