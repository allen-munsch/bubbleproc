"""
bubbleproc - Bubblewrap sandboxing for Python

A drop-in replacement for subprocess.run() that executes commands in a
bubblewrap sandbox, blocking access to secrets and limiting filesystem access.

Usage:
    from bubbleproc import run, Sandbox
    
    # Simple - run a command with default protections
    result = run("ls -la", cwd="/home/user/project")
    
    # With explicit read-write access
    result = run("python script.py", rw=["/home/user/project"])
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