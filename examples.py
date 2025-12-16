#!/usr/bin/env python3
"""
Examples and tests for the bubblepy module.

Run with: python examples.py
"""

from bubblepy import Sandbox, run, check_output, patch_subprocess, create_aider_sandbox
import subprocess
import os
import tempfile


def example_basic():
    """Basic usage - run a simple command."""
    print("=== Basic Usage ===")
    
    # Simple command (no filesystem access needed)
    result = run("echo 'Hello from bubblepy!'", capture_output=True)
    print(f"Output: {result.stdout.strip()}")
    print(f"Return code: {result.returncode}")


def example_filesystem():
    """Filesystem access control."""
    print("\n=== Filesystem Access ===")
    
    # Create a temp directory to work with
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a test file
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Hello World\n")
        
        # Read-only access
        result = run(f"cat {test_file}", ro=[tmpdir], capture_output=True)
        print(f"Read file: {result.stdout.strip()}")
        
        # Read-write access
        result = run(
            f"echo 'Modified' >> {test_file} && cat {test_file}",
            rw=[tmpdir],
            capture_output=True
        )
        print(f"After write: {result.stdout.strip()}")
        
        # Verify the write persisted
        with open(test_file) as f:
            print(f"Actual content: {f.read().strip()}")


def example_secrets_blocked():
    """Demonstrate that secrets are blocked."""
    print("\n=== Secrets Blocked ===")
    
    home = os.environ.get("HOME", "/tmp")
    
    # Try to read .ssh (should be empty/blocked)
    result = run(
        f"ls -la {home}/.ssh 2>&1 || echo 'Access blocked'",
        share_home=True,
        capture_output=True
    )
    print(f"Trying to access ~/.ssh: {result.stdout.strip()}")
    
    # Try to read .aws (should be empty/blocked)
    result = run(
        f"ls -la {home}/.aws 2>&1 || echo 'Access blocked'",
        share_home=True,
        capture_output=True
    )
    print(f"Trying to access ~/.aws: {result.stdout.strip()}")


def example_network():
    """Network access control."""
    print("\n=== Network Access ===")
    
    # Without network (should fail)
    result = run(
        "curl -s --connect-timeout 2 https://example.com 2>&1 || echo 'Network blocked'",
        capture_output=True
    )
    print(f"Without --network: {result.stdout.strip()[:50]}...")
    
    # With network (should work)
    result = run(
        "curl -s --connect-timeout 5 https://example.com | head -c 100",
        network=True,
        capture_output=True
    )
    print(f"With --network: {result.stdout.strip()[:50]}...")


def example_sandbox_object():
    """Using the Sandbox class for reusable configuration."""
    print("\n=== Sandbox Object ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Configure once, use multiple times
        sb = Sandbox(
            rw=[tmpdir],
            network=False,
            env={"MY_VAR": "hello"},
        )
        
        # Run multiple commands with same config
        sb.run(f"echo $MY_VAR > {tmpdir}/out.txt")
        result = sb.run(f"cat {tmpdir}/out.txt", capture_output=True)
        print(f"Environment variable passed: {result.stdout.strip()}")
        
        # Check output helper
        output = sb.check_output("echo 'check_output works'")
        print(f"check_output: {output.strip()}")


def example_aider_sandbox():
    """Sandbox configured for Aider usage."""
    print("\n=== Aider Sandbox ===")
    
    with tempfile.TemporaryDirectory() as project_dir:
        # Create a mock project
        with open(os.path.join(project_dir, "main.py"), "w") as f:
            f.write("print('hello')\n")
        
        # Create sandbox for aider
        sb = create_aider_sandbox(project_dir, network=True)
        
        # Show what aider would see
        result = sb.run(f"ls -la {project_dir}", capture_output=True)
        print(f"Project files: {result.stdout.strip()}")
        
        # Verify API key passthrough works (if set)
        api_key = os.environ.get("ANTHROPIC_API_KEY", "not-set")
        result = sb.run(
            "echo ${ANTHROPIC_API_KEY:0:10}...",  # Just first 10 chars
            capture_output=True
        )
        print(f"API key passed: {result.stdout.strip()}")


def example_monkey_patch():
    """Monkey-patching subprocess for transparent sandboxing."""
    print("\n=== Monkey Patch ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Patch subprocess
        patch_subprocess(rw=[tmpdir], network=False, share_home=True)
        
        # Now regular subprocess.run with shell=True is sandboxed
        result = subprocess.run(
            f"echo 'sandboxed!' > {tmpdir}/test.txt && cat {tmpdir}/test.txt",
            shell=True,
            capture_output=True,
            text=True
        )
        print(f"Patched subprocess.run: {result.stdout.strip()}")
        
        # Non-shell commands still work normally
        result = subprocess.run(["echo", "not sandboxed"], capture_output=True, text=True)
        print(f"Non-shell command: {result.stdout.strip()}")
        
        # Clean up
        from bubblepy import unpatch_subprocess
        unpatch_subprocess()


def example_dangerous_commands():
    """Show that dangerous commands are contained."""
    print("\n=== Dangerous Commands Contained ===")
    
    with tempfile.TemporaryDirectory() as safe_dir:
        # Create a file in the safe directory
        safe_file = os.path.join(safe_dir, "important.txt")
        with open(safe_file, "w") as f:
            f.write("important data\n")
        
        # Try to delete everything (should fail outside rw paths)
        result = run(
            "rm -rf / 2>&1 || echo 'Deletion blocked'",
            rw=[safe_dir],
            capture_output=True
        )
        print(f"rm -rf /: {result.stdout.strip()[:60]}")
        
        # The safe file should still exist
        print(f"Safe file exists: {os.path.exists(safe_file)}")
        
        # Try to access /etc/passwd for writing (should be read-only)
        result = run(
            "echo 'hacked' >> /etc/passwd 2>&1 || echo 'Write blocked'",
            capture_output=True
        )
        print(f"Write to /etc/passwd: {result.stdout.strip()}")


def main():
    """Run all examples."""
    print("Sandbox Module Examples")
    print("=" * 50)
    
    examples = [
        ("Basic", example_basic),
        ("Filesystem", example_filesystem),
        ("Secrets Blocked", example_secrets_blocked),
        ("Network", example_network),
        ("Sandbox Object", example_sandbox_object),
        ("Aider Sandbox", example_aider_sandbox),
        ("Monkey Patch", example_monkey_patch),
        ("Dangerous Commands", example_dangerous_commands),
    ]
    
    for name, func in examples:
        try:
            func()
        except Exception as e:
            print(f"\n=== {name} ===")
            print(f"Error: {e}")
    
    print("\n" + "=" * 50)
    print("All examples complete!")


if __name__ == "__main__":
    main()
