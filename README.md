# bubbleproc - Bubblewrap Sandboxing for Python

A simple Python module that wraps [bubblewrap](https://github.com/containers/bubblewrap) to sandbox subprocess calls. Designed to protect against accidental (or malicious) file deletion, credential theft, and other damage from AI coding tools like Aider and MCP servers.

## Quick Start

```python
from bubbleproc import run

# Run a command with read-write access to your project
result = run("python script.py", rw=["~/myproject"])

# Run with network access (for API calls)
result = run("npm install", rw=["~/myproject"], network=True)
```

## Installation

1. Install bubblewrap:
```bash
# Ubuntu/Debian
sudo apt install bubblewrap

# Fedora
sudo dnf install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

2. Copy `bubbleproc.py` to your project or install it:
```bash
# Copy to your project
cp bubbleproc.py ~/myproject/

# Or add to PYTHONPATH
export PYTHONPATH="$PYTHONPATH:/path/to/bubbleproc"
```

## Features

### 🔒 Secrets Are Blocked by Default

When using `share_home=True`, these paths are automatically blocked:

| Category | Paths |
|----------|-------|
| SSH/GPG | `.ssh`, `.gnupg`, `.pki` |
| Cloud | `.aws`, `.azure`, `.gcloud`, `.kube` |
| Containers | `.docker`, `.helm` |
| Package tokens | `.npmrc`, `.pypirc`, `.cargo/credentials` |
| Password managers | `.password-store`, `.config/keybase` |
| CLI tokens | `.config/gh`, `.config/hub` |
| Browsers | `.mozilla`, `.config/google-chrome` |
| History | `.bash_history`, `.zsh_history`, etc. |

### 🛡️ System Paths Are Read-Only

System directories (`/usr`, `/bin`, `/etc`, etc.) are mounted read-only. Attempts to write to them fail silently or with permission errors.

### 🌐 Network Is Disabled by Default

Commands can't make network requests unless you explicitly allow it with `network=True`.

## Usage Patterns

### Simple One-Off Commands

```python
from bubbleproc import run, check_output

# Basic command
result = run("ls -la", ro=["~/code"])

# Capture output
result = run("grep -r TODO .", ro=["~/project"], capture_output=True)
print(result.stdout)

# Check output (raises on error)
output = check_output("cat README.md", ro=["~/project"])
```

### Reusable Sandbox Configuration

```python
from bubbleproc import Sandbox

# Configure once
sb = Sandbox(
    rw=["~/myproject"],
    network=True,
    env_passthrough=["ANTHROPIC_API_KEY"],
)

# Use multiple times
sb.run("npm install")
sb.run("npm test")
sb.run("npm run build")
```

### Aider Integration

```python
from bubbleproc import create_aider_sandbox

# Create a sandbox optimized for Aider
sb = create_aider_sandbox("~/myproject")

# Run aider commands safely
sb.run("aider --message 'add docstrings to all functions'")
```

### Transparent Sandboxing (Monkey Patch)

```python
from bubbleproc import patch_subprocess
import subprocess

# Patch subprocess module
patch_subprocess(rw=["~/project"], network=True)

# Now all shell commands are sandboxed automatically
subprocess.run("rm -rf /", shell=True)  # Harmless! Can't escape sandbox

# Uninstall the patch
from bubbleproc import unpatch_subprocess
unpatch_subprocess()
```

## API Reference

### `run(command, **options)`

Run a command in a sandbox. Returns `subprocess.CompletedProcess`.

**Options:**
- `ro`: List of paths to mount read-only
- `rw`: List of paths to mount read-write
- `network`: Allow network access (default: False)
- `share_home`: Mount $HOME read-only with secrets blocked (default: False)
- `env`: Dict of environment variables to set
- `env_passthrough`: List of env vars to pass from host
- `capture_output`: Capture stdout/stderr (default: False)
- `text`: Return strings instead of bytes (default: True)
- `check`: Raise on non-zero exit (default: False)
- `cwd`: Working directory
- `timeout`: Timeout in seconds

### `Sandbox(**options)`

Create a reusable sandbox configuration.

**Options:**
- `ro`, `rw`, `network`, `share_home`, `env`, `env_passthrough` (same as `run`)
- `allow_secrets`: List of secret paths to allow (e.g., `[".gnupg"]`)
- `gpu`: Allow GPU access (default: False)
- `timeout`: Default timeout for all commands
- `cwd`: Default working directory

**Methods:**
- `run(command, **kwargs)` - Run a command
- `check_output(command, **kwargs)` - Run and return output
- `Popen(command, **kwargs)` - Start process without waiting

### `create_aider_sandbox(project_dir, **options)`

Create a sandbox configured for Aider CLI usage.

**Options:**
- `project_dir`: Project directory (required, mounted read-write)
- `network`: Allow network for API calls (default: True)
- `allow_gpg`: Allow GPG for signed commits (default: False)

### `patch_subprocess(**options)` / `unpatch_subprocess()`

Monkey-patch `subprocess.run()` to automatically sandbox shell commands.

## Use with MCP Servers

When running MCP tools that execute shell commands, use the sandbox to contain them:

```python
from bubbleproc import Sandbox

# Create sandbox for MCP filesystem server
sb = Sandbox(
    rw=["~/allowed-directory"],
    network=False,  # MCP filesystem doesn't need network
)

# Execute MCP tool commands through sandbox
def execute_mcp_command(command: str) -> str:
    result = sb.run(command, capture_output=True, check=True)
    return result.stdout
```

## CLI Usage

```bash
# Run a command in sandbox
python bubbleproc.py --rw ~/project -- ls -la

# With network
python bubbleproc.py --network --rw ~/project -- curl https://example.com

# Share home (secrets blocked)
python bubbleproc.py --share-home -- cat ~/.gitconfig
```

## Security Considerations

This sandbox provides defense-in-depth but is not a complete security solution:

1. **It blocks common attack vectors** - Credential theft, system damage
2. **It doesn't block everything** - A determined attacker could find bypasses
3. **Use with other measures** - Code review, limited API keys, monitoring

The goal is to prevent accidental damage and opportunistic attacks from AI tools, not to contain sophisticated adversaries.

## Requirements

- Python 3.8+
- bubblewrap (`bwrap`)
- Linux (bubblewrap is Linux-only)

## License

MIT
