# bubbleproc

Bubblewrap sandboxing for Python - protect against accidental damage from AI coding tools.

It also supports monkey patching `subprocess`, to bubblewrap `Popen`, `run`, `check_output`, etc.

## Installation

```bash
pip install bubbleproc
```

Requires `bubblewrap` to be installed:
```bash
# Ubuntu/Debian
sudo apt install bubblewrap

# Fedora  
sudo dnf install bubblewrap

# Arch
sudo pacman -S bubblewrap
```

## Quick Start

```python
from bubbleproc import run, Sandbox

# Run a command with read-write access to your project
result = run("python script.py", rw=["~/myproject"])

# Run with network access (for API calls)
result = run("npm install", rw=["~/myproject"], network=True)

# Reusable sandbox configuration
sb = Sandbox(rw=["~/project"], network=True)
sb.run("make build")
sb.run("make test")
```

## Features

- 🔒 Secrets blocked by default (SSH keys, AWS credentials, etc.)
- 🛡️ System paths are read-only
- 🌐 Network disabled by default
- 🔌 Drop-in subprocess.run() replacement
- 🐍 Pure Python fallback when Rust extension unavailable

See the main repository README for full documentation.
