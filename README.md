# `bubbleproc`: Unified Agent-Safe Sandboxing Toolkit

**A high-performance, language-agnostic security focused toolkit (experimental) built in Rust for safely executing untrusted external processes.**

`bubbleproc` wraps the Linux `bubblewrap` utility, providing a robust, opinionated, and easily configurable sandbox via stable APIs. Its primary use case is to **contain the blast radius** of subprocess calls initiated by untrusted code, such as **AI agents (e.g., Gemini Cli, GPT-Pilot, etc)**, build tools (`npm`, `pip`, `cargo`), or servers.

The system is split into a core Rust library and clean bindings for various languages:

  * **Core Logic:** Implemented in Rust for performance and security.
  * **Language Bindings:** Available for Python, Elixir, and TypeScript/Node.js.

### Key Security Guarantees

`bubbleproc` enforces a strict least-privilege policy by default:

| Feature | Default State | Description |
| :--- | :--- | :--- |
| **Secrets Protection** | Blocked | Sensitive user paths (`.ssh`, `.aws`, `.npmrc`, etc.) are hidden, even if the user's home directory is shared. |
| **System Paths** | Read-Only | Essential system directories (`/usr`, `/bin`, `/etc`, `/lib`, etc.) are mounted Read-Only. Attempts to write to them will fail. |
| **Network Access** | Disabled | All network communication is blocked unless explicitly enabled via a configuration flag. |
| **Environment** | Cleaned | Only essential environment variables are passed unless explicitly listed in a passthrough list. |
| **Filesystem** | Ephemeral | The sandbox uses an empty, temporary filesystem for directories not explicitly bound (`/tmp`, `/home`, etc.). |

-----

### Quick Start (Python Example)

```python
from bubbleproc import run

# Run a command with read-write access only to your project directory.
# Network access is blocked by default.
result = run("python script.py", rw=["~/myproject"])

# Run an external tool that needs network access and safe R/W access to code
result = run("npm install", rw=["~/myproject"], network=True)
```

### Installation

1.  **Install `bubblewrap` (bwrap)**
    `bubblewrap` is a prerequisite for `bubbleproc` and is a standard Linux utility for unprivileged containerization.

    ```bash
    # Ubuntu/Debian
    sudo apt install bubblewrap

    # Fedora
    sudo dnf install bubblewrap

    # Arch
    sudo pacman -S bubblewrap
    ```

2.  **Install Language Bindings**
    The core logic is compiled from Rust when installing the binding for your target language.

      * **Python:** (Refer to `bindings/python/README.md`)
      * **Elixir:** (Refer to `bindings/elixir/README.md`)
      * **TypeScript/Node.js:** (Refer to `bindings/typescript/README.md`)

-----

### Architecture and Structure

The project is structured around a stable Rust core that exposes functionality through idiomatic language wrappers.

| Component | Location | Description |
| :--- | :--- | :--- |
| **Core Logic** | `crates/bubbleproc-core` | Contains the configuration model, error handling, and security validation rules (e.g., the forbidden secrets list). |
| **Linux Runtime** | `crates/bubbleproc-linux` | Handles the low-level interaction with `bubblewrap` (command argument construction, execution, and environment setup). |
| **CLI** | `crates/bubbleproc-cli` | The standalone binary wrapper, primarily for testing and manual execution. |
| **Python Bindings** | `bindings/python` | Provides the Python API (`run`, `Sandbox`, `patch_subprocess`) using Rust FFI. |
| **Elixir Bindings** | `bindings/elixir` | Provides the Elixir API using Rust NIFs (Native Implemented Functions). |
| **TypeScript Bindings** | `bindings/typescript` | Provides the Node.js/TypeScript API, likely using Node FFI or a companion binary. |

-----

### Secrets Protection Details

When a user requests to share their home directory (`share_home=True`), `bubbleproc` does not simply expose the entire directory. Instead, it checks a hard-coded list of common credential paths and overlays them with a temporary, empty filesystem, effectively hiding the host file from the sandboxed process.

| Category | Paths Blocked (Example) |
| :--- | :--- |
| **SSH/GPG** | `.ssh`, `.gnupg`, `.pki` |
| **Cloud** | `.aws`, `.azure`, `.gcloud`, `.kube` |
| **Package Tokens** | `.npmrc`, `.pypirc`, `.cargo/credentials` |
| **Password Managers** | `.password-store`, `.config/keybase` |
| **Browser Data** | `.mozilla`, `.config/google-chrome` |

### Security Considerations

While built with security in mind, this toolkit provides **defense-in-depth** and is not a complete security guarantee:

  * It blocks common, high-value attack vectors.
  * It does not block all possible bypasses (a determined attacker could potentially find kernel or `bubblewrap` exploits).
  * The goal is to prevent **accidental damage** and **opportunistic attacks** from untrusted build steps or AI agents, not to contain sophisticated, targeted adversaries.

### Requirements

  * Linux Operating System (required by `bubblewrap`)
  * `bubblewrap` (`bwrap`) installed in the host environment.

### License

MIT