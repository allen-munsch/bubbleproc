use bubbleproc_core::constants::{ESSENTIAL_ETC, FORBIDDEN_WRITE, SECRET_PATHS};
use bubbleproc_core::{Config, Result, SandboxError};
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

/// Expand ~ to home directory
fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, &path[2..]);
        }
    } else if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

/// Check if path is forbidden for write access
fn is_forbidden_write(path: &str) -> bool {
    let resolved = expand_tilde(path);
    for forbidden in FORBIDDEN_WRITE {
        if resolved == *forbidden || resolved.starts_with(&format!("{}/", forbidden)) {
            return true;
        }
    }
    false
}

/// Validate configuration, returns error if invalid
pub fn validate_config(config: &Config) -> Result<()> {
    for path in &config.rw {
        let resolved = expand_tilde(path);
        if is_forbidden_write(&resolved) {
            return Err(SandboxError::SecurityViolation(format!(
                "Write access to '{}' is forbidden (system path)",
                resolved
            )));
        }
    }
    Ok(())
}

/// Check if bwrap is available on this system
pub fn is_bwrap_available() -> bool {
    find_bwrap_path().is_some()
}

/// Find the path to bwrap executable
pub fn find_bwrap_path() -> Option<String> {
    // Check common locations
    for path in &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"] {
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    // Try which command
    if let Ok(output) = std::process::Command::new("which").arg("bwrap").output() {
        if output.status.success() {
            if let Ok(path) = String::from_utf8(output.stdout) {
                let trimmed = path.trim().to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
    }

    None
}

/// Build bwrap arguments from config
pub fn build_bwrap_args(config: &Config, shell_command: &str) -> Result<Vec<String>> {
    let mut args: Vec<String> = Vec::new();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let user = std::env::var("USER").unwrap_or_else(|_| "sandbox".to_string());

    // === 1. Namespace Isolation ===
    args.push("--unshare-user".into());
    args.push("--unshare-pid".into());
    args.push("--unshare-uts".into());
    args.push("--unshare-ipc".into());
    args.push("--unshare-cgroup".into());

    if !config.network {
        args.push("--unshare-net".into());
    }

    // === 2. Security Flags ===
    args.push("--die-with-parent".into());
    args.push("--new-session".into());
    args.push("--hostname".into());
    args.push("sandbox".into());
    args.push("--cap-drop".into());
    args.push("ALL".into());

    // === 3. /proc and /dev ===
    args.push("--proc".into());
    args.push("/proc".into());
    args.push("--dev".into());
    args.push("/dev".into());

    for dev in &[
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/tty",
    ] {
        if Path::new(dev).exists() {
            args.push("--dev-bind-try".into());
            args.push(dev.to_string());
            args.push(dev.to_string());
        }
    }

    // === 4. GPU Access ===
    if config.gpu {
        if Path::new("/dev/dri").exists() {
            args.push("--dev-bind".into());
            args.push("/dev/dri".into());
            args.push("/dev/dri".into());
        }
        if let Ok(entries) = std::fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("nvidia") {
                    let path = format!("/dev/{}", name_str);
                    args.push("--dev-bind".into());
                    args.push(path.clone());
                    args.push(path);
                }
            }
        }
    }

    // === 5. Read-Only System Mounts ===
    for dir in &["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32"] {
        if Path::new(dir).is_dir() {
            args.push("--ro-bind".into());
            args.push(dir.to_string());
            args.push(dir.to_string());
        }
    }

    // === 6. /etc Handling (tmpfs + essential files) ===
    args.push("--tmpfs".into());
    args.push("/etc".into());

    for file in ESSENTIAL_ETC {
        if Path::new(file).exists() {
            args.push("--ro-bind-try".into());
            args.push(file.to_string());
            args.push(file.to_string());
        }
    }

    // === 7. Ephemeral Mounts ===
    args.push("--tmpfs".into());
    args.push("/tmp".into());
    args.push("--tmpfs".into());
    args.push("/run".into());
    args.push("--tmpfs".into());
    args.push("/var/tmp".into());

    // === 8. Home Directory Handling ===
    if config.share_home {
        // Mount home read-only
        args.push("--ro-bind".into());
        args.push(home.clone());
        args.push(home.clone());

        // Block secrets by overlaying with tmpfs
        for secret in SECRET_PATHS {
            if config.allow_secrets.iter().any(|s| s == secret) {
                continue;
            }
            let secret_path = format!("{}/{}", home, secret);
            if Path::new(&secret_path).exists() {
                args.push("--tmpfs".into());
                args.push(secret_path);
            }
        }
    } else {
        // Empty home with essential subdirectories
        args.push("--tmpfs".into());
        args.push(home.clone());

        for subdir in &[".cache", ".config", ".local/share"] {
            args.push("--dir".into());
            args.push(format!("{}/{}", home, subdir));
        }
    }

    // === 9. User RO Mounts ===
    for path in &config.ro {
        let resolved = expand_tilde(path);
        if Path::new(&resolved).exists() {
            args.push("--ro-bind".into());
            args.push(resolved.clone());
            args.push(resolved);
        }
    }

    // === 10. User RW Mounts ===
    for path in &config.rw {
        let resolved = expand_tilde(path);
        if Path::new(&resolved).exists() {
            args.push("--bind".into());
            args.push(resolved.clone());
            args.push(resolved);
        }
    }

    // === 11. Environment Variables (CRITICAL: use --setenv) ===
    args.push("--setenv".into());
    args.push("HOME".into());
    args.push(home.clone());

    args.push("--setenv".into());
    args.push("USER".into());
    args.push(user.clone());

    args.push("--setenv".into());
    args.push("LOGNAME".into());
    args.push(user);

    args.push("--setenv".into());
    args.push("PATH".into());
    args.push("/usr/local/bin:/usr/bin:/bin".into());

    args.push("--setenv".into());
    args.push("TMPDIR".into());
    args.push("/tmp".into());

    // TERM
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());
    args.push("--setenv".into());
    args.push("TERM".into());
    args.push(term);

    // LANG
    let lang = std::env::var("LANG").unwrap_or_else(|_| "C.UTF-8".into());
    args.push("--setenv".into());
    args.push("LANG".into());
    args.push(lang);

    // Pass through requested env vars
    for key in &config.env_passthrough {
        if let Ok(val) = std::env::var(key) {
            args.push("--setenv".into());
            args.push(key.clone());
            args.push(val);
        }
    }

    // Add explicit env vars
    for (key, val) in &config.env {
        args.push("--setenv".into());
        args.push(key.clone());
        args.push(val.clone());
    }

    // === 12. Working Directory ===
    let cwd = config.cwd.clone().unwrap_or_else(|| {
        // Try to find a suitable directory from rw paths
        for path in &config.rw {
            let resolved = expand_tilde(path);
            let p = Path::new(&resolved);
            if p.is_dir() {
                return resolved;
            } else if p.is_file() {
                if let Some(parent) = p.parent() {
                    if parent.is_dir() {
                        return parent.to_string_lossy().to_string();
                    }
                }
            }
        }
        // Try ro paths
        for path in &config.ro {
            let resolved = expand_tilde(path);
            let p = Path::new(&resolved);
            if p.is_dir() {
                return resolved;
            } else if p.is_file() {
                if let Some(parent) = p.parent() {
                    if parent.is_dir() {
                        return parent.to_string_lossy().to_string();
                    }
                }
            }
        }
        "/tmp".to_string()
    });
    args.push("--chdir".into());
    args.push(cwd);

    // === 13. Command (CRITICAL: wrap in sh -c) ===
    args.push("--".into());
    args.push("sh".into());
    args.push("-c".into());
    args.push(shell_command.to_string());

    Ok(args)
}

/// Run a shell command in the sandbox
pub fn run_shell_command(config: &Config, shell_command: &str) -> Result<Output> {
    // Validate config first
    validate_config(config)?;

    // Find bwrap
    let bwrap_path = which::which("bwrap").map_err(|_| SandboxError::BwrapNotFound)?;

    // Build bwrap arguments (includes --setenv for env vars)
    let bwrap_args = build_bwrap_args(config, shell_command)?;

    // Debug: print command
    if std::env::var("BUBBLEPROC_DEBUG").is_ok() {
        eprintln!(
            "Executing bwrap command: {} {}",
            bwrap_path.display(),
            bwrap_args
                .iter()
                .map(|s| format!("\"{}\"", s))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }

    // Execute bwrap with clean environment
    // CRITICAL: env_clear() prevents leaking host environment variables
    let output = Command::new(&bwrap_path)
        .env_clear()
        .args(&bwrap_args)
        .output()?;

    Ok(output)
}

/// Result of command execution
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run a shell command and return structured result
pub fn run_command(config: &Config, shell_command: &str) -> Result<CommandResult> {
    let output = run_shell_command(config, shell_command)?;

    Ok(CommandResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}
