use bubbleproc_core::{Config, Result, SandboxError};
use bubbleproc_core::constants::{SECRET_PATHS, ESSENTIAL_ETC, FORBIDDEN_WRITE};
use std::process::Command;
use std::path::{Path, PathBuf};

/// Expands tilde and resolves the absolute path.
fn resolve_path(path: &str) -> String {
    shellexpand::tilde(path).to_string()
}

/// Checks if a path is a forbidden system path for read-write access.
fn is_forbidden_write(resolved_path: &str) -> bool {
    for forbidden in FORBIDDEN_WRITE {
        if resolved_path == *forbidden || resolved_path.starts_with(&format!("{}/", forbidden)) {
            return true;
        }
    }
    false
}


pub fn run_command(config: &Config, command: &str, args: &[String]) -> Result<std::process::Output> {
    let bwrap_path = which::which("bwrap").map_err(|_| SandboxError::BwrapNotFound)?;
    let mut cmd = Command::new(bwrap_path);

    // --- 1. Isolation & Namespace Flags ---
    cmd.args(&["--unshare-user", "--unshare-pid", "--unshare-uts", 
               "--unshare-ipc", "--unshare-cgroup", "--die-with-parent", 
               "--new-session", "--hostname", "sandbox", 
               "--cap-drop", "ALL"]);
    
    if !config.network {
        cmd.arg("--unshare-net");
    }

    // --- 2. Base System & Devices ---
    cmd.args(&["--ro-bind", "/", "/"]);
    cmd.args(&["--proc", "/proc", "--dev", "/dev"]);

    
    // Standard devices
    for dev in &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty"] {
        if Path::new(dev).exists() { cmd.args(&["--dev-bind", dev, dev]); }
    }

    // GPU Support (from Python sketch)
    if config.gpu {
        if Path::new("/dev/dri").exists() { cmd.args(&["--dev-bind", "/dev/dri", "/dev/dri"]); }
        for entry in glob::glob("/dev/nvidia*").unwrap().flatten() {
            if entry.exists() {
                cmd.args(&["--dev-bind", entry.to_str().unwrap(), entry.to_str().unwrap()]);
            }
        }
    }

    // --- 3. Read-Only System Mounts ---
    for dir in &["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32"] {
        if Path::new(dir).exists() { cmd.args(&["--ro-bind", dir, dir]); }
    }

    // Mount a writable tmpfs on /etc and then bind mount essential files into it.
    cmd.args(&["--tmpfs", "/etc"]);
    // Essential /etc files
    for file in ESSENTIAL_ETC {
        if Path::new(file).exists() { cmd.args(&["--ro-bind", file, file]); }
    }

    // --- 4. Ephemeral Mounts ---
    cmd.args(&["--tmpfs", "/tmp", "--tmpfs", "/run", "--tmpfs", "/var/tmp"]);

    // --- 5. Home Directory & Secrets Logic ---
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    
    if config.share_home {
        cmd.args(&["--ro-bind", &home, &home]);
        
        // Hide secrets by overlaying them with tmpfs
        for secret in SECRET_PATHS {
            if config.allow_secrets.contains(&secret.to_string()) { continue; }

            let secret_path = PathBuf::from(&home).join(secret);
            if secret_path.exists() {
                cmd.args(&["--tmpfs", secret_path.to_str().unwrap()]);
            }
        }
    } else {
        // Empty fake home, but create essential subdirectories
        cmd.args(&["--tmpfs", &home]);
        for subdir in &[".cache", ".config", ".local/share"] {
            let p = PathBuf::from(&home).join(subdir);
            cmd.args(&["--dir", p.to_str().unwrap()]);
        }
    }

    // --- 6. User Configured Mounts ---
    for path in &config.ro {
        let p = resolve_path(path);
        if Path::new(&p).exists() { cmd.args(&["--ro-bind", &p, &p]); }
    }
    for path in &config.rw {
        let p = resolve_path(path);
        if is_forbidden_write(&p) {
            return Err(SandboxError::SecurityViolation(format!("Write access to '{}' is forbidden (system path)", p)));
        }
        if Path::new(&p).exists() { cmd.args(&["--bind", &p, &p]); }
    }

    // --- 7. Environment Variables ---
    cmd.env_clear();
    cmd.env("HOME", &home);
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    
    // Explicit environment variables
    for (k, v) in &config.env { cmd.env(k, v); }
    // Pass-throughs
    for k in &config.env_passthrough {
        if let Ok(v) = std::env::var(k) { cmd.env(k, v); }
    }

    // --- 8. Execution ---
    let effective_cwd = match &config.cwd {
        Some(cwd) => resolve_path(cwd),
        None => "/tmp".to_string(), // Default safe CWD
    };
    cmd.arg("--chdir");
    cmd.arg(effective_cwd);

    cmd.arg("--");
    cmd.arg(command);
    cmd.args(args);

    eprintln!("Executing bwrap command: {:?}", cmd); // Debug line

    let output = cmd.output()?;

    // Check exit status
    if output.status.code().is_none() {
        return Err(SandboxError::ExecutionFailed(-1));
    }
    
    Ok(output)
}
