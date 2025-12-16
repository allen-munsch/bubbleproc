// Paths that are ALWAYS blocked (overlaid with empty tmpfs)
pub const SECRET_PATHS: &[&str] = &[
    ".ssh", ".gnupg", ".pki", ".aws", ".azure", ".gcloud", ".config/gcloud", 
    ".kube", ".docker", ".helm", ".npmrc", ".yarnrc", ".pypirc", ".netrc",
    ".gem", ".cargo/credentials", ".password-store", ".local/share/keyrings", 
    ".secrets", ".private", ".bash_history", ".zsh_history", ".python_history", 
    ".node_repl_history", ".config/gh", ".config/heroku", ".config/doctl",
    ".config/op", ".config/keybase" // Added password managers
];

// System paths that cannot be written to
pub const FORBIDDEN_WRITE: &[&str] = &[
    "/", "/bin", "/boot", "/etc", "/lib", "/lib64", "/lib32",
    "/opt", "/root", "/sbin", "/sys", "/usr", "/var",
];

// Essential files for networking/system tools to work (DNS + SSL)
pub const ESSENTIAL_ETC: &[&str] = &[
    "/etc/resolv.conf", "/etc/hosts", "/etc/localtime", 
    "/etc/passwd", "/etc/group", // Needed for user lookups
    "/etc/ssl", "/etc/pki", "/etc/ca-certificates",
    "/etc/alternatives" 
];
