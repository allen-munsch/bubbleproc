/// Paths that are ALWAYS blocked (overlaid with empty tmpfs)
pub const SECRET_PATHS: &[&str] = &[
    ".ssh", ".gnupg", ".pki",
    ".aws", ".azure", ".gcloud", ".config/gcloud",
    ".kube", ".docker", ".helm",
    ".npmrc", ".yarnrc", ".pypirc", ".netrc",
    ".gem/credentials", ".cargo/credentials", ".cargo/credentials.toml",
    ".composer/auth.json",
    ".password-store", ".local/share/keyrings",
    ".config/op", ".config/keybase",
    ".config/gh", ".config/hub", ".config/netlify",
    ".config/heroku", ".config/doctl",
    ".mozilla", ".config/google-chrome", ".config/chromium",
    ".config/BraveSoftware", ".config/vivaldi",
    ".secrets", ".credentials", ".private",
    ".bash_history", ".zsh_history", ".python_history",
    ".psql_history", ".mysql_history", ".node_repl_history",
];

/// System paths that cannot be written to
pub const FORBIDDEN_WRITE: &[&str] = &[
    "/", "/bin", "/boot", "/etc", "/lib", "/lib64", "/lib32",
    "/opt", "/root", "/sbin", "/sys", "/usr", "/var",
];

/// Essential /etc files for system tools to work
pub const ESSENTIAL_ETC: &[&str] = &[
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/localtime",
    "/etc/ssl",
    "/etc/pki",
    "/etc/ca-certificates",
    "/etc/alternatives",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/terminfo",
];