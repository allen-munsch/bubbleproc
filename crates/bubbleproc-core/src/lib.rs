use std::collections::HashMap;
use thiserror::Error;

pub mod constants;
pub use constants::*;

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("bubblewrap (bwrap) not found in PATH")]
    BwrapNotFound,

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Command failed: {0}")]
    CommandFailed(String),
}

pub type Result<T> = std::result::Result<T, SandboxError>;

/// Sandbox configuration
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Paths to mount read-only
    pub ro: Vec<String>,
    /// Paths to mount read-write
    pub rw: Vec<String>,
    /// Allow network access
    pub network: bool,
    /// Allow GPU device access
    pub gpu: bool,
    /// Mount $HOME read-only with secrets blocked
    pub share_home: bool,
    /// Environment variables to set
    pub env: HashMap<String, String>,
    /// Environment variables to pass through from host
    pub env_passthrough: Vec<String>,
    /// Secret paths to allow (e.g., [".gnupg"])
    pub allow_secrets: Vec<String>,
    /// Working directory inside sandbox
    pub cwd: Option<String>,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rw(mut self, paths: Vec<String>) -> Self {
        self.rw = paths;
        self
    }

    pub fn with_ro(mut self, paths: Vec<String>) -> Self {
        self.ro = paths;
        self
    }

    pub fn with_network(mut self, enabled: bool) -> Self {
        self.network = enabled;
        self
    }

    pub fn with_share_home(mut self, enabled: bool) -> Self {
        self.share_home = enabled;
        self
    }

    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = env;
        self
    }

    pub fn with_env_passthrough(mut self, vars: Vec<String>) -> Self {
        self.env_passthrough = vars;
        self
    }

    pub fn with_cwd(mut self, cwd: Option<String>) -> Self {
        self.cwd = cwd;
        self
    }
}