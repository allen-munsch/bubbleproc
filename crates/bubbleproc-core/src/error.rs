use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Bubblewrap (bwrap) executable not found in PATH")]
    BwrapNotFound,
    #[error("Path resolution error: {0}")]
    PathError(String),
    #[error("I/O Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Command execution failed with status: {0}")]
    ExecutionFailed(i32),
    #[error("Serialization/Deserialization error: {0}")]
    Serialization(String),
    #[error("Security Violation: {0}")]
    SecurityViolation(String),
}

pub type Result<T> = std::result::Result<T, SandboxError>;
