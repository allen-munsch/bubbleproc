use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub ro: Vec<String>,
    pub rw: Vec<String>,
    pub network: bool,
    pub gpu: bool, // Added GPU support
    pub share_home: bool,
    pub env: HashMap<String, String>,
    pub env_passthrough: Vec<String>,
    pub allow_secrets: Vec<String>,
    pub cwd: Option<String>,
}
