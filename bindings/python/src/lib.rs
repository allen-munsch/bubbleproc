use bubbleproc_core::{Config, SandboxError};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::collections::HashMap;

/// Essential environment variables for basic shell functionality.
/// These are always passed through even if not explicitly requested.
const ESSENTIAL_ENV_VARS: &[&str] = &[
    "PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR",
];

/// Convert SandboxError to PyErr
fn to_py_err(e: SandboxError) -> PyErr {
    PyRuntimeError::new_err(format!("{}", e))
}

/// Ensure essential env vars are in the passthrough list
fn ensure_essential_env_vars(env_passthrough: &mut Vec<String>) {
    for var in ESSENTIAL_ENV_VARS {
        let var_string = var.to_string();
        if !env_passthrough.contains(&var_string) {
            env_passthrough.push(var_string);
        }
    }
}

/// Python-exposed Sandbox class
#[pyclass]
pub struct Sandbox {
    config: Config,
}

#[pymethods]
impl Sandbox {
    #[new]
    #[pyo3(signature = (
        ro = Vec::new(),
        rw = Vec::new(),
        network = false,
        gpu = false,
        share_home = false,
        env = HashMap::new(),
        env_passthrough = Vec::new(),
        allow_secrets = Vec::new(),
        cwd = None
    ))]
    fn new(
        ro: Vec<String>,
        rw: Vec<String>,
        network: bool,
        gpu: bool,
        share_home: bool,
        env: HashMap<String, String>,
        mut env_passthrough: Vec<String>,
        allow_secrets: Vec<String>,
        cwd: Option<String>,
    ) -> PyResult<Self> {
        // Always ensure essential env vars are passed through
        ensure_essential_env_vars(&mut env_passthrough);

        let config = Config {
            ro,
            rw,
            network,
            gpu,
            share_home,
            env,
            env_passthrough,
            allow_secrets,
            cwd,
        };

        // Validate config
        bubbleproc_linux::validate_config(&config).map_err(to_py_err)?;

        Ok(Self { config })
    }

    /// Run a shell command in the sandbox
    /// Returns (exit_code, stdout, stderr)
    fn run(&self, py: Python<'_>, shell_command: &str) -> PyResult<(i32, String, String)> {
        // Clone config and command for the closure
        let config = self.config.clone();
        let command = shell_command.to_string();
        
        // Release the GIL while the subprocess runs
        let result = py.allow_threads(move || {
            bubbleproc_linux::run_command(&config, &command)
        }).map_err(to_py_err)?;
        
        Ok((result.exit_code, result.stdout, result.stderr))
    }
}

/// Module-level run function for convenience
#[pyfunction]
#[pyo3(signature = (
    command,
    ro = Vec::new(),
    rw = Vec::new(),
    network = false,
    share_home = false,
    env = HashMap::new(),
    env_passthrough = Vec::new(),
    cwd = None
))]
fn run(
    command: &str,
    ro: Vec<String>,
    rw: Vec<String>,
    network: bool,
    share_home: bool,
    env: HashMap<String, String>,
    mut env_passthrough: Vec<String>,
    cwd: Option<String>,
) -> PyResult<(i32, String, String)> {
    // Ensure essential env vars
    ensure_essential_env_vars(&mut env_passthrough);

    let config = Config {
        ro,
        rw,
        network,
        gpu: false,
        share_home,
        env,
        env_passthrough,
        allow_secrets: Vec::new(),
        cwd,
    };

    bubbleproc_linux::validate_config(&config).map_err(to_py_err)?;

    let result = bubbleproc_linux::run_command(&config, command).map_err(to_py_err)?;

    Ok((result.exit_code, result.stdout, result.stderr))
}

/// Validate a path for RW access
#[pyfunction]
fn validate_rw_path(path: &str) -> PyResult<bool> {
    let mut env_passthrough = Vec::new();
    ensure_essential_env_vars(&mut env_passthrough);

    let config = Config {
        rw: vec![path.to_string()],
        env_passthrough,
        ..Default::default()
    };

    match bubbleproc_linux::validate_config(&config) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[pymodule]
fn _bubbleproc_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Sandbox>()?;
    m.add_function(wrap_pyfunction!(run, m)?)?;
    m.add_function(wrap_pyfunction!(validate_rw_path, m)?)?;
    Ok(())
}
