use pyo3::prelude::*;
use bubbleproc_core::Config;
use std::collections::HashMap;

#[pyclass(module = "bubbleproc._bubbleproc_rs")]
struct Sandbox {
    config: Config,
}

#[pymethods]
impl Sandbox {
    #[new]
    #[pyo3(signature = (ro=None, rw=None, network=false, gpu=false, share_home=false, env=None, env_passthrough=None, allow_secrets=None, cwd=None))]
    fn new(
        ro: Option<Vec<String>>, 
        rw: Option<Vec<String>>, 
        network: bool, 
        gpu: bool,
        share_home: bool,
        env: Option<HashMap<String, String>>,
        env_passthrough: Option<Vec<String>>,
        allow_secrets: Option<Vec<String>>,
        cwd: Option<String>
    ) -> Self {
        Sandbox {
            config: Config {
                ro: ro.unwrap_or_default(),
                rw: rw.unwrap_or_default(),
                network,
                gpu,
                share_home,
                env: env.unwrap_or_default(),
                env_passthrough: env_passthrough.unwrap_or_default(),
                allow_secrets: allow_secrets.unwrap_or_default(),
                cwd,
            }
        }
    }

    // The core execution function called by the Python wrapper
    fn run(&self, command: String, args: Vec<String>) -> PyResult<(i32, String, String)> {
        let output = bubbleproc_linux::run_command(&self.config, &command, &args)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        
        Ok((
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }
}

#[pymodule]
fn _bubbleproc_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Sandbox>()?;
    Ok(())
}
