use rustler::{Env, NifResult, Term, Encoder};
use bubbleproc_core::Config;
use std::collections::HashMap;

mod atoms {
    rustler::atoms! {
        ok,
        error,
        ro,
        rw,
        network,
        gpu,
        share_home,
        env,
        env_passthrough,
        allow_secrets,
        timeout,
        cwd
    }
}

#[rustler::nif]
fn run_command<'a>(
    env: Env<'a>,
    sandbox_term: Term<'a>,
    command: String,
    cwd_opt: Option<String>,
) -> NifResult<Term<'a>> {
    // Decode sandbox struct from Elixir term
    let config = decode_sandbox(env, sandbox_term)?;
    
    // Override cwd if provided
    let final_config = Config {
        cwd: cwd_opt.or(config.cwd),
        ..config
    };

    // Split command into executable and args
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return Ok((atoms::error(), "Empty command").encode(env));
    }

    let cmd = parts[0];
    let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

    match bubbleproc_linux::run_command(&final_config, cmd, &args) {
        Ok(output) => {
            let code = output.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            
            Ok((atoms::ok(), (code, stdout, stderr)).encode(env))
        }
        Err(e) => {
            Ok((atoms::error(), e.to_string()).encode(env))
        }
    }
}

fn decode_sandbox<'a>(env: Env<'a>, term: Term<'a>) -> NifResult<Config> {
    use rustler::types::map::MapIterator;
    
    let mut config = Config::default();
    
    // Decode the Elixir struct fields
    if let Ok(map_iter) = term.decode::<MapIterator>() {
        for (key, value) in map_iter {
            if let Ok(key_atom) = key.atom_to_string() {
                match key_atom.as_str() {
                    "ro" => {
                        if let Ok(list) = value.decode::<Vec<String>>() {
                            config.ro = list;
                        }
                    }
                    "rw" => {
                        if let Ok(list) = value.decode::<Vec<String>>() {
                            config.rw = list;
                        }
                    }
                    "network" => {
                        if let Ok(b) = value.decode::<bool>() {
                            config.network = b;
                        }
                    }
                    "gpu" => {
                        if let Ok(b) = value.decode::<bool>() {
                            config.gpu = b;
                        }
                    }
                    "share_home" => {
                        if let Ok(b) = value.decode::<bool>() {
                            config.share_home = b;
                        }
                    }
                    "env" => {
                        if let Ok(map) = value.decode::<HashMap<String, String>>() {
                            config.env = map;
                        }
                    }
                    "env_passthrough" => {
                        if let Ok(list) = value.decode::<Vec<String>>() {
                            config.env_passthrough = list;
                        }
                    }
                    "allow_secrets" => {
                        if let Ok(list) = value.decode::<Vec<String>>() {
                            config.allow_secrets = list;
                        }
                    }
                    "cwd" => {
                        config.cwd = value.decode::<Option<String>>().ok().flatten();
                    }
                    _ => {}
                }
            }
        }
    }
    
    Ok(config)
}

rustler::init!("Elixir.Bubbleproc.Native", [run_command]);
