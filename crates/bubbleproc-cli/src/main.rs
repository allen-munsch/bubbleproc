use clap::Parser;
use bubbleproc_core::Config;
use std::process;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, help = "Read-only mounts (e.g., --ro /data)")]
    ro: Vec<String>,

    #[arg(long, help = "Read-write mounts (e.g., --rw ~/project)")]
    rw: Vec<String>,

    #[arg(long, help = "Allow network access")]
    network: bool,

    #[arg(long, help = "Allow GPU device access (/dev/dri, /dev/nvidia*)")]
    gpu: bool,

    #[arg(long, help = "Mount $HOME read-only, hiding known secret paths")]
    share_home: bool,

    #[arg(long, value_parser = parse_env, help = "Set environment variable (e.g., --env KEY=VALUE)")]
    env: Vec<(String, String)>,

    #[arg(last = true, required = true, help = "The command and its arguments, separated by --")]
    command: Vec<String>,
}

fn parse_env(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() == 2 {
        Ok((parts[0].to_string(), parts[1].to_string()))
    } else {
        Err(format!("Invalid KEY=VALUE format: {}", s))
    }
}

fn main() {
    let args = Args::parse();
    
    if args.command.is_empty() { 
        eprintln!("Usage: bubbleproc [options] -- <command> [args...]");
        process::exit(1); 
    }

    let config = Config {
        ro: args.ro,
        rw: args.rw,
        network: args.network,
        gpu: args.gpu,
        share_home: args.share_home,
        env: args.env.into_iter().collect(),
        // CLI typically doesn't handle dynamic env_passthrough easily, omitting here.
        ..Default::default()
    };

    let cmd = &args.command[0];
    let cmd_args = &args.command[1..];

    match bubbleproc_linux::run_command(&config, cmd, cmd_args) {
        Ok(output) => {
            use std::io::Write;
            std::io::stdout().write_all(&output.stdout).ok();
            std::io::stderr().write_all(&output.stderr).ok();
            process::exit(output.status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("Bubbleproc Error: {}", e);
            process::exit(1);
        }
    }
}
