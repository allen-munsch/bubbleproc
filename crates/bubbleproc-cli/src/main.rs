use bubbleproc_core::Config;
use clap::Parser;
use std::process;

#[derive(Parser, Debug)]
#[command(author, version, about = "Run commands in a bubblewrap sandbox")]
struct Args {
    /// Read-only mounts
    #[arg(long)]
    ro: Vec<String>,

    /// Read-write mounts
    #[arg(long)]
    rw: Vec<String>,

    /// Allow network access
    #[arg(long)]
    network: bool,

    /// Allow GPU device access
    #[arg(long)]
    gpu: bool,

    /// Mount $HOME read-only with secrets hidden
    #[arg(long)]
    share_home: bool,

    /// Set environment variable (KEY=VALUE)
    #[arg(long, value_parser = parse_env)]
    env: Vec<(String, String)>,

    /// Pass through environment variable from host
    #[arg(long)]
    env_passthrough: Vec<String>,

    /// Allow access to specific secret paths
    #[arg(long)]
    allow_secret: Vec<String>,

    /// Working directory inside sandbox
    #[arg(long)]
    cwd: Option<String>,

    /// Command to execute (after --)
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn parse_env(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() == 2 {
        Ok((parts[0].to_string(), parts[1].to_string()))
    } else {
        Err(format!("Invalid KEY=VALUE: {}", s))
    }
}

/// Shell-quote a string if it contains special characters
fn shell_quote(s: &str) -> String {
    // Characters that need quoting
    let needs_quoting = s.is_empty()
        || s.contains(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '"' | '\''
                        | '\\'
                        | '$'
                        | '`'
                        | '!'
                        | '*'
                        | '?'
                        | '['
                        | ']'
                        | '('
                        | ')'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                        | '|'
                        | '&'
                        | ';'
                        | '#'
                        | '~'
                )
        });

    if needs_quoting {
        // Use single quotes, escaping any single quotes in the string
        format!("'{}'", s.replace("'", "'\\''"))
    } else {
        s.to_string()
    }
}

fn main() {
    let args = Args::parse();

    if args.command.is_empty() {
        eprintln!("Usage: bubbleproc [OPTIONS] -- <COMMAND>");
        process::exit(1);
    }

    // Join command parts into shell command string, with proper quoting
    let shell_command = args
        .command
        .iter()
        .map(|s| shell_quote(s))
        .collect::<Vec<_>>()
        .join(" ");

    let config = Config {
        ro: args.ro,
        rw: args.rw,
        network: args.network,
        gpu: args.gpu,
        share_home: args.share_home,
        env: args.env.into_iter().collect(),
        env_passthrough: args.env_passthrough,
        allow_secrets: args.allow_secret,
        cwd: args.cwd,
    };

    match bubbleproc_linux::run_shell_command(&config, &shell_command) {
        Ok(output) => {
            use std::io::Write;
            std::io::stdout().write_all(&output.stdout).ok();
            std::io::stderr().write_all(&output.stderr).ok();
            process::exit(output.status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!("bubbleproc error: {}", e);
            process::exit(1);
        }
    }
}
