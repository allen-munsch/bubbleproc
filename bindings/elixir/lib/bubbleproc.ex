defmodule Bubbleproc do
  @moduledoc """
  Bubblewrap sandboxing for Elixir.

  Provides secure subprocess execution using Linux bubblewrap,
  protecting against accidental damage from AI coding tools.

  ## Quick Start

      # Run a command with read-write access
      {:ok, result} = Bubbleproc.run("ls -la", rw: ["~/project"])
      
      # Run with network access
      {:ok, result} = Bubbleproc.run("npm install", rw: ["~/project"], network: true)

  ## Using a Sandbox

      # Create a reusable sandbox
      {:ok, sandbox} = Bubbleproc.Sandbox.new(rw: ["~/project"], network: true)
      
      # Run multiple commands
      {:ok, _} = Bubbleproc.Sandbox.run(sandbox, "npm install")
      {:ok, result} = Bubbleproc.Sandbox.run(sandbox, "npm test")

  ## Features

  - 🔒 Secrets blocked by default (SSH keys, AWS credentials, etc.)
  - 🛡️ System paths are read-only
  - 🌐 Network disabled by default
  - ⚡ Native Rust implementation via Rustler
  """

  alias Bubbleproc.{Sandbox, Error}

  @type run_option ::
          {:ro, [String.t()]} 
          | {:rw, [String.t()]} 
          | {:network, boolean()} 
          | {:gpu, boolean()} 
          | {:share_home, boolean()} 
          | {:env, %{String.t() => String.t()}} 
          | {:env_passthrough, [String.t()]} 
          | {:allow_secrets, [String.t()]} 
          | {:timeout, non_neg_integer()} 
          | {:cwd, String.t()}

  @type run_result :: %{
          code: integer(),
          stdout: String.t(),
          stderr: String.t()
        }

  @doc """
  Run a command in a sandbox.

  ## Options

  - `:ro` - Paths to mount read-only
  - `:rw` - Paths to mount read-write
  - `:network` - Allow network access (default: false)
  - `:gpu` - Allow GPU access (default: false)
  - `:share_home` - Mount $HOME read-only with secrets blocked (default: false)
  - `:env` - Additional environment variables
  - `:env_passthrough` - Environment variables to pass from host
  - `:allow_secrets` - Secret paths to allow (e.g., [".gnupg"])
  - `:timeout` - Command timeout in milliseconds
  - `:cwd` - Working directory

  ## Examples

      iex> Bubbleproc.run("echo hello")
      {:ok, %{code: 0, stdout: "hello\n", stderr: ""}}

      iex> Bubbleproc.run("ls", rw: ["~/project"])
      {:ok, %{code: 0, stdout: "...", stderr: ""}}

      iex> Bubbleproc.run("curl https://example.com", network: true)
      {:ok, %{code: 0, stdout: "...", stderr: ""}}
  """
  @spec run(String.t(), [run_option()]) :: {:ok, run_result()} | {:error, Error.t()}
  def run(command, opts \ \[]) do
    with {:ok, sandbox} <- Sandbox.new(opts) do
      Sandbox.run(sandbox, command)
    end
  end

  @doc """
  Run a command and return only its stdout. Raises on non-zero exit.

  ## Examples

      iex> Bubbleproc.run!("echo hello")
      "hello\n"
  """
  @spec run!(String.t(), [run_option()]) :: String.t()
  def run!(command, opts \ \[]) do
    case run(command, opts) do
      {:ok, %{code: 0, stdout: stdout}} ->
        stdout

      {:ok, %{code: code, stderr: stderr}} ->
        raise Error, "Command failed with code #{code}: #{stderr}"

      {:error, error} ->
        raise error
    end
  end

  @doc """
  Create a sandbox configured for Aider CLI usage.

  ## Options

  - `:network` - Allow network for API calls (default: true)
  - `:allow_gpg` - Allow GPG for signed commits (default: false)

  ## Example

      {:ok, sandbox} = Bubbleproc.aider_sandbox("~/myproject")
      {:ok, _} = Bubbleproc.Sandbox.run(sandbox, "aider --message 'add docstrings'")
  """
  @spec aider_sandbox(String.t(), keyword()) :: {:ok, Sandbox.t()} | {:error, Error.t()}
  def aider_sandbox(project_dir, opts \ \[]) do
    network = Keyword.get(opts, :network, true)
    allow_gpg = Keyword.get(opts, :allow_gpg, false)

    allow_secrets = if allow_gpg, do: [".gnupg"], else: []

    Sandbox.new(
      rw: [project_dir],
      network: network,
      share_home: true,
      env_passthrough: [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "GOOGLE_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "TERM",
        "COLORTERM",
        "CLICOLOR",
        "FORCE_COLOR",
        "AIDER_MODEL",
        "AIDER_DARK_MODE",
        "AIDER_AUTO_COMMITS"
      ],
      allow_secrets: allow_secrets
    )
  end
end
