defmodule Bubbleproc.Sandbox do
  @moduledoc """
  A reusable sandbox configuration for executing multiple commands.

  ## Example

      {:ok, sandbox} = Bubbleproc.Sandbox.new(rw: ["~/project"])
      {:ok, _} = Bubbleproc.Sandbox.run(sandbox, "npm install")
      {:ok, result} = Bubbleproc.Sandbox.run(sandbox, "npm test")
      IO.puts(result.stdout)
  """

  alias Bubbleproc.{Native, Error}

  @type t :: %__MODULE__{ 
          ro: [String.t()],
          rw: [String.t()],
          network: boolean(),
          gpu: boolean(),
          share_home: boolean(),
          env: %{String.t() => String.t()},
          env_passthrough: [String.t()],
          allow_secrets: [String.t()],
          timeout: non_neg_integer() | nil,
          cwd: String.t() | nil
        }

  defstruct ro: [],
            rw: [],
            network: false,
            gpu: false,
            share_home: false,
            env: %{},
            env_passthrough: [],
            allow_secrets: [],
            timeout: nil,
            cwd: nil

  @secret_paths [
    ".ssh", ".gnupg", ".pki",
    ".aws", ".azure", ".gcloud", ".config/gcloud",
    ".kube", ".docker", ".helm",
    ".npmrc", ".yarnrc", ".pypirc", ".netrc",
    ".gem/credentials", ".cargo/credentials",
    ".password-store", ".local/share/keyrings",
    ".config/op", ".config/keybase",
    ".config/gh", ".config/hub",
    ".secrets", ".credentials", ".private",
    ".bash_history", ".zsh_history"
  ]

  @forbidden_write [
    "/", "/bin", "/boot", "/etc", "/lib", "/lib64", "/lib32",
    "/opt", "/root", "/sbin", "/sys", "/usr", "/var"
  ]

  @doc """
  Create a new sandbox with the given options.

  ## Options

  See `Bubbleproc.run/2` for available options.
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, Error.t()}
  def new(opts \\ []) do
    sandbox = %__MODULE__{ 
      ro: Keyword.get(opts, :ro, []),
      rw: Keyword.get(opts, :rw, []),
      network: Keyword.get(opts, :network, false),
      gpu: Keyword.get(opts, :gpu, false),
      share_home: Keyword.get(opts, :share_home, false),
      env: Keyword.get(opts, :env, %{}),
      env_passthrough: Keyword.get(opts, :env_passthrough, []),
      allow_secrets: Keyword.get(opts, :allow_secrets, []),
      timeout: Keyword.get(opts, :timeout),
      cwd: Keyword.get(opts, :cwd)
    }

    with :ok <- validate_bwrap(),
         :ok <- validate_rw_paths(sandbox.rw) do
      {:ok, sandbox}
    end
  end

  @doc """
  Run a command in the sandbox.
  """
  @spec run(t(), String.t(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def run(%__MODULE__{} = sandbox, command, opts \\ []) do
    cwd = Keyword.get(opts, :cwd, sandbox.cwd)

    case Native.run_command(sandbox, command, cwd) do
      {:ok, {code, stdout, stderr}} ->
        {:ok, %{code: code, stdout: stdout, stderr: stderr}}

      {:error, reason} ->
        {:error, %Error{message: reason}}
    end
  end

  @doc """
  Run a command and return its output. Raises on error.
  """
  @spec run!(t(), String.t(), keyword()) :: String.t()
  def run!(%__MODULE__{} = sandbox, command, opts \\ []) do
    case run(sandbox, command, opts) do
      {:ok, %{code: 0, stdout: stdout}} ->
        stdout

      {:ok, %{code: code, stderr: stderr}} ->
        raise Error, "Command failed with code #{code}: #{stderr}"

      {:error, error} ->
        raise error
    end
  end

  # Private functions

  defp validate_bwrap do
    case System.find_executable("bwrap") do
      nil ->
        {:error, %Error{message: "bubblewrap (bwrap) not found. Install with: apt install bubblewrap"}}

      _path ->
        :ok
    end
  end

  defp validate_rw_paths(paths) do
    Enum.reduce_while(paths, :ok, fn path, :ok ->
      resolved = resolve_path(path)

      if forbidden_write?(resolved) do
        {:halt, {:error, %Error{message: "Write access to '#{resolved}' is forbidden (system path)"}}}
      else
        {:cont, :ok}
      end
    end)
  end

  defp resolve_path("~" <> rest) do
    Path.expand("~" <> rest)
  end

  defp resolve_path(path), do: Path.expand(path)

  defp forbidden_write?(resolved) do
    Enum.any?( @forbidden_write, fn forbidden ->
      resolved == forbidden or String.starts_with?(resolved, forbidden <> "/")
    end)
  end
end
