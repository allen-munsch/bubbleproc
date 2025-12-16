defmodule Bubbleproc.Native do
  @moduledoc false
  # NIF bindings to the Rust implementation

  use Rustler,
    otp_app: :bubbleproc,
    crate: :bubbleproc_nif

  @doc """
  Run a command in the sandbox using the Rust implementation.
  """
  @spec run_command(Bubbleproc.Sandbox.t(), String.t(), String.t() | nil) ::
          {:ok, {integer(), String.t(), String.t()}} | {:error, String.t()}
  def run_command(_sandbox, _command, _cwd) do
    :erlang.nif_error(:nif_not_loaded)
  end
end
