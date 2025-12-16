defmodule Bubbleproc.Error do
  @moduledoc """
  Error struct for sandbox failures.
  """

  defexception [:message]

  @type t :: %__MODULE__{message: String.t()}

  @impl true
  def exception(message) when is_binary(message) do
    %__MODULE__{message: message}
  end

  def exception(opts) when is_list(opts) do
    message = Keyword.get(opts, :message, "Unknown sandbox error")
    %__MODULE__{message: message}
  end
end
