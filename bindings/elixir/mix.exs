defmodule Bubbleproc.MixProject do
  use Mix.Project

  @version "1.0.0"
  @source_url "https://github.com/your-org/bubbleproc"

  def project do
    [
      app: :bubbleproc,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.30"},
      {:ex_doc, "~> 0.30", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    Bubblewrap sandboxing for Elixir - protect against AI coding tool damage.
    Provides secure subprocess execution with isolation from secrets and system resources.
    """
  end

  defp package do
    [
      name: "bubbleproc",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url
      },
      files: ~w(lib native .formatter.exs mix.exs README.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "Bubbleproc",
      source_url: @source_url,
      extras: ["README.md"]
    ]
  end
end