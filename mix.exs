defmodule FeistelCipher.MixProject do
  use Mix.Project

  def project do
    [
      app: :feistel_cipher,
      version: "0.2.0",
      elixir: "~> 1.17",
      consolidate_protocols: Mix.env() not in [:dev, :test],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "A Ecto migration for Feistel cipher",
      package: package(),
      source_url: "https://github.com/devall-org/feistel_cipher",
      homepage_url: "https://github.com/devall-org/feistel_cipher",
      docs: [
        main: "readme",
        extras: ["README.md"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:igniter, "~> 0.6", optional: true},
      {:ecto_sql, "~> 3.12"},
      {:ex_doc, "~> 0.29", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: "feistel_cipher",
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/devall-org/feistel_cipher"
      }
    ]
  end
end
