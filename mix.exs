defmodule FeistelCipher.MixProject do
  use Mix.Project

  def project do
    [
      app: :feistel_cipher,
      version: "0.13.2",
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      consolidate_protocols: Mix.env() not in [:dev, :test],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Encrypted integer IDs using Feistel cipher",
      package: package(),
      source_url: "https://github.com/devall-org/feistel_cipher",
      homepage_url: "https://github.com/devall-org/feistel_cipher",
      docs: [
        main: "readme",
        extras: ["README.md"],
        assets: %{"assets" => "assets"},
        before_closing_body_tag: fn
          :html ->
            """
            <script>
            MathJax = {
              tex: {
                inlineMath: [['$', '$'], ['\\\\(', '\\\\)']],
                displayMath: [['$$', '$$'], ['\\\\[', '\\\\]']]
              }
            };
            </script>
            <script src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js" async></script>
            """

          _ ->
            ""
        end
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

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
      {:postgrex, "~> 0.19", only: :test},
      {:benchee, "~> 1.0", only: [:dev, :test]},
      {:ex_doc, "~> 0.29", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: "feistel_cipher",
      licenses: ["MIT"],
      maintainers: ["Jechol Lee"],
      links: %{
        "GitHub" => "https://github.com/devall-org/feistel_cipher"
      },
      files: ~w(lib mix.exs README.md LICENSE assets)
    ]
  end
end
