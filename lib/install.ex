defmodule Mix.Tasks.FeistelCipher.Install.Docs do
  @moduledoc false

  def short_doc do
    "A Ecto migration for Feistel cipher"
  end

  def example do
    "mix feistel_cipher.install"
  end

  def long_doc do
    """
    #{short_doc()}

    ## Example

    ```bash
    mix feistel_cipher.install
    ```

    * `--repo` or `-r` — Specify an Ecto repo for FeistelCipher to use
    * `--prefix` or `-p` — Specify a prefix for the FeistelCipher schema, defaults to `#{FeistelCipher.default_prefix()}`
    * `--xor` or `-x` — Specify the XOR parameter for the Feistel cipher, should be less than 2^31, defaults to `#{FeistelCipher.default_xor()}`
    * `--mul` or `-m` — Specify the MUL parameter for the Feistel cipher, should be less than 2^31, defaults to `#{FeistelCipher.default_mul()}`
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.FeistelCipher.Install do
    @shortdoc __MODULE__.Docs.short_doc()
    @moduledoc __MODULE__.Docs.long_doc()

    use Igniter.Mix.Task

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :feistel_cipher,
        adds_deps: [],
        installs: [],
        example: __MODULE__.Docs.example(),
        only: nil,
        positional: [],
        composes: [],
        schema: [repo: :string, prefix: :string, xor: :integer, mul: :integer],
        defaults: [
          prefix: FeistelCipher.default_prefix(),
          xor: FeistelCipher.default_xor(),
          mul: FeistelCipher.default_mul()
        ],
        aliases: [r: :repo, p: :prefix, x: :xor, m: :mul],
        required: []
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      app_name = Igniter.Project.Application.app_name(igniter)
      opts = igniter.args.options

      case extract_repo(igniter, app_name, opts[:repo]) do
        {:ok, repo} ->
          migration = """
          def up do
            FeistelCipher.Migration.up(prefix: "#{opts[:prefix]}", xor: #{opts[:xor]}, mul: #{opts[:mul]})
          end

          def down do
            FeistelCipher.Migration.down(prefix: "#{opts[:prefix]}", xor: #{opts[:xor]}, mul: #{opts[:mul]})
          end
          """

          igniter
          |> Igniter.Project.Formatter.import_dep(:feistel_cipher)
          |> Igniter.Libs.Ecto.gen_migration(repo, "add_feistel_cipher",
            timestamp: "19700101000000",
            body: migration,
            on_exists: :skip
          )

        {:error, igniter} ->
          igniter
      end
    end

    defp extract_repo(igniter, app_name, nil) do
      case Igniter.Libs.Ecto.list_repos(igniter) do
        {_igniter, [repo | _]} ->
          {:ok, repo}

        _ ->
          issue = """
          No ecto repos found for #{inspect(app_name)}.

          Ensure `:ecto` is installed and configured for the current application.
          """

          {:error, Igniter.add_issue(igniter, issue)}
      end
    end

    defp extract_repo(igniter, _app_name, module) do
      repo = Igniter.Project.Module.parse(module)

      case Igniter.Project.Module.module_exists(igniter, repo) do
        {true, _igniter} ->
          {:ok, repo}

        {false, _} ->
          {:error, Igniter.add_issue(igniter, "Provided repo (#{inspect(repo)}) doesn't exist")}
      end
    end
  end
else
  defmodule Mix.Tasks.FeistelCipher.Install do
    @shortdoc "#{__MODULE__.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc __MODULE__.Docs.long_doc()

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'feistel_cipher.install' requires igniter. Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter/readme.html#installation
      """)

      exit({:shutdown, 1})
    end
  end
end
