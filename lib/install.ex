defmodule Mix.Tasks.FeistelCipher.Install.Docs do
  @moduledoc false

  def short_doc do
    "A Ecto migration for Feistel cipher"
  end

  def example do
    "mix igniter.install feistel_cipher"
  end

  def long_doc do
    """
    #{short_doc()}

    ## Example

    ```bash
    mix feistel_cipher.install
    ```

    * `--repo` or `-r` — Specify an Ecto repo for FeistelCipher to use.
    * `--functions-prefix` or `-p` — Specify the PostgreSQL schema prefix where the FeistelCipher functions will be created, defaults to `public`
    * `--functions-salt` or `-s` — Specify the constant value used in the Feistel cipher algorithm. Changing this value will result in different cipher outputs for the same input, should be less than 2^31, defaults to `#{FeistelCipher.default_functions_salt()}`
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
        schema: [repo: :string, functions_prefix: :string, functions_salt: :integer],
        defaults: [
          functions_prefix: "public",
          functions_salt: FeistelCipher.default_functions_salt()
        ],
        aliases: [r: :repo, p: :functions_prefix, s: :functions_salt],
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
            FeistelCipher.Migration.up(functions_prefix: "#{opts[:functions_prefix]}", functions_salt: #{opts[:functions_salt]})
          end

          def down do
            FeistelCipher.Migration.down(functions_prefix: "#{opts[:functions_prefix]}")
          end
          """

          # Feistel cipher first published on May 1, 1973 (Horst Feistel, "Cryptography and Computer Privacy", Scientific American)
          igniter
          |> Igniter.Project.Formatter.import_dep(:feistel_cipher)
          |> Igniter.Libs.Ecto.gen_migration(repo, "add_feistel_cipher",
            timestamp: "19730501000000",
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
