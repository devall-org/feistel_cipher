defmodule Mix.Tasks.FeistelCipher.Upgrade.Docs do
  @moduledoc false

  def short_doc do
    "Generate a migration to upgrade FeistelCipher from v0.x to v1.0"
  end

  def example do
    "mix feistel_cipher.upgrade"
  end

  def long_doc do
    """
    #{short_doc()}

    Generates an Ecto migration that upgrades your database from FeistelCipher v0.x to v1.0.

    v1.0 uses new PostgreSQL functions (`feistel_cipher_v1`, `feistel_column_trigger_v1`)
    that coexist with the old ones, allowing a smooth upgrade.

    ## Example

    ```bash
    #{example()}
    ```

    ## Options

    * `--repo` or `-r` — Specify an Ecto repo for FeistelCipher to use.
    * `--functions-prefix` or `-p` — Specify the PostgreSQL schema prefix (default: `public`)
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.FeistelCipher.Upgrade do
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
        schema: [repo: :string, functions_prefix: :string],
        defaults: [functions_prefix: "public"],
        aliases: [r: :repo, p: :functions_prefix],
        required: []
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      app_name = Igniter.Project.Application.app_name(igniter)
      opts = igniter.args.options

      case extract_repo(igniter, app_name, opts[:repo]) do
        {:ok, repo} ->
          functions_prefix = opts[:functions_prefix]

          migration = """
          def up do
            # Install v1 functions (coexist with old v0.x functions).
            # Use the SAME functions_salt from your original feistel_cipher.install migration.
            # Find it in the migration file with timestamp 19730501000000.
            FeistelCipher.up_for_functions(functions_prefix: "#{functions_prefix}", functions_salt: :REPLACE_WITH_YOUR_SALT)
          end

          def down do
            FeistelCipher.down_for_functions(functions_prefix: "#{functions_prefix}")
          end
          """

          notice = """

          ⚠️  Next steps after running this migration:

            For Ash users:
              1. Run `mix ash.codegen --name upgrade_feistel_v1` to generate trigger migrations
              2. In the generated migration's `up` function, replace `down_for_trigger` (or `down_for_v1_trigger`) with `force_down_for_legacy_trigger`
              3. In the `down` function, replace `up_for_trigger` with `up_for_legacy_trigger` and `bits:` with `time_bits: 0, data_bits:`

            For plain Ecto users:
              See UPGRADE.md for trigger migration instructions

            Optionally, add old function cleanup to the LAST migration.
            See https://github.com/devall-org/feistel_cipher/blob/main/UPGRADE.md
          """

          igniter
          |> Igniter.Libs.Ecto.gen_migration(repo, "upgrade_feistel_cipher_to_v1",
            body: migration,
            on_exists: :skip
          )
          |> Igniter.add_notice(notice)

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
  defmodule Mix.Tasks.FeistelCipher.Upgrade do
    @shortdoc "#{__MODULE__.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc __MODULE__.Docs.long_doc()

    use Mix.Task

    def run(_argv) do
      Mix.shell().error("""
      The task 'feistel_cipher.upgrade' requires igniter. Please install igniter and try again.

      For more information, see: https://hexdocs.pm/igniter/readme.html#installation
      """)

      exit({:shutdown, 1})
    end
  end
end
