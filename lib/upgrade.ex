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
            # === Step 1: Install v1 functions ===
            # These coexist with the old v0.x functions (feistel_cipher, feistel_column_trigger).
            # Use the SAME functions_salt from your original feistel_cipher.install migration.
            # Find it in the migration file with timestamp 19730501000000.
            FeistelCipher.up_for_functions(functions_prefix: "#{functions_prefix}", functions_salt: :REPLACE_WITH_YOUR_SALT)

            # === Step 2: Upgrade each trigger from v0.x to v1 ===
            # For each table using Feistel cipher, drop the old trigger and create a new one.
            # Find your triggers in previous migrations where up_for_trigger was called.
            #
            # Upgrade guide:
            #   bits: N  →  time_bits: 0, data_bits: N
            #   (if bits was not specified, the old default was 52)
            #
            # Example:
            #   execute FeistelCipher.force_down_for_trigger("#{functions_prefix}", "posts", "seq", "id")
            #   execute FeistelCipher.up_for_trigger("#{functions_prefix}", "posts", "seq", "id",
            #     time_bits: 0, data_bits: 52, functions_prefix: "#{functions_prefix}")

            # === Step 3 (optional): Drop old v0.x functions ===
            # After all triggers are upgraded, you can remove the old functions.
            # Which functions exist depends on which version you're upgrading from:
            #
            #   # v0.15.0
            #   execute "DROP FUNCTION IF EXISTS #{functions_prefix}.feistel_cipher(bigint, int, bigint, int)"
            #   execute "DROP FUNCTION IF EXISTS #{functions_prefix}.feistel_column_trigger()"
            #
            #   # v0.14.0
            #   execute "DROP FUNCTION IF EXISTS #{functions_prefix}.feistel_encrypt(bigint, int, bigint, int)"
            #   execute "DROP FUNCTION IF EXISTS #{functions_prefix}.feistel_column_trigger()"
            #
            #   # v0.4.x or earlier
            #   execute "DROP FUNCTION IF EXISTS #{functions_prefix}.feistel(bigint, int, bigint)"
            #   execute "DROP FUNCTION IF EXISTS #{functions_prefix}.handle_feistel_encryption()"
          end

          def down do
            raise "Irreversible migration"
          end
          """

          igniter
          |> Igniter.Libs.Ecto.gen_migration(repo, "upgrade_feistel_cipher_to_v1",
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
