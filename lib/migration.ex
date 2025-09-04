defmodule FeistelCipher.Migration do
  @moduledoc """
  Migrations create functions FeistelCipher needs to function.

  ## Usage

  To use migrations in your application you'll need to generate an `Ecto.Migration` that wraps
  calls to `FeistelCipher.Migration`:

  ```bash
  mix ecto.gen.migration add_feistel_cipher
  ```

  Open the generated migration in your editor and call the `up` and `down` functions on
  `FeistelCipher.Migration`:

  ```elixir
  defmodule MyApp.Repo.Migrations.AddFeistelCipher do
    use Ecto.Migration

    def up, do: FeistelCipher.Migration.up()

    def down, do: FeistelCipher.Migration.down()
  end
  ```

  This will run all of FeistelCipher's versioned migrations for your database.

  Now, run the migration to create the table:

  ```bash
  mix ecto.migrate
  ```

  ## Isolation with Prefixes

  FeistelCipher supports namespacing through PostgreSQL schemas, also called "prefixes" in Ecto. With
  prefixes your jobs table can reside outside of your primary schema (usually public) and you can
  have multiple separate job tables.

  To use a prefix you first have to specify it within your migration:

  ```elixir
  defmodule MyApp.Repo.Migrations.AddPrefixedFeistelIdJobsTable do
    use Ecto.Migration

    def up, do: FeistelCipher.Migration.up(prefix: "private")

    def down, do: FeistelCipher.Migration.down(prefix: "private")
  end
  ```

  In some cases, for example if your "private" schema already exists and your database user in
  production doesn't have permissions to create a new schema, trying to create the schema from the
  migration will result in an error. In such situations, it may be useful to inhibit the creation
  of the "private" schema:

  ```elixir
  defmodule MyApp.Repo.Migrations.AddPrefixedFeistelIdJobsTable do
    use Ecto.Migration

    def up, do: FeistelCipher.Migration.up(prefix: "private", create_schema: false)

    def down, do: FeistelCipher.Migration.down(prefix: "private")
  end
  ```

  ## Migrating Without Ecto

  If your application uses something other than Ecto for migrations, be it an external system or
  another ORM, it may be helpful to create plain SQL migrations for FeistelCipher database schema changes.

  The simplest mechanism for obtaining the SQL changes is to create the migration locally and run
  `mix ecto.migrate --log-migrations-sql`. That will log all of the generated SQL, which you can
  then paste into your migration system of choice.

  Alternatively, if you'd like a more automated approach, try using the [feistel_id_migations_sql][sql]
  project to generate `up` and `down` SQL migrations for you.

  [sql]: https://github.com/btwb/feistel_id_migrations_sql
  """

  use Ecto.Migration

  @doc """
  Run the `up` changes.

  ## Example

  Run migrations in an alternate prefix:

      FeistelCipher.Migration.up(prefix: "payments")

  """
  def up(opts \\ []) when is_list(opts) do
    import Bitwise

    %{
      create_schema: create_schema,
      prefix: prefix,
      quoted_prefix: quoted_prefix,
      seed: seed
    } = FeistelCipher.with_defaults(opts)

    if seed <= 0 or seed >= 1 <<< 31 do
      raise "feistel seed must be greater than 0 and less than 2^31"
    end

    if create_schema, do: execute("CREATE SCHEMA IF NOT EXISTS #{quoted_prefix}")

    # Copied from https://wiki.postgresql.org/wiki/Pseudo_encrypt
    # Algorithm reference from https://www.youtube.com/watch?v=FGhj3CGxl8I

    # bigint is 64 bits, but excluding negative numbers, only 63 bits are usable.
    # Limited to a maximum of 62 bits as it needs to be halved for the operation.
    # Multiplication and operation parameters are all limited to 31 bits.
    # Since 31 bits (half of 62 bits) are multiplied by a 31-bit parameter,
    # the calculation result is also within the 62-bit range, making it safe for bigint.
    execute("""
    CREATE FUNCTION #{prefix}.feistel(input bigint, bits int, key bigint) returns bigint AS $$
      DECLARE
        i int := 1;

        a bigint array[5];
        b bigint array[5];

        half_bits int    := bits / 2;
        half_mask bigint := (1::bigint << half_bits) - 1;
        mask      bigint := (1::bigint << bits) - 1;

      BEGIN
        IF bits < 2 OR bits > 62 OR bits % 2 = 1 THEN
          RAISE EXCEPTION 'feistel bits must be an even number between 2 and 62: %', bits;
        END IF;

        IF key < 0 OR key >= (1::bigint << 31) THEN
          RAISE EXCEPTION 'feistel key must be between 0 and 2^31-1: %', key;
        END IF;

        IF input > mask THEN
          RAISE EXCEPTION 'feistel input is larger than % bits: %', bits, input;
        END IF;

        a[1] := (input >> half_bits) & half_mask;
        b[1] := input & half_mask;

        WHILE i < 4 LOOP
          a[i + 1] := b[i];
          b[i + 1] := a[i] # ((((b[i] # #{seed}) * #{seed}) # key) & half_mask);

          i := i + 1;
        END LOOP;

        a[5] := b[4];
        b[5] := a[4];

        RETURN ((a[5] << half_bits) | b[5]);
      END;
    $$ LANGUAGE plpgsql strict immutable;
    """)

    execute("""
    CREATE FUNCTION #{prefix}.handle_feistel_encryption() RETURNS trigger AS $$
      DECLARE
        bits int;
        key bigint;
        source_column text;
        target_column text;

        clear bigint;
        encrypted bigint;
        decrypted bigint;

        new_target_value bigint;
        old_target_value bigint;

      BEGIN
        bits             := TG_ARGV[0]::int;
        key              := TG_ARGV[1]::bigint;
        source_column := TG_ARGV[2];
        target_column   := TG_ARGV[3];

        -- Prevent manual modification of encrypted target column during UPDATE
        -- The target column should only be set automatically based on the source column
        -- Direct modification would break the encryption consistency
        IF TG_OP = 'UPDATE' THEN
          EXECUTE format('SELECT ($1).%I::bigint, ($2).%I::bigint', target_column, target_column)
          INTO old_target_value, new_target_value
          USING OLD, NEW;

          IF old_target_value != new_target_value THEN
            RAISE EXCEPTION '% cannot be modified on UPDATE. OLD.%: %, NEW.%: %', target_column, target_column, old_target_value, target_column, new_target_value;
          END IF;
        END IF;

        EXECUTE format('SELECT ($1).%I::bigint', source_column)
        INTO clear
        USING NEW;

        IF clear IS NULL THEN
          encrypted := NULL;
        ELSE
          encrypted := #{prefix}.feistel(clear, bits, key);
          decrypted := #{prefix}.feistel(encrypted, bits, key);

          -- Sanity check: This condition should never occur in practice
          -- Feistel cipher is mathematically guaranteed to be reversible
          -- If this fails, it indicates a serious bug in the feistel function implementation
          IF decrypted != clear THEN
            RAISE EXCEPTION 'feistel function does not have an inverse. clear: %, encrypted: %, decrypted: %, bits: %, key: %',
              clear, encrypted, decrypted, bits, key;
          END IF;
        END IF;

        -- Dynamically set the value of the target column in the NEW record
        NEW := jsonb_populate_record(NEW, jsonb_build_object(target_column, to_jsonb(encrypted)));
        RETURN NEW;
      END;
    $$ LANGUAGE plpgsql;
    """)
  end

  @doc """
  Run the `down` changes.

  ## ⚠️ WARNING

  This function drops all FeistelCipher core functions. **PostgreSQL will automatically prevent
  this operation if any triggers are still using these functions**, returning a dependency error.

  You must remove all FeistelCipher triggers first before this migration can succeed.

  ## Example

  Run migrations in an alternate prefix:

      FeistelCipher.Migration.down(prefix: "payments")

  """
  def down(opts \\ []) when is_list(opts) do
    %{prefix: prefix} = FeistelCipher.with_defaults(opts)

    execute("DROP FUNCTION #{prefix}.feistel(bigint, int, bigint)")
    execute("DROP FUNCTION #{prefix}.handle_feistel_encryption()")
  end

  @doc """
  Returns the SQL for creating a trigger for a table to encrypt a `source` field to a `target` field.

  ## Arguments

  * `table` - (String, required) The name of the table.
  * `source` - (String, required) The name of the source column containing the `bigint` integer (typically from a `BIGSERIAL` column like `seq`).
  * `target` - (String, required) The name of the target column to store the encrypted integer (typically the `BIGINT` primary key like `id`).
  * `bits` - (Integer, optional) The number of bits for the Feistel cipher. Must be an even number, 62 or less. The default is 52 for LiveView and JavaScript interoperability.

  ## Important Warning

  ⚠️ Once a table has been created with a specific `bits` value, you **cannot** change the `bits` setting later.
  The Feistel cipher algorithm depends on the `bits` parameter, and changing it would make existing encrypted IDs
  incompatible with the new cipher. If you need to change the `bits` value, you would need to:
  1. Drop the existing trigger using `down_for_encryption/3`
  2. Recreate all existing data with the new cipher
  3. Set up the new trigger with the desired `bits` value

  For this reason, carefully consider your `bits` requirement before creating the initial trigger.

  ## Example

      FeistelCipher.Migration.up_for_encryption("posts", "seq", "id", 52)

  """
  def up_for_encryption(table, source, target, bits \\ 52) do
    # The default is 52 for LiveView and JavaScript interoperability.
    0 = rem(bits, 2)

    """
    CREATE TRIGGER "#{FeistelCipher.trigger_name(table, source, target)}"
      BEFORE INSERT OR UPDATE
      ON "#{table}"
      FOR EACH ROW
      EXECUTE PROCEDURE handle_feistel_encryption(#{bits}, #{FeistelCipher.table_seed(table)}, '#{source}', '#{target}');
    """
  end

  @doc """
  Returns the SQL for dropping a trigger for a table to encrypt a `source` field to a `target` field.

  ## Arguments

  * `table` - (String, required) The name of the table.
  * `source` - (String, required) The name of the source column.
  * `target` - (String, required) The name of the target column.

  ## ⚠️ DANGER WARNING

  This function generates SQL that performs a **DANGEROUS** operation. The returned SQL includes safety guards
  that will prevent accidental execution. This operation will:
  - Remove the FeistelCipher trigger from the specified table
  - Potentially break your application's encryption functionality
  - May lead to data inconsistency if not handled properly

  **The generated SQL will NOT execute by default.** You must manually remove the safety guard (`RAISE EXCEPTION`)
  from the generated SQL after understanding the risks and confirming you really need to drop the trigger.

  Before using this function, ensure you have:
  1. Proper database backups
  2. A clear understanding of the impact on your application
  3. A plan for handling existing encrypted data

  ## Example

      FeistelCipher.Migration.down_for_encryption("posts", "seq", "id")

  """
  def down_for_encryption(table, source, target) do
    """
    DO $$
    BEGIN
      RAISE EXCEPTION 'FeistelCipher trigger deletion prevented. This will break encryption for table "#{table}". Remove this RAISE EXCEPTION block to execute. See https://hexdocs.pm/feistel_cipher/0.4.0/FeistelCipher.Migration.html#down_for_encryption/3 for details.';
    END
    $$;

    DROP TRIGGER "#{FeistelCipher.trigger_name(table, source, target)}" ON "#{table}";
    """
  end
end
