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
        IF bits > 62 THEN
          RAISE EXCEPTION 'feistel bits must be 62 or less: %', bits;
        END IF;

        IF bits % 2 = 1 THEN
          RAISE EXCEPTION 'feistel bits must be an even number: %', bits;
        END IF;

        IF key >= (1::bigint << 31) THEN
          RAISE EXCEPTION 'feistel key is larger than 31 bits: %', key;
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

  ## Example

      FeistelCipher.Migration.up_sql_for_table("posts", source: "seq", target: "id")

  """
  def up_sql_for_table(table, opts \\ []) when is_list(opts) do
    # The default is 52 for JavaScript interoperability.
    bits = opts |> Keyword.get(:bits, 52)
    0 = rem(bits, 2)

    source = opts |> Keyword.fetch!(:source)
    target = opts |> Keyword.fetch!(:target)

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

  ## Example

      FeistelCipher.Migration.down_sql_for_table("posts", source: "seq", target: "id")

  """
  def down_sql_for_table(table, opts \\ []) when is_list(opts) do
    source = opts |> Keyword.fetch!(:source)
    target = opts |> Keyword.fetch!(:target)

    """
    DROP TRIGGER "#{FeistelCipher.trigger_name(table, source, target)}" ON "#{table}";
    """
  end
end
