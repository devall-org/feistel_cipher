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
  prefixes your cipher functions can reside outside of your primary schema (usually public) and you can
  have multiple separate cipher function sets.

  To use a prefix you first have to specify it within your migration:

  ```elixir
  defmodule MyApp.Repo.Migrations.AddPrefixedFeistelCipherFunctions do
    use Ecto.Migration

    def up, do: FeistelCipher.Migration.up(functions_prefix: "private")

    def down, do: FeistelCipher.Migration.down(functions_prefix: "private")
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

  ## Arguments

  * `opts` - (Keyword list, optional) Configuration options:
    * `:functions_prefix` - (String, optional) The PostgreSQL schema prefix where the FeistelCipher functions will be created. Defaults to "public".
    * `:cipher_salt` - (Integer, optional) The constant value used in the Feistel cipher algorithm. Changing this value will result in different cipher outputs for the same input. Must be between 0 and 2^31-1. If not provided, uses `FeistelCipher.default_cipher_salt()`.
  """
  def up(opts \\ []) when is_list(opts) do
    functions_prefix = Keyword.get(opts, :functions_prefix, "public")
    cipher_salt = Keyword.get(opts, :cipher_salt, FeistelCipher.default_cipher_salt())
    validate_key!(cipher_salt, "cipher_salt")

    execute("CREATE SCHEMA IF NOT EXISTS #{functions_prefix}")

    # Copied from https://wiki.postgresql.org/wiki/Pseudo_encrypt
    # Algorithm reference from https://www.youtube.com/watch?v=FGhj3CGxl8I

    # bigint is 64 bits, but excluding negative numbers, only 63 bits are usable.
    # Limited to a maximum of 62 bits as it needs to be halved for the operation.
    # Multiplication and operation parameters are all limited to 31 bits.
    # Since 31 bits (half of 62 bits) are multiplied by a 31-bit parameter,
    # the calculation result is also within the 62-bit range, making it safe for bigint.
    execute("""
    CREATE FUNCTION #{functions_prefix}.feistel_encrypt(input bigint, bits int, key bigint) returns bigint AS $$
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
          b[i + 1] := a[i] # ((((b[i] # #{cipher_salt}) * #{cipher_salt}) # key) & half_mask);

          i := i + 1;
        END LOOP;

        a[5] := b[4];
        b[5] := a[4];

        RETURN ((a[5] << half_bits) | b[5]);
      END;
    $$ LANGUAGE plpgsql strict immutable;
    """)

    execute("""
    CREATE FUNCTION #{functions_prefix}.feistel_column_trigger() RETURNS trigger AS $$
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
        bits          := TG_ARGV[0]::int;
        key           := TG_ARGV[1]::bigint;
        source_column := TG_ARGV[2];
        target_column := TG_ARGV[3];

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
          encrypted := #{functions_prefix}.feistel_encrypt(clear, bits, key);
          decrypted := #{functions_prefix}.feistel_encrypt(encrypted, bits, key);

          -- Sanity check: This condition should never occur in practice
          -- Feistel cipher is mathematically guaranteed to be reversible
          -- If this fails, it indicates a serious bug in the feistel_encrypt function implementation
          IF decrypted != clear THEN
            RAISE EXCEPTION 'feistel_encrypt function does not have an inverse. clear: %, encrypted: %, decrypted: %, bits: %, key: %',
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

  ## Arguments

  * `opts` - (Keyword list, optional) Configuration options:
    * `:functions_prefix` - (String, optional) The PostgreSQL schema prefix where the FeistelCipher functions are located. Defaults to "public".

  ## ⚠️ WARNING

  This function drops all FeistelCipher core functions. **PostgreSQL will automatically prevent
  this operation if any triggers are still using these functions**, returning a dependency error.
  """
  def down(opts \\ []) when is_list(opts) do
    functions_prefix = Keyword.get(opts, :functions_prefix, "public")

    execute("DROP FUNCTION #{functions_prefix}.feistel_encrypt(bigint, int, bigint)")
    execute("DROP FUNCTION #{functions_prefix}.feistel_column_trigger()")
  end

  @doc """
  Returns the SQL for creating a trigger for a table to encrypt a `source` field to a `target` field.

  ## Arguments

  * `prefix` - (String, required) The PostgreSQL schema prefix where the table resides.
  * `table` - (String, required) The name of the table.
  * `source` - (String, required) The name of the source column containing the `bigint` integer (typically from a `BIGSERIAL` column like `seq`).
  * `target` - (String, required) The name of the target column to store the encrypted integer (typically the `BIGINT` primary key like `id`).
  * `opts` - (Keyword list, optional) Configuration options:
    * `:bits` - (Integer, optional) The number of bits for the Feistel cipher. Must be an even number, 62 or less. The default is 52 for LiveView and JavaScript interoperability.
    * `:key` - (Integer, optional) The encryption key. Must be between 0 and 2^31-1 (2,147,483,647). If not provided, a key is automatically generated from a hash of the prefix, table, source, target, and bits parameters. Use this when you need to maintain compatibility with previously created triggers.
    * `:functions_prefix` - (String, optional) The PostgreSQL schema prefix where the FeistelCipher functions (`feistel_encrypt` and `feistel_column_trigger`) are located. This should match the `functions_prefix` used when running `FeistelCipher.Migration.up/1`. Defaults to "public".

  ## Important Warning

  ⚠️ Once a table has been created with a specific `bits` value, you **cannot** change the `bits` setting later.
  The Feistel cipher algorithm depends on the `bits` parameter, and changing it would make existing encrypted IDs
  incompatible with the new cipher. If you need to change the `bits` value, you would need to:
  1. Drop the existing trigger using `down_for_encryption/4`
  2. Recreate all existing data with the new cipher
  3. Set up the new trigger with the desired `bits` value

  For this reason, carefully consider your `bits` requirement before creating the initial trigger.

  ## Key Compatibility

  When no key is explicitly provided, the encryption key is automatically generated from a hash of the prefix, table, source, target, and bits parameters.
  If you need to recreate a trigger with the same key (to maintain data compatibility), you can either:
  1. Use the same prefix, table, source, target, and bits parameters (automatic key generation)
  2. Explicitly provide the original key using the `key` parameter

  ## Examples

      # Automatic key generation (default bits: 52)
      FeistelCipher.Migration.up_for_encryption("public", "posts", "seq", "id")

      # With custom bits
      FeistelCipher.Migration.up_for_encryption("public", "posts", "seq", "id", bits: 40)

      # Explicit key for compatibility
      FeistelCipher.Migration.up_for_encryption("public", "posts", "seq", "id", bits: 52, key: 123456789)

      # When FeistelCipher functions are in a different prefix (e.g., "crypto" prefix)
      FeistelCipher.Migration.up_for_encryption("public", "posts", "seq", "id", functions_prefix: "crypto")

  """
  def up_for_encryption(prefix, table, source, target, opts \\ []) when is_list(opts) do
    # The default is 52 for LiveView and JavaScript interoperability.
    bits = Keyword.get(opts, :bits, 52)

    unless rem(bits, 2) == 0 do
      raise ArgumentError, "bits must be an even number, got: #{bits}"
    end

    key = Keyword.get(opts, :key) || generate_key(prefix, table, source, target, bits)
    validate_key!(key, "key")

    functions_prefix = Keyword.get(opts, :functions_prefix, "public")

    """
    CREATE TRIGGER #{trigger_name(table, source, target)}
      BEFORE INSERT OR UPDATE
      ON #{prefix}.#{table}
      FOR EACH ROW
      EXECUTE PROCEDURE #{functions_prefix}.feistel_column_trigger(#{bits}, #{key}, '#{source}', '#{target}');
    """
  end

  @doc """
  Returns the SQL for dropping a trigger for a table to encrypt a `source` field to a `target` field.

  ## Arguments

  * `prefix` - (String, required) The PostgreSQL schema prefix where the table resides.
  * `table` - (String, required) The name of the table.
  * `source` - (String, required) The name of the source column.
  * `target` - (String, required) The name of the target column.

  ## ⚠️ DANGER WARNING

  This function generates SQL that performs a **DANGEROUS** operation. The returned SQL includes safety guards
  that will prevent accidental execution. This operation will:
  - Remove the FeistelCipher trigger from the specified table
  - Break the `source` -> `target` encryption for the specified table
  - May lead to data inconsistency if not handled properly

  **The generated SQL will NOT execute by default.** You must manually remove the safety guard (`RAISE EXCEPTION`)
  from the generated SQL after understanding the risks and confirming you really need to drop the trigger.

  ## Key Compatibility and Safe Recreation

  **If you plan to recreate the trigger after dropping it**, you must ensure key compatibility:

  1. **Same Key (SAFE)**: If the new trigger uses the same key as the old one, existing encrypted data remains valid.
     When no key is explicitly provided, the key is automatically generated from a hash of the prefix, table, source, target, and bits parameters.

  2. **Different Key (REQUIRES MANUAL ACTION)**: If any of these parameters change, the key will be different:
     - Find the original key from your previous migration
     - Use `up_for_encryption/5` with the explicit `:key` option:
       ```elixir
       FeistelCipher.Migration.up_for_encryption("public", "posts", "seq", "id", bits: 52, key: original_key)
       ```

  3. **Empty Table (SAFE)**: If the table has no data, you can safely use a new key by simply removing
     the `RAISE EXCEPTION` block and proceeding with the new trigger.

  Before using this function, ensure you have:
  1. Proper database backups
  2. A clear understanding of the key compatibility impact
  3. The original key value if parameters have changed
  4. Verified whether the table contains data

  ## Example

      FeistelCipher.Migration.down_for_encryption("public", "posts", "seq", "id")

  """
  def down_for_encryption(prefix, table, source, target) do
    """
    DO $$
    BEGIN
      RAISE EXCEPTION 'FeistelCipher trigger deletion prevented. This may break the #{source} -> #{target} encryption for table #{prefix}.#{table}. Check key compatibility before proceeding. Remove this RAISE EXCEPTION block to execute. See FeistelCipher.Migration.down_for_encryption/4 documentation for details.';
    END
    $$;

    DROP TRIGGER #{trigger_name(table, source, target)} ON #{prefix}.#{table};
    """
  end

  defp generate_key(prefix, table, source, target, bits) do
    <<key::31, _::481>> = :crypto.hash(:sha512, "#{prefix}_#{table}_#{source}_#{target}_#{bits}")
    key
  end

  defp trigger_name(table, source, target) do
    "#{table}_encrypt_#{source}_to_#{target}_trigger"
  end

  @max_key_value Bitwise.bsl(1, 31)

  defp validate_key!(key, name) do
    unless key >= 0 and key < @max_key_value do
      raise ArgumentError, "#{name} must be between 0 and 2^31-1, got: #{key}"
    end
  end
end
