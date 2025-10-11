defmodule FeistelCipher do
  @moduledoc """
  Generate non-sequential IDs using Feistel cipher in PostgreSQL.

  ## Basic Usage

  ```elixir
  defmodule MyApp.Repo.Migrations.AddFeistelCipher do
    use Ecto.Migration

    def up, do: FeistelCipher.up_for_functions()
    def down, do: FeistelCipher.down_for_functions()
  end
  ```

  ## With Custom Prefix

  ```elixir
  def up, do: FeistelCipher.up_for_functions(functions_prefix: "private")
  def down, do: FeistelCipher.down_for_functions(functions_prefix: "private")
  ```

  See function documentation for detailed options and examples.
  """

  use Ecto.Migration

  @doc """
  Returns the default salt constant used in the Feistel cipher algorithm.
  """
  @spec default_functions_salt() :: pos_integer()
  def default_functions_salt do
    1_076_943_109
  end

  @doc """
  Create FeistelCipher functions in the database.

  ## Options

  * `:functions_prefix` - Schema prefix for functions (default: "public").
  * `:functions_salt` - Salt constant for cipher algorithm (default: `default_functions_salt()`). Must be 0 to 2^31-1.
  """
  @spec up_for_functions(keyword()) :: :ok
  def up_for_functions(opts \\ []) when is_list(opts) do
    functions_prefix = Keyword.get(opts, :functions_prefix, "public")
    functions_salt = Keyword.get(opts, :functions_salt, default_functions_salt())
    validate_key!(functions_salt, "functions_salt")

    execute("CREATE SCHEMA IF NOT EXISTS #{functions_prefix}")

    # Copied from https://wiki.postgresql.org/wiki/Pseudo_encrypt
    # Algorithm reference from https://www.youtube.com/watch?v=FGhj3CGxl8I

    # bigint is 64 bits, but excluding negative numbers, only 63 bits are usable.
    # Limited to a maximum of 62 bits as it needs to be halved for the operation.
    # Multiplication and operation parameters are all limited to 31 bits.
    # Since 31 bits (half of 62 bits) are multiplied by a 31-bit parameter,
    # the calculation result is also within the 62-bit range, making it safe for bigint.
    execute("""
    CREATE FUNCTION #{functions_prefix}.feistel_encrypt(input bigint, bits int, key bigint, rounds int) returns bigint AS $$
      DECLARE
        i          int;

        left_half  bigint;
        right_half bigint;
        temp       bigint;

        half_bits  int    := bits / 2;
        half_mask  bigint := (1::bigint << half_bits) - 1;
        mask       bigint := (1::bigint << bits) - 1;

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

        IF rounds < 1 OR rounds > 32 THEN
          RAISE EXCEPTION 'feistel rounds must be between 1 and 32: %', rounds;
        END IF;

        -- Split input into left and right halves
        left_half  := (input >> half_bits) & half_mask;
        right_half := input & half_mask;

        -- Feistel rounds
        FOR i IN 1..rounds LOOP
          temp       := right_half;
          right_half := left_half # ((((right_half # #{functions_salt}) * #{functions_salt}) # key) & half_mask);
          left_half  := temp;
        END LOOP;

        -- Final swap
        temp       := left_half;
        left_half  := right_half;
        right_half := temp;

        -- Combine halves
        RETURN ((left_half << half_bits) | right_half);
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
        rounds int;

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
        rounds        := TG_ARGV[4]::int;

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
          encrypted := #{functions_prefix}.feistel_encrypt(clear, bits, key, rounds);
          decrypted := #{functions_prefix}.feistel_encrypt(encrypted, bits, key, rounds);

          -- Sanity check: This condition should never occur in practice
          -- Feistel cipher is mathematically guaranteed to be reversible
          -- If this fails, it indicates a serious bug in the feistel_encrypt function implementation
          IF decrypted != clear THEN
            RAISE EXCEPTION 'feistel_encrypt function does not have an inverse. clear: %, encrypted: %, decrypted: %, bits: %, key: %, rounds: %',
              clear, encrypted, decrypted, bits, key, rounds;
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
  Drop FeistelCipher functions from the database.

  ⚠️ **Warning**: PostgreSQL will prevent this if any triggers still use these functions.

  ## Options

  * `:functions_prefix` - Schema prefix where functions are located (default: "public").
  """
  @spec down_for_functions(keyword()) :: :ok
  def down_for_functions(opts \\ []) when is_list(opts) do
    functions_prefix = Keyword.get(opts, :functions_prefix, "public")

    execute("DROP FUNCTION #{functions_prefix}.feistel_encrypt(bigint, int, bigint, int)")
    execute("DROP FUNCTION #{functions_prefix}.feistel_column_trigger()")
  end

  @doc """
  Returns SQL to create a trigger that encrypts a `source` column to a `target` column.

  ## Options

  * `:bits` - Cipher bits (default: 52, max: 62, must be even). ⚠️ Cannot be changed after creation.
  * `:key` - Encryption key (0 to 2^31-1). Auto-generated if not provided.
  * `:rounds` - Number of Feistel rounds (default: 16, min: 1, max: 32).
      - DES uses 16 rounds. 32 provides double the security with acceptable performance.
      - Performance: 16 rounds ≈ 4.4μs, 32 rounds ≈ 8.7μs per encryption (see README benchmarks).
  * `:functions_prefix` - Schema where cipher functions are located (default: "public").

  ## Examples

      FeistelCipher.up_for_trigger("public", "posts", "seq", "id")
      FeistelCipher.up_for_trigger("public", "posts", "seq", "id", bits: 40, key: 123456789)
      FeistelCipher.up_for_trigger("public", "posts", "seq", "id", rounds: 8)
      FeistelCipher.up_for_trigger("public", "posts", "seq", "id", functions_prefix: "crypto")

  """
  @spec up_for_trigger(String.t(), String.t(), String.t(), String.t(), keyword()) :: String.t()
  def up_for_trigger(prefix, table, source, target, opts \\ []) when is_list(opts) do
    # The default is 52 for LiveView and JavaScript interoperability.
    bits = Keyword.get(opts, :bits, 52)

    unless rem(bits, 2) == 0 do
      raise ArgumentError, "bits must be an even number, got: #{bits}"
    end

    rounds = Keyword.get(opts, :rounds, 16)

    unless rounds >= 1 and rounds <= 32 do
      raise ArgumentError, "rounds must be between 1 and 32, got: #{rounds}"
    end

    key = Keyword.get(opts, :key) || generate_key(prefix, table, source, target, bits)
    validate_key!(key, "key")

    functions_prefix = Keyword.get(opts, :functions_prefix, "public")

    """
    CREATE TRIGGER #{trigger_name(table, source, target)}
      BEFORE INSERT OR UPDATE
      ON #{prefix}.#{table}
      FOR EACH ROW
      EXECUTE PROCEDURE #{functions_prefix}.feistel_column_trigger(#{bits}, #{key}, '#{source}', '#{target}', #{rounds});
    """
  end

  @doc """
  Returns SQL to drop a trigger. **DANGEROUS OPERATION**.

  The generated SQL includes a safety guard that prevents execution by default.
  You must manually remove the `RAISE EXCEPTION` block after understanding the risks.

  ## ⚠️ Key Compatibility Warning

  If recreating the trigger:
  - **Same key**: Use identical prefix/table/source/target/bits (auto-generates same key), or provide explicit `:key`
  - **Different key**: Existing encrypted data becomes invalid
  - **Empty table**: Safe to use new key

  To find the original key, check your migration file where the trigger was created.
  The key is in the generated SQL: `EXECUTE PROCEDURE ...feistel_column_trigger(bits, key, ...)`

  ## Example

      FeistelCipher.down_for_trigger("public", "posts", "seq", "id")

      # If recreating with same key (find original_key from migration file)
      FeistelCipher.up_for_trigger("public", "posts", "seq", "id", key: original_key)

  """
  @spec down_for_trigger(String.t(), String.t(), String.t(), String.t()) :: String.t()
  def down_for_trigger(prefix, table, source, target) do
    """
    DO $$
    BEGIN
      RAISE EXCEPTION 'FeistelCipher trigger deletion prevented. This may break the #{source} -> #{target} encryption for table #{prefix}.#{table}. Check key compatibility before proceeding. Remove this RAISE EXCEPTION block to execute. See FeistelCipher.down_for_trigger/4 documentation for details.';
    END
    $$;

    DROP TRIGGER #{trigger_name(table, source, target)} ON #{prefix}.#{table};
    """
  end

  # Generates a deterministic encryption key based on table/column information.
  # Uses SHA-512 hash to derive a 31-bit key (valid range: 0 to 2^31-1).
  # Same parameters always generate the same key, ensuring consistency across deployments.
  defp generate_key(prefix, table, source, target, bits) do
    <<key::31, _::481>> = :crypto.hash(:sha512, "#{prefix}_#{table}_#{source}_#{target}_#{bits}")
    key
  end

  defp trigger_name(table, source, target) do
    "#{table}_encrypt_#{source}_to_#{target}_trigger"
  end

  defp validate_key!(key, name) do
    max_key = Bitwise.bsl(1, 31) - 1

    unless key >= 0 and key <= max_key do
      raise ArgumentError,
            "#{name} must be between 0 and 2^31-1 (0..#{max_key}), got: #{key}"
    end
  end
end
