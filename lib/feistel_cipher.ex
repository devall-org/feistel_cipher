defmodule FeistelCipher do
  @moduledoc """
  Encrypted integer IDs - UUID alternative using Feistel cipher.

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

  This value is embedded in the PostgreSQL functions and cannot be changed after creation.
  To use a different salt, specify `:functions_salt` when calling `up_for_functions/1`.

  The default value `1_076_943_109` is an arbitrarily chosen constant within the valid
  range (0 to 2^31-1). Any value in this range can be used as the salt.
  """
  @spec default_functions_salt() :: pos_integer()
  def default_functions_salt do
    1_076_943_109
  end

  @doc """
  Create FeistelCipher functions in the database.

  ## Options

  * `:functions_prefix` - Schema prefix for functions (default: "public"). ⚠️ Cannot be changed after creation.
  * `:functions_salt` - Salt constant for cipher algorithm (default: `default_functions_salt()`). Must be 0 to 2^31-1. ⚠️ Cannot be changed after creation.
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
        -- Trigger parameters
        bits          int;
        key           bigint;
        source_column text;
        target_column text;
        rounds        int;

        -- Source and encrypted values
        clear_value   bigint;
        encrypted     bigint;

        -- Temporary values for validation
        decrypted     bigint;
        old_target    bigint;
        new_target    bigint;

      BEGIN
        -- Extract trigger parameters
        bits          := TG_ARGV[0]::int;
        key           := TG_ARGV[1]::bigint;
        source_column := TG_ARGV[2];
        target_column := TG_ARGV[3];
        rounds        := TG_ARGV[4]::int;

        -- Guard: Prevent manual modification of encrypted target column during UPDATE
        -- The target column should only be set automatically based on the source column.
        -- Direct modification would break the encryption consistency.
        IF TG_OP = 'UPDATE' THEN
          EXECUTE format('SELECT ($1).%I::bigint, ($2).%I::bigint', target_column, target_column)
          INTO old_target, new_target
          USING OLD, NEW;

          IF old_target != new_target THEN
            RAISE EXCEPTION 'Column "%" cannot be modified on UPDATE (OLD.%: %, NEW.%: %)',
              target_column, target_column, old_target, target_column, new_target;
          END IF;
        END IF;

        -- Get the clear value from the source column
        EXECUTE format('SELECT ($1).%I::bigint', source_column)
        INTO clear_value
        USING NEW;

        -- Handle NULL case early
        IF clear_value IS NULL THEN
          encrypted := NULL;
        ELSE
          -- Encrypt the clear value
          encrypted := #{functions_prefix}.feistel_encrypt(clear_value, bits, key, rounds);

          -- Sanity check: Verify encryption is reversible
          -- This condition should never occur in practice as Feistel cipher is
          -- mathematically guaranteed to be reversible. If this fails, it indicates
          -- a serious bug in the feistel_encrypt function implementation.
          decrypted := #{functions_prefix}.feistel_encrypt(encrypted, bits, key, rounds);

          IF decrypted != clear_value THEN
            RAISE EXCEPTION 'feistel_encrypt function does not have an inverse (clear: %, encrypted: %, decrypted: %, bits: %, key: %, rounds: %)',
              clear_value, encrypted, decrypted, bits, key, rounds;
          END IF;
        END IF;

        -- Set the encrypted value to the target column in the NEW record
        NEW := jsonb_populate_record(NEW, jsonb_build_object(target_column, to_jsonb(encrypted)));

        RETURN NEW;
      END;
    $$ LANGUAGE plpgsql;
    """)
  end

  @doc """
  Drop FeistelCipher functions from the database.

  **Note**: PostgreSQL will automatically prevent this operation if any triggers
  are still using these functions. Drop all triggers first using `down_for_trigger/4`.

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
  * `:key` - Encryption key (0 to 2^31-1). Auto-generated if not provided. ⚠️ Cannot be changed after creation.
  * `:rounds` - Number of Feistel rounds (default: 16, min: 1, max: 32). ⚠️ Cannot be changed after creation.
      - DES uses 16 rounds. 32 provides double the security with acceptable performance.
      - Performance: 16 rounds ≈ 4.4μs, 32 rounds ≈ 8.7μs per encryption (see README benchmarks).
  * `:functions_prefix` - Schema where cipher functions are located (default: "public"). ⚠️ Cannot be changed after creation.

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

    key = Keyword.get(opts, :key) || generate_key(prefix, table, source, target)
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

  For legitimate use cases (like column rename), use `force_down_for_trigger/4` instead.

  ## Example

      FeistelCipher.down_for_trigger("public", "posts", "seq", "id")

  """
  @spec down_for_trigger(String.t(), String.t(), String.t(), String.t()) :: String.t()
  def down_for_trigger(prefix, table, source, target) do
    """
    DO $$
    BEGIN
      RAISE EXCEPTION 'FeistelCipher trigger deletion prevented. This may break the #{source} -> #{target} encryption for table #{prefix}.#{table}. Use force_down_for_trigger/4 if this is intentional (e.g., column rename). See documentation for details.';
    END
    $$;

    DROP TRIGGER #{trigger_name(table, source, target)} ON #{prefix}.#{table};
    """
  end

  @doc """
  Returns SQL to drop a trigger, bypassing the safety guard.

  Use this when you need to drop and recreate a trigger (e.g., column rename).

  ## When You Need to Drop and Recreate a Trigger

  Common scenarios requiring trigger recreation:
  - **Column rename**: Renaming `seq` to `sequence` or `id` to `external_id`
  - **Table rename**: Renaming `posts` to `articles`
  - **Schema change**: Moving table to a different schema

  ## ⚠️ Parameter Validation Required

  Starting from this version, you MUST provide the exact same encryption parameters 
  that were used when creating the trigger:
  - **bits**: Same bit size (e.g., 52)
  - **key**: Same encryption key
  - **rounds**: Same number of rounds (e.g., 16)
  - **functions_prefix**: Same schema where cipher functions reside (e.g., "public")

  This validation prevents accidental parameter mismatches that would break encryption consistency.

  If ANY of these parameters don't match, the function will raise an exception:
  - **INSERT**: New records encrypt to different `id` values, causing primary key collisions
  - **UPDATE**: Trigger detects `id` mismatch and raises exception, preventing all updates
  - Existing encrypted `id` values become inconsistent with their `seq` values

  **Safe scenarios**:
  - All four parameters match the original values (safe to rename columns/tables)
  - Empty table with no existing encrypted data (safe to use different parameters)

  **Finding original parameters**: Check your migration file where the trigger was created.
  Look for the `up_for_trigger/5` call and its options (`:bits`, `:key`, `:rounds`, `:functions_prefix`).
  If options were omitted, the defaults were used (bits: 52, rounds: 16, functions_prefix: "public").
  For auto-generated keys, use `generate_key/4` with the original prefix, table, source, and target column names.

  ## Options

  * `:bits` - Cipher bits (must match original). Required.
  * `:key` - Encryption key (must match original). Required.
  * `:rounds` - Number of Feistel rounds (must match original). Required.
  * `:functions_prefix` - Schema where cipher functions are located (must match original). Required.

  ## Examples

      # Example: Column rename (seq -> sequence, id -> external_id)
      def change do
        # 1. Drop the old trigger with matching parameters
        execute FeistelCipher.force_down_for_trigger("public", "posts", "seq", "id",
          bits: 52,
          key: FeistelCipher.generate_key("public", "posts", "seq", "id"),
          rounds: 16,
          functions_prefix: "public"
        )

        # 2. Rename columns
        rename table(:posts), :seq, to: :sequence
        rename table(:posts), :id, to: :external_id

        # 3. Recreate trigger with SAME encryption parameters
        execute FeistelCipher.up_for_trigger("public", "posts", "sequence", "external_id",
          bits: 52,
          key: FeistelCipher.generate_key("public", "posts", "seq", "id"), # Use OLD names for key
          rounds: 16,
          functions_prefix: "public"
        )
      end

  """
  @spec force_down_for_trigger(String.t(), String.t(), String.t(), String.t()) :: String.t()
  def force_down_for_trigger(prefix, table, source, target) do
    require Logger
    Logger.warn("""
    ⚠️  DEPRECATED: force_down_for_trigger/4 is deprecated and unsafe.
    
    Please use force_down_for_trigger/5 with explicit parameters:
    
    FeistelCipher.force_down_for_trigger("#{prefix}", "#{table}", "#{source}", "#{target}",
      bits: 52,  # or your original value
      key: FeistelCipher.generate_key("#{prefix}", "#{table}", "#{source}", "#{target}"),  # or your original value
      rounds: 16,  # or your original value
      functions_prefix: "public"  # or your original value
    )
    
    This version assumes default values and may fail if your trigger uses different parameters.
    """)
    
    # Use common defaults - may not match actual trigger parameters
    force_down_for_trigger(prefix, table, source, target,
      bits: 52,
      key: generate_key(prefix, table, source, target),
      rounds: 16,
      functions_prefix: "public"
    )
  end

  @spec force_down_for_trigger(String.t(), String.t(), String.t(), String.t(), keyword()) :: String.t()
  def force_down_for_trigger(prefix, table, source, target, opts) do
    bits = Keyword.fetch!(opts, :bits)
    key = Keyword.fetch!(opts, :key)
    rounds = Keyword.fetch!(opts, :rounds)
    functions_prefix = Keyword.fetch!(opts, :functions_prefix)

    trigger_name = trigger_name(table, source, target)

    """
    DO $$
    DECLARE
      trigger_exists boolean;
      current_bits int;
      current_key bigint;
      current_source text;
      current_target text;
      current_rounds int;
      current_functions_prefix text;
    BEGIN
      -- Check if trigger exists
      SELECT EXISTS (
        SELECT 1 
        FROM pg_trigger t
        JOIN pg_class c ON t.tgrelid = c.oid
        JOIN pg_namespace n ON c.relnamespace = n.oid
        WHERE t.tgname = '#{trigger_name}'
          AND c.relname = '#{table}'
          AND n.nspname = '#{prefix}'
      ) INTO trigger_exists;

      IF NOT trigger_exists THEN
        RAISE EXCEPTION 'Trigger "#{trigger_name}" does not exist on table "#{prefix}.#{table}"';
      END IF;

      -- Get current trigger parameters
      SELECT 
        (string_to_array(encode(t.tgargs, 'escape'), chr(0)))[1]::int,     -- bits
        (string_to_array(encode(t.tgargs, 'escape'), chr(0)))[2]::bigint,  -- key
        (string_to_array(encode(t.tgargs, 'escape'), chr(0)))[3],          -- source_column
        (string_to_array(encode(t.tgargs, 'escape'), chr(0)))[4],          -- target_column
        (string_to_array(encode(t.tgargs, 'escape'), chr(0)))[5]::int,     -- rounds
        pn.nspname                                                          -- functions_prefix
      INTO current_bits, current_key, current_source, current_target, current_rounds, current_functions_prefix
      FROM pg_trigger t
      JOIN pg_class c ON t.tgrelid = c.oid
      JOIN pg_namespace n ON c.relnamespace = n.oid
      JOIN pg_proc p ON t.tgfoid = p.oid
      JOIN pg_namespace pn ON p.pronamespace = pn.oid
      WHERE t.tgname = '#{trigger_name}'
        AND c.relname = '#{table}'
        AND n.nspname = '#{prefix}';

      -- Validate parameters match
      IF current_bits != #{bits} THEN
        RAISE EXCEPTION 'Parameter mismatch: bits. Expected: %, Actual: %', #{bits}, current_bits;
      END IF;

      IF current_key != #{key} THEN
        RAISE EXCEPTION 'Parameter mismatch: key. Expected: %, Actual: %', #{key}, current_key;
      END IF;

      IF current_source != '#{source}' THEN
        RAISE EXCEPTION 'Parameter mismatch: source column. Expected: %, Actual: %', '#{source}', current_source;
      END IF;

      IF current_target != '#{target}' THEN
        RAISE EXCEPTION 'Parameter mismatch: target column. Expected: %, Actual: %', '#{target}', current_target;
      END IF;

      IF current_rounds != #{rounds} THEN
        RAISE EXCEPTION 'Parameter mismatch: rounds. Expected: %, Actual: %', #{rounds}, current_rounds;
      END IF;

      IF current_functions_prefix != '#{functions_prefix}' THEN
        RAISE EXCEPTION 'Parameter mismatch: functions_prefix. Expected: %, Actual: %', '#{functions_prefix}', current_functions_prefix;
      END IF;

      -- All parameters match, safe to drop trigger
      RAISE NOTICE 'All parameters match. Dropping trigger "#{trigger_name}" on "#{prefix}.#{table}"';
    END
    $$;

    DROP TRIGGER #{trigger_name} ON #{prefix}.#{table};
    """
  end

  @doc """
  Generates a deterministic encryption key based on table/column information.

  Uses SHA-512 hash to derive a 31-bit key (valid range: 0 to 2^31-1).
  Same parameters always generate the same key, ensuring consistency across deployments.

  This is useful when recreating triggers (e.g., column rename) to maintain the same encryption key.

  ## Examples

      # Get the key used by the original trigger
      key = FeistelCipher.generate_key("public", "posts", "seq", "id")

      # Use it when recreating with new column names
      FeistelCipher.up_for_trigger("public", "posts", "sequence", "external_id", key: key)

  """
  @spec generate_key(String.t(), String.t(), String.t(), String.t()) :: non_neg_integer()
  def generate_key(prefix, table, source, target) do
    <<key::31, _::481>> = :crypto.hash(:sha512, "#{prefix}_#{table}_#{source}_#{target}")
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
