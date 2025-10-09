defmodule FeistelCipher.MigrationTest do
  use ExUnit.Case, async: false
  alias FeistelCipher.TestRepo

  setup do
    # Tests run sequentially (async: false) and clean up after themselves
    :ok
  end

  defp create_functions(opts \\ []) do
    functions_prefix = Keyword.get(opts, :functions_prefix, "public")
    functions_salt = Keyword.get(opts, :functions_salt, FeistelCipher.default_functions_salt())

    # Use migration to create functions (simulates real usage)
    migration_module =
      cond do
        functions_prefix == "public" and functions_salt == FeistelCipher.default_functions_salt() ->
          FeistelCipher.TestMigrations.AddFeistelCipher

        functions_prefix == "crypto" ->
          FeistelCipher.TestMigrations.AddFeistelCipherCrypto

        functions_salt == 999_999_999 ->
          FeistelCipher.TestMigrations.AddFeistelCipherCustomSalt
      end

    Ecto.Migrator.run(TestRepo, [{0, migration_module}], :up, all: true, log: false)
  end

  defp drop_functions(opts \\ []) do
    functions_prefix = Keyword.get(opts, :functions_prefix, "public")
    functions_salt = Keyword.get(opts, :functions_salt, FeistelCipher.default_functions_salt())

    migration_module =
      cond do
        functions_prefix == "public" and functions_salt == FeistelCipher.default_functions_salt() ->
          FeistelCipher.TestMigrations.AddFeistelCipher

        functions_prefix == "crypto" ->
          FeistelCipher.TestMigrations.AddFeistelCipherCrypto

        functions_salt == 999_999_999 ->
          FeistelCipher.TestMigrations.AddFeistelCipherCustomSalt
      end

    Ecto.Migrator.run(TestRepo, [{0, migration_module}], :down, all: true, log: false)
  end

  describe "up/1 and down/1" do
    test "creates and drops feistel_encrypt function" do
      # Run migration up
      create_functions()

      # Check if feistel_encrypt function exists
      result =
        TestRepo.query!("""
        SELECT routine_name
        FROM information_schema.routines
        WHERE routine_type = 'FUNCTION'
          AND routine_schema = 'public'
          AND routine_name = 'feistel_encrypt'
        """)

      assert length(result.rows) == 1

      # Test the function works
      encrypted = TestRepo.query!("SELECT public.feistel_encrypt(123, 52, 456)")
      assert [[encrypted_value]] = encrypted.rows
      assert is_integer(encrypted_value)

      # Test that encryption is reversible
      decrypted = TestRepo.query!("SELECT public.feistel_encrypt($1, 52, 456)", [encrypted_value])
      assert [[123]] = decrypted.rows

      # Run migration down
      drop_functions()

      # Check if functions are dropped
      result =
        TestRepo.query!("""
        SELECT routine_name
        FROM information_schema.routines
        WHERE routine_type = 'FUNCTION'
          AND routine_schema = 'public'
          AND routine_name IN ('feistel_encrypt', 'feistel_column_trigger')
        """)

      assert result.rows == []
    end

    test "creates functions in custom prefix" do
      # Run migration up with custom prefix
      create_functions(functions_prefix: "crypto")

      # Check if feistel_encrypt function exists in crypto schema
      result =
        TestRepo.query!("""
        SELECT routine_name
        FROM information_schema.routines
        WHERE routine_type = 'FUNCTION'
          AND routine_schema = 'crypto'
          AND routine_name = 'feistel_encrypt'
        """)

      assert length(result.rows) == 1

      # Test the function works
      encrypted = TestRepo.query!("SELECT crypto.feistel_encrypt(789, 52, 101112)")
      assert [[encrypted_value]] = encrypted.rows
      assert is_integer(encrypted_value)

      # Clean up
      drop_functions(functions_prefix: "crypto")
      TestRepo.query!("DROP SCHEMA IF EXISTS crypto CASCADE")
    end

    test "uses custom functions_salt" do
      custom_salt = 999_999_999

      # Run migration up with custom salt
      create_functions(functions_salt: custom_salt)

      # The salt is embedded in the function, so we just test it works
      encrypted = TestRepo.query!("SELECT public.feistel_encrypt(123, 52, 456)")
      assert [[encrypted_value]] = encrypted.rows
      assert is_integer(encrypted_value)

      # Clean up
      drop_functions()
    end
  end

  describe "feistel_encrypt function" do
    setup do
      create_functions()
      on_exit(fn -> drop_functions() end)
      :ok
    end

    test "produces expected encryption results (golden test)" do
      # These are known-good encryption results that must never change
      # to maintain backward compatibility with existing encrypted data
      golden_cases = [
        # {input, bits, key, expected_output}
        {123, 52, 456, 3_213_617_205_849_620},
        {1, 62, 1, 2_094_966_981_571_635_280},
        {4_611_686_018_427_387_903, 62, 2_147_483_647, 14_092_722_811_706_499},
        {42, 32, 123_456_789, 1_824_131_800},
        {255, 8, 999, 51},
        {1000, 52, 1_073_741_824, 2_007_014_348_997_340}
      ]

      for {input, bits, key, expected} <- golden_cases do
        result = TestRepo.query!("SELECT public.feistel_encrypt($1, $2, $3)", [input, bits, key])

        assert [[^expected]] = result.rows,
               "Encryption output changed! This breaks backward compatibility.\n" <>
                 "Input: #{input}, Bits: #{bits}, Key: #{key}\n" <>
                 "Expected: #{expected}, Got: #{inspect(result.rows)}"
      end
    end

    test "encrypts and decrypts correctly (reversibility test)" do
      max_key = Bitwise.bsl(1, 31) - 1
      mid_key = div(max_key, 2)
      # Test all valid even bit sizes from 2 to 62
      bit_sizes = Enum.to_list(2..62//2)

      # Test all combinations of extreme and middle values for each bit size
      for bits <- bit_sizes do
        max_input = Bitwise.bsl(1, bits) - 1
        mid_input = div(max_input, 2)
        inputs = [1, mid_input, max_input]
        keys = [1, mid_key, max_key]

        for input <- inputs, key <- keys do
          encrypted =
            TestRepo.query!("SELECT public.feistel_encrypt($1, $2, $3)", [input, bits, key])

          assert [[encrypted_value]] = encrypted.rows

          decrypted =
            TestRepo.query!("SELECT public.feistel_encrypt($1, $2, $3)", [
              encrypted_value,
              bits,
              key
            ])

          assert [[^input]] = decrypted.rows
        end
      end
    end

    test "raises error for invalid bits" do
      # Odd bits
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_encrypt(1, 61, 1)")
      end

      # Bits too small
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_encrypt(1, 1, 1)")
      end

      # Bits too large (> 62)
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_encrypt(1, 64, 1)")
      end
    end

    test "raises error for invalid key" do
      # Negative key
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_encrypt(1, 62, -1)")
      end

      # Key too large (>= 2^31)
      invalid_key = Bitwise.bsl(1, 31)

      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_encrypt(1, 62, $1)", [invalid_key])
      end
    end

    test "raises error for input larger than bits" do
      # For 8 bits, max value is 2^8 - 1 = 255
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_encrypt(256, 8, 1)")
      end

      # For 62 bits, test with value larger than 2^62 - 1
      too_large = Bitwise.bsl(1, 62)

      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_encrypt($1, 62, 1)", [too_large])
      end
    end

    test "handles NULL input" do
      result = TestRepo.query!("SELECT public.feistel_encrypt(NULL, 62, 1)")
      assert [[nil]] = result.rows
    end

    test "works with different bit sizes" do
      bit_sizes = [2, 4, 8, 16, 32, 40, 52, 60, 62]

      for bits <- bit_sizes do
        max_value = Bitwise.bsl(1, bits) - 1
        # Test with 0, 1, middle value, and max value
        test_inputs = [0, 1, div(max_value, 2), max_value]

        for input <- test_inputs do
          encrypted = TestRepo.query!("SELECT public.feistel_encrypt($1, $2, 1)", [input, bits])
          assert [[encrypted_value]] = encrypted.rows

          decrypted =
            TestRepo.query!("SELECT public.feistel_encrypt($1, $2, 1)", [encrypted_value, bits])

          assert [[^input]] = decrypted.rows
        end
      end
    end
  end

  describe "feistel_column_trigger function with real table" do
    setup do
      create_functions()

      # Create test table
      TestRepo.query!("""
      CREATE TABLE test_posts (
        seq BIGSERIAL,
        id BIGINT,
        title TEXT
      )
      """)

      # Get the SQL for creating trigger
      trigger_sql =
        FeistelCipher.Migration.up_for_encryption("public", "test_posts", "seq", "id")

      # Execute trigger creation
      TestRepo.query!(trigger_sql)

      on_exit(fn ->
        TestRepo.query!("DROP TABLE IF EXISTS test_posts CASCADE")
        drop_functions()
      end)

      :ok
    end

    test "automatically encrypts seq to id on INSERT" do
      # Insert without specifying id
      TestRepo.query!("""
      INSERT INTO test_posts (title) VALUES ('First Post')
      """)

      result = TestRepo.query!("SELECT seq, id, title FROM test_posts")
      assert [[seq, id, "First Post"]] = result.rows
      assert seq != id
      assert is_integer(seq)
      assert is_integer(id)

      # Verify id is encrypted version of seq
      decrypted =
        TestRepo.query!("SELECT public.feistel_encrypt($1, 52, $2)", [id, get_default_key()])

      assert [[^seq]] = decrypted.rows
    end

    test "encrypts multiple inserts correctly" do
      for i <- 1..5 do
        TestRepo.query!("INSERT INTO test_posts (title) VALUES ($1)", ["Post #{i}"])
      end

      result = TestRepo.query!("SELECT seq, id FROM test_posts ORDER BY seq")
      assert length(result.rows) == 5

      # Verify all are encrypted correctly
      for [seq, id] <- result.rows do
        decrypted =
          TestRepo.query!("SELECT public.feistel_encrypt($1, 52, $2)", [id, get_default_key()])

        assert [[^seq]] = decrypted.rows
      end
    end

    test "prevents manual modification of id on UPDATE" do
      # Insert a post
      TestRepo.query!("INSERT INTO test_posts (title) VALUES ('Original')")
      result = TestRepo.query!("SELECT seq, id FROM test_posts")
      [[_seq, original_id]] = result.rows

      # Try to update id manually
      assert_raise Postgrex.Error, ~r/id cannot be modified on UPDATE/, fn ->
        TestRepo.query!("UPDATE test_posts SET id = $1 WHERE id = $2", [999_999, original_id])
      end
    end

    test "updates seq and id together" do
      # Insert a post
      TestRepo.query!("INSERT INTO test_posts (title) VALUES ('Original')")

      # Update title (should not affect id)
      TestRepo.query!("UPDATE test_posts SET title = 'Updated'")

      result = TestRepo.query!("SELECT seq, id, title FROM test_posts")
      assert [[seq, id, "Updated"]] = result.rows

      # Verify id is still valid encryption of seq
      decrypted =
        TestRepo.query!("SELECT public.feistel_encrypt($1, 52, $2)", [id, get_default_key()])

      assert [[^seq]] = decrypted.rows
    end

    test "handles explicit NULL id" do
      # Create table that allows NULL seq for this specific test
      TestRepo.query!("DROP TABLE IF EXISTS test_nullable CASCADE")

      TestRepo.query!("""
      CREATE TABLE test_nullable (
        seq BIGINT,
        id BIGINT,
        title TEXT
      )
      """)

      # Create trigger for nullable table
      trigger_sql =
        FeistelCipher.Migration.up_for_encryption("public", "test_nullable", "seq", "id")

      TestRepo.query!(trigger_sql)

      # Insert with NULL seq
      TestRepo.query!("INSERT INTO test_nullable (seq, title) VALUES (NULL, 'Null Test')")

      result = TestRepo.query!("SELECT seq, id FROM test_nullable WHERE title = 'Null Test'")
      assert [[nil, nil]] = result.rows

      # Clean up
      TestRepo.query!("DROP TABLE IF EXISTS test_nullable CASCADE")
    end
  end

  describe "up_for_encryption/5" do
    test "generates correct SQL" do
      sql = FeistelCipher.Migration.up_for_encryption("public", "users", "seq", "id")

      assert sql =~ "CREATE TRIGGER"
      assert sql =~ "users_encrypt_seq_to_id_trigger"
      assert sql =~ "public.users"
      assert sql =~ "feistel_column_trigger"
      assert sql =~ "52"
      assert sql =~ "'seq'"
      assert sql =~ "'id'"
    end

    test "uses custom bits" do
      sql = FeistelCipher.Migration.up_for_encryption("public", "users", "seq", "id", bits: 40)
      assert sql =~ "40"
    end

    test "uses custom key" do
      sql =
        FeistelCipher.Migration.up_for_encryption("public", "users", "seq", "id", key: 123_456)

      assert sql =~ "123456"
    end

    test "uses custom functions_prefix" do
      sql =
        FeistelCipher.Migration.up_for_encryption("public", "users", "seq", "id",
          functions_prefix: "crypto"
        )

      assert sql =~ "crypto.feistel_column_trigger"
    end

    test "raises for odd bits" do
      assert_raise ArgumentError, ~r/bits must be an even number/, fn ->
        FeistelCipher.Migration.up_for_encryption("public", "users", "seq", "id", bits: 51)
      end
    end

    test "raises for invalid key" do
      assert_raise ArgumentError, ~r/key must be between 0 and 2\^31-1/, fn ->
        FeistelCipher.Migration.up_for_encryption("public", "users", "seq", "id", key: -1)
      end

      max_key = Bitwise.bsl(1, 31)

      assert_raise ArgumentError, ~r/key must be between 0 and 2\^31-1/, fn ->
        FeistelCipher.Migration.up_for_encryption("public", "users", "seq", "id", key: max_key)
      end
    end
  end

  describe "down_for_encryption/4" do
    test "generates SQL with safety guard" do
      sql = FeistelCipher.Migration.down_for_encryption("public", "users", "seq", "id")

      assert sql =~ "RAISE EXCEPTION"
      assert sql =~ "DROP TRIGGER users_encrypt_seq_to_id_trigger"
      assert sql =~ "public.users"
    end
  end

  # Helper function to get the default key for testing
  defp get_default_key do
    # This mimics the key generation in up_for_encryption
    <<key::31, _::481>> = :crypto.hash(:sha512, "public_test_posts_seq_id_52")
    key
  end
end
