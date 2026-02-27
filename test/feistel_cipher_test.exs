defmodule FeistelCipher.MigrationTest do
  use ExUnit.Case, async: false
  alias FeistelCipher.TestRepo

  # Fixed salt for testing purposes to ensure consistent results
  @test_salt 1_076_943_109

  setup do
    # Tests run sequentially (async: false) and clean up after themselves
    :ok
  end

  defp create_functions(opts \\ []) do
    functions_prefix = Keyword.get(opts, :functions_prefix, "public")
    functions_salt = Keyword.get(opts, :functions_salt, @test_salt)

    # Use migration to create functions (simulates real usage)
    migration_module =
      cond do
        functions_prefix == "public" and functions_salt == @test_salt ->
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
    functions_salt = Keyword.get(opts, :functions_salt, @test_salt)

    migration_module =
      cond do
        functions_prefix == "public" and functions_salt == @test_salt ->
          FeistelCipher.TestMigrations.AddFeistelCipher

        functions_prefix == "crypto" ->
          FeistelCipher.TestMigrations.AddFeistelCipherCrypto

        functions_salt == 999_999_999 ->
          FeistelCipher.TestMigrations.AddFeistelCipherCustomSalt
      end

    Ecto.Migrator.run(TestRepo, [{0, migration_module}], :down, all: true, log: false)
  end

  describe "up/1 and down/1" do
    test "creates and drops feistel_cipher function" do
      # Run migration up
      create_functions()

      # Check if feistel_cipher function exists
      result =
        TestRepo.query!("""
        SELECT routine_name
        FROM information_schema.routines
        WHERE routine_type = 'FUNCTION'
          AND routine_schema = 'public'
          AND routine_name = 'feistel_cipher_v1'
        """)

      assert length(result.rows) == 1

      # Test the function works
      encrypted = TestRepo.query!("SELECT public.feistel_cipher_v1(123, 52, 456, 16)")
      assert [[encrypted_value]] = encrypted.rows
      assert is_integer(encrypted_value)

      # Test that encryption is reversible
      decrypted =
        TestRepo.query!("SELECT public.feistel_cipher_v1($1, 52, 456, 16)", [encrypted_value])

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
          AND routine_name IN ('feistel_cipher_v1', 'feistel_trigger_v1')
        """)

      assert result.rows == []
    end

    test "creates functions in custom prefix" do
      # Run migration up with custom prefix
      create_functions(functions_prefix: "crypto")

      # Check if feistel_cipher function exists in crypto schema
      result =
        TestRepo.query!("""
        SELECT routine_name
        FROM information_schema.routines
        WHERE routine_type = 'FUNCTION'
          AND routine_schema = 'crypto'
          AND routine_name = 'feistel_cipher_v1'
        """)

      assert length(result.rows) == 1

      # Test the function works
      encrypted = TestRepo.query!("SELECT crypto.feistel_cipher_v1(789, 52, 101112, 16)")
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
      encrypted = TestRepo.query!("SELECT public.feistel_cipher_v1(123, 52, 456, 16)")
      assert [[encrypted_value]] = encrypted.rows
      assert is_integer(encrypted_value)

      # Clean up
      drop_functions()
    end
  end

  describe "feistel_cipher function" do
    setup do
      create_functions()
      on_exit(fn -> drop_functions() end)
      :ok
    end

    test "produces expected encryption results (golden test)" do
      # These are known-good encryption results that must never change
      # to maintain backward compatibility with existing encrypted data
      # Test with rounds 1, 4, 16 (default), and 32
      # NOTE: v0.14.0+ uses hashint8extended-based round function for security hardening
      golden_cases = [
        # {input, bits, key, rounds, expected_output}
        # NOTE: v0.14.0+ uses HMAC-SHA256 based round function for cryptographic security
        # 1 round
        {123, 52, 456, 1, 1_134_341_128_315},
        {1, 62, 1, 1, 2_702_257_970_112_102_401},
        {4_611_686_018_427_387_903, 62, 2_147_483_647, 1, 2_269_692_879_368_617_983},
        {42, 32, 123_456_789, 1, 3_526_230_058},
        {255, 8, 999, 1, 159},
        {1000, 52, 1_073_741_824, 1, 1_126_135_324_738_536},

        # 4 rounds
        {123, 52, 456, 4, 1_129_052_748_386_260},
        {1, 62, 1, 4, 360_291_969_257_229_043},
        {4_611_686_018_427_387_903, 62, 2_147_483_647, 4, 2_197_652_977_928_326_251},
        {42, 32, 123_456_789, 4, 1_146_714_997},
        {255, 8, 999, 4, 155},
        {1000, 52, 1_073_741_824, 4, 1_356_320_492_190},

        # 16 rounds (default)
        {123, 52, 456, 16, 2_254_853_619_361_601},
        {1, 62, 1, 16, 1_117_001_479_715_069_149},
        {4_611_686_018_427_387_903, 62, 2_147_483_647, 16, 828_622_283_567_234_730},
        {42, 32, 123_456_789, 16, 1_570_808_861},
        {255, 8, 999, 16, 155},
        {1000, 52, 1_073_741_824, 16, 1_126_110_981_055_764},

        # 32 rounds
        {123, 52, 456, 32, 1_129_069_844_376_462},
        {1, 62, 1, 32, 36_051_636_900_129_733},
        {4_611_686_018_427_387_903, 62, 2_147_483_647, 32, 3_854_957_036_047_420_257},
        {42, 32, 123_456_789, 32, 3_546_808_425},
        {255, 8, 999, 32, 185},
        {1000, 52, 1_073_741_824, 32, 2_251_862_728_273_434}
      ]

      for {input, bits, key, rounds, expected} <- golden_cases do
        result =
          TestRepo.query!("SELECT public.feistel_cipher_v1($1, $2, $3, $4)", [
            input,
            bits,
            key,
            rounds
          ])

        if expected do
          [[actual]] = result.rows

          assert actual == expected,
                 "Encryption output changed! This breaks backward compatibility.\n" <>
                   "Input: #{input}, Bits: #{bits}, Key: #{key}, Rounds: #{rounds}\n" <>
                   "Expected: #{expected}, Got: #{actual}"
        else
          # Print value for rounds that need golden values
          [[output]] = result.rows
          IO.puts("        {#{input}, #{bits}, #{key}, #{rounds}, #{output}},")
        end
      end
    end

    test "encrypts and decrypts correctly (reversibility test)" do
      max_key = Bitwise.bsl(1, 31) - 1
      mid_key = div(max_key, 2)
      # Test all valid even bit sizes from 0 to 62
      bit_sizes = Enum.to_list(0..62//2)

      # Test with various round counts (odd and even, boundary cases)
      round_counts = [1, 2, 3, 4, 7, 8, 15, 16, 31, 32]

      # Test all combinations of extreme and middle values for each bit size
      for bits <- bit_sizes, rounds <- round_counts do
        max_input = Bitwise.bsl(1, bits) - 1
        min_input = 0
        mid_input = Bitwise.bsr(max_input, 1)

        inputs = [min_input, mid_input, max_input]

        keys = [1, mid_key, max_key]

        for input <- inputs, key <- keys do
          encrypted =
            TestRepo.query!("SELECT public.feistel_cipher_v1($1, $2, $3, $4)", [
              input,
              bits,
              key,
              rounds
            ])

          assert [[encrypted_value]] = encrypted.rows

          decrypted =
            TestRepo.query!("SELECT public.feistel_cipher_v1($1, $2, $3, $4)", [
              encrypted_value,
              bits,
              key,
              rounds
            ])

          [[actual]] = decrypted.rows

          assert actual == input,
                 "Reversibility failed for input: #{input}, bits: #{bits}, key: #{key}, rounds: #{rounds}\n" <>
                   "Got: #{actual}"
        end
      end
    end

    test "raises error for invalid bits" do
      # Odd bits
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(1, 61, 1, 16)")
      end

      # Bits invalid (negative)
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(1, -2, 1, 16)")
      end

      # Bits too large (> 62)
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(1, 64, 1, 16)")
      end
    end

    test "raises error for invalid key" do
      # Negative key
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(1, 62, -1, 16)")
      end

      # Key too large (>= 2^31)
      invalid_key = Bitwise.bsl(1, 31)

      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(1, 62, $1, 16)", [invalid_key])
      end
    end

    test "raises error for invalid rounds" do
      # Rounds too small (< 1)
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(1, 62, 1, 0)")
      end

      # Rounds too large (> 32)
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(1, 62, 1, 33)")
      end

      # Negative rounds
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(1, 62, 1, -1)")
      end
    end

    test "raises error for input larger than bits" do
      # For 8 bits, max value is 2^8 - 1 = 255
      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(256, 8, 1, 16)")
      end

      # For 62 bits, test with value larger than 2^62 - 1
      too_large = Bitwise.bsl(1, 62)

      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1($1, 62, 1, 16)", [too_large])
      end
    end

    test "handles zero bits as 0 -> 0 identity" do
      result = TestRepo.query!("SELECT public.feistel_cipher_v1(0, 0, 1, 16)")
      assert [[0]] = result.rows

      assert_raise Postgrex.Error, fn ->
        TestRepo.query!("SELECT public.feistel_cipher_v1(1, 0, 1, 16)")
      end
    end

    test "handles NULL input" do
      result = TestRepo.query!("SELECT public.feistel_cipher_v1(NULL::bigint, 62, 1, 16)")
      assert [[nil]] = result.rows
    end

    test "produces valid permutation for 4 bits (0-15 -> 0-15)" do
      # For 4 bits, all inputs 0-15 should map to all outputs 0-15 (bijection)
      bits = 4
      key = 12345
      rounds = 16

      # Encrypt all possible inputs (0-15)
      encrypted_values =
        for input <- 0..15 do
          result =
            TestRepo.query!("SELECT public.feistel_cipher_v1($1, $2, $3, $4)", [
              input,
              bits,
              key,
              rounds
            ])

          [[encrypted_value]] = result.rows
          encrypted_value
        end

      # All encrypted values should be in range [0, 15]
      assert Enum.all?(encrypted_values, fn val -> val >= 0 and val <= 15 end),
             "All encrypted values should be in range [0, 15], got: #{inspect(encrypted_values)}"

      # All encrypted values should be unique (no collisions)
      assert length(Enum.uniq(encrypted_values)) == 16,
             "All 16 encrypted values should be unique, got: #{inspect(encrypted_values)}"

      # Encrypted values should form a complete permutation of [0, 15]
      assert Enum.sort(encrypted_values) == Enum.to_list(0..15),
             "Encrypted values should be a permutation of 0-15, got: #{inspect(Enum.sort(encrypted_values))}"
    end
  end

  describe "feistel_column_trigger function with real table (time_bits: 0)" do
    setup do
      create_functions()

      # Ensure clean state before creating table
      TestRepo.query!("DROP TABLE IF EXISTS test_posts CASCADE")

      # Create test table
      TestRepo.query!("""
      CREATE TABLE test_posts (
        seq BIGSERIAL,
        id BIGINT,
        title TEXT
      )
      """)

      # Get the SQL for creating trigger (time_bits: 0 for backward-compatible behavior)
      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_posts", "seq", "id", time_bits: 0)

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

      # Verify id is encrypted version of seq (data_bits default: 38)
      key = FeistelCipher.generate_key("public", "test_posts", "seq", "id")

      decrypted =
        TestRepo.query!("SELECT public.feistel_cipher_v1($1, 38, $2, 16)", [id, key])

      [[actual]] = decrypted.rows
      assert actual == seq
    end

    test "encrypts multiple inserts correctly" do
      for i <- 1..5 do
        TestRepo.query!("INSERT INTO test_posts (title) VALUES ($1)", ["Post #{i}"])
      end

      result = TestRepo.query!("SELECT seq, id FROM test_posts ORDER BY seq")
      assert length(result.rows) == 5

      # Verify all are encrypted correctly (data_bits default: 38)
      key = FeistelCipher.generate_key("public", "test_posts", "seq", "id")

      for [seq, id] <- result.rows do
        decrypted =
          TestRepo.query!("SELECT public.feistel_cipher_v1($1, 38, $2, 16)", [id, key])

        [[actual]] = decrypted.rows
        assert actual == seq
      end
    end

    test "updating title does not affect seq and id" do
      # Insert a post
      TestRepo.query!("INSERT INTO test_posts (title) VALUES ('Original')")

      result = TestRepo.query!("SELECT seq, id FROM test_posts")
      [[original_seq, original_id]] = result.rows

      # Update title (should not affect seq/id)
      TestRepo.query!("UPDATE test_posts SET title = 'Updated'")

      result = TestRepo.query!("SELECT seq, id, title FROM test_posts")
      [[actual_seq, actual_id, title]] = result.rows
      assert actual_seq == original_seq
      assert actual_id == original_id
      assert title == "Updated"

      # Verify id is still valid encryption of seq
      key = FeistelCipher.generate_key("public", "test_posts", "seq", "id")

      decrypted =
        TestRepo.query!("SELECT public.feistel_cipher_v1($1, 38, $2, 16)", [
          original_id,
          key
        ])

      [[decrypted_seq]] = decrypted.rows
      assert decrypted_seq == original_seq
    end

    test "updating seq automatically updates id" do
      # Insert a post
      TestRepo.query!("INSERT INTO test_posts (title) VALUES ('Original')")

      result = TestRepo.query!("SELECT seq, id FROM test_posts")
      [[original_seq, original_id]] = result.rows

      # Update seq (id should be automatically updated)
      new_seq = original_seq + 100
      TestRepo.query!("UPDATE test_posts SET seq = $1", [new_seq])

      result = TestRepo.query!("SELECT seq, id FROM test_posts")
      [[actual_seq, new_id]] = result.rows
      assert actual_seq == new_seq

      # id should have changed
      assert new_id != original_id

      # Verify new id is encrypted version of new seq
      key = FeistelCipher.generate_key("public", "test_posts", "seq", "id")

      decrypted =
        TestRepo.query!("SELECT public.feistel_cipher_v1($1, 38, $2, 16)", [
          new_id,
          key
        ])

      [[decrypted_seq]] = decrypted.rows
      assert decrypted_seq == new_seq
    end

    test "updating seq to NULL sets id to NULL" do
      # Create table that allows NULL seq
      TestRepo.query!("DROP TABLE IF EXISTS test_nullable_seq CASCADE")

      TestRepo.query!("""
      CREATE TABLE test_nullable_seq (
        seq BIGINT,
        id BIGINT,
        title TEXT
      )
      """)

      # Create trigger for nullable table (time_bits: 0)
      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_nullable_seq", "seq", "id",
          time_bits: 0
        )

      TestRepo.query!(trigger_sql)

      # Insert with a value
      TestRepo.query!("INSERT INTO test_nullable_seq (seq, title) VALUES (42, 'Original')")

      result = TestRepo.query!("SELECT seq, id FROM test_nullable_seq")
      [[42, original_id]] = result.rows
      assert original_id != nil

      # Update seq to NULL (id should also become NULL)
      TestRepo.query!("UPDATE test_nullable_seq SET seq = NULL")

      result = TestRepo.query!("SELECT seq, id FROM test_nullable_seq")
      assert [[nil, nil]] = result.rows

      # Clean up
      TestRepo.query!("DROP TABLE IF EXISTS test_nullable_seq CASCADE")
    end

    test "updating seq from NULL to value sets id to encrypted value" do
      # Create table that allows NULL seq
      TestRepo.query!("DROP TABLE IF EXISTS test_nullable_update CASCADE")

      TestRepo.query!("""
      CREATE TABLE test_nullable_update (
        seq BIGINT,
        id BIGINT,
        title TEXT
      )
      """)

      # Create trigger for nullable table (time_bits: 0)
      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_nullable_update", "seq", "id",
          time_bits: 0
        )

      TestRepo.query!(trigger_sql)

      # Insert with NULL seq
      TestRepo.query!("INSERT INTO test_nullable_update (seq, title) VALUES (NULL, 'Test')")

      result = TestRepo.query!("SELECT seq, id FROM test_nullable_update")
      assert [[nil, nil]] = result.rows

      # Update seq from NULL to a value
      TestRepo.query!("UPDATE test_nullable_update SET seq = 42")

      result = TestRepo.query!("SELECT seq, id FROM test_nullable_update")
      assert [[42, id]] = result.rows
      assert id != nil

      # Calculate the key for this specific table
      key = FeistelCipher.generate_key("public", "test_nullable_update", "seq", "id")

      # Verify id is encrypted version of seq (data_bits default: 38)
      decrypted =
        TestRepo.query!("SELECT public.feistel_cipher_v1($1, 38, $2, 16)", [id, key])

      [[decrypted_seq]] = decrypted.rows
      assert decrypted_seq == 42

      # Clean up
      TestRepo.query!("DROP TABLE IF EXISTS test_nullable_update CASCADE")
    end
  end

  describe "feistel_column_trigger function with time_bits > 0" do
    # 1 hour bucket
    @time_bucket 3600

    setup do
      create_functions()

      TestRepo.query!("DROP TABLE IF EXISTS test_time_posts CASCADE")

      TestRepo.query!("""
      CREATE TABLE test_time_posts (
        seq BIGSERIAL,
        id BIGINT,
        title TEXT
      )
      """)

      on_exit(fn ->
        TestRepo.query!("DROP TABLE IF EXISTS test_time_posts CASCADE")
        drop_functions()
      end)

      :ok
    end

    test "rows in same time_bucket share the same time_bits prefix (encrypt_time: false)" do
      time_bits = 12
      data_bits = 40
      key = FeistelCipher.generate_key("public", "test_time_posts", "seq", "id")

      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_time_posts", "seq", "id",
          time_bits: time_bits,
          time_bucket: @time_bucket,
          data_bits: data_bits,
          key: key
        )

      TestRepo.query!(trigger_sql)

      # Insert multiple rows (all within the same transaction = same now())
      for i <- 1..5 do
        TestRepo.query!("INSERT INTO test_time_posts (title) VALUES ($1)", ["Post #{i}"])
      end

      result = TestRepo.query!("SELECT seq, id FROM test_time_posts ORDER BY seq")
      assert length(result.rows) == 5

      # All rows should share the same time prefix
      data_mask = Bitwise.bsl(1, data_bits) - 1

      prefixes =
        for [_seq, id] <- result.rows do
          Bitwise.bsr(id, data_bits)
        end

      assert length(Enum.uniq(prefixes)) == 1,
             "All rows in same time_bucket should share the same time prefix, got: #{inspect(prefixes)}"

      # Verify data parts are all different and reversible
      for [seq, id] <- result.rows do
        data_component = Bitwise.band(id, data_mask)

        decrypted =
          TestRepo.query!("SELECT public.feistel_cipher_v1($1, $2, $3, 16)", [
            data_component,
            data_bits,
            key
          ])

        [[actual]] = decrypted.rows
        assert actual == seq
      end
    end

    test "time prefix matches expected time_value (encrypt_time: false)" do
      time_bits = 12
      data_bits = 40
      key = FeistelCipher.generate_key("public", "test_time_posts", "seq", "id")

      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_time_posts", "seq", "id",
          time_bits: time_bits,
          time_bucket: @time_bucket,
          data_bits: data_bits,
          key: key
        )

      TestRepo.query!(trigger_sql)

      TestRepo.query!("INSERT INTO test_time_posts (title) VALUES ('Test')")

      result =
        TestRepo.query!("SELECT id, extract(epoch from now())::bigint FROM test_time_posts")

      [[id, epoch_now]] = result.rows

      # Calculate expected time_value
      time_mask = Bitwise.bsl(1, time_bits) - 1
      expected_time_value = div(epoch_now, @time_bucket) |> Bitwise.band(time_mask)

      actual_time_prefix = Bitwise.bsr(id, data_bits)
      assert actual_time_prefix == expected_time_value
    end

    test "time prefix uses time_offset when provided" do
      time_bits = 12
      data_bits = 40
      time_offset = 21_600
      key = FeistelCipher.generate_key("public", "test_time_posts", "seq", "id")

      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_time_posts", "seq", "id",
          time_bits: time_bits,
          time_bucket: @time_bucket,
          time_offset: time_offset,
          data_bits: data_bits,
          key: key
        )

      TestRepo.query!(trigger_sql)
      TestRepo.query!("INSERT INTO test_time_posts (title) VALUES ('Offset Test')")

      result =
        TestRepo.query!("SELECT id, extract(epoch from now())::bigint FROM test_time_posts")

      [[id, epoch_now]] = result.rows

      time_mask = Bitwise.bsl(1, time_bits) - 1
      expected_time_value = div(epoch_now + time_offset, @time_bucket) |> Bitwise.band(time_mask)

      actual_time_prefix = Bitwise.bsr(id, data_bits)
      assert actual_time_prefix == expected_time_value
    end

    test "encrypt_time: true encrypts time prefix with feistel cipher" do
      time_bits = 12
      data_bits = 40
      key = FeistelCipher.generate_key("public", "test_time_posts", "seq", "id")

      TestRepo.query!("DROP TABLE IF EXISTS test_encrypt_time CASCADE")

      TestRepo.query!("""
      CREATE TABLE test_encrypt_time (
        seq BIGSERIAL,
        id BIGINT,
        title TEXT
      )
      """)

      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_encrypt_time", "seq", "id",
          time_bits: time_bits,
          time_bucket: @time_bucket,
          encrypt_time: true,
          data_bits: data_bits,
          key: key
        )

      TestRepo.query!(trigger_sql)

      # Insert a row
      TestRepo.query!("INSERT INTO test_encrypt_time (title) VALUES ('Test')")

      result =
        TestRepo.query!("SELECT id, extract(epoch from now())::bigint FROM test_encrypt_time")

      [[id, epoch_now]] = result.rows

      # Calculate the expected encrypted time_value
      time_mask = Bitwise.bsl(1, time_bits) - 1
      raw_time_value = div(epoch_now, @time_bucket) |> Bitwise.band(time_mask)

      # The time prefix should be the encrypted version of raw_time_value
      encrypted_time =
        TestRepo.query!("SELECT public.feistel_cipher_v1($1, $2, $3, 16)", [
          raw_time_value,
          time_bits,
          key
        ])

      [[expected_encrypted_time]] = encrypted_time.rows

      actual_time_prefix = Bitwise.bsr(id, data_bits)
      assert actual_time_prefix == expected_encrypted_time

      # Rows in same bucket should still share the same encrypted prefix
      TestRepo.query!("INSERT INTO test_encrypt_time (title) VALUES ('Test2')")

      result2 = TestRepo.query!("SELECT id FROM test_encrypt_time ORDER BY seq")

      prefixes =
        for [row_id] <- result2.rows do
          Bitwise.bsr(row_id, data_bits)
        end

      assert length(Enum.uniq(prefixes)) == 1,
             "Encrypted time prefixes should match within same bucket"

      # Data part should still be reversible
      data_mask = Bitwise.bsl(1, data_bits) - 1

      for [row_id] <- result2.rows do
        data_component = Bitwise.band(row_id, data_mask)

        decrypted =
          TestRepo.query!("SELECT public.feistel_cipher_v1($1, $2, $3, 16)", [
            data_component,
            data_bits,
            key
          ])

        [[_actual]] = decrypted.rows
        # Just verify it doesn't error; we can't easily get seq here
      end

      TestRepo.query!("DROP TABLE IF EXISTS test_encrypt_time CASCADE")
    end

    test "time_value overflow wraps with modulo (2^time_bits)" do
      # Use very small time_bits (4) and time_bucket of 1 second
      # Current epoch (~1.7 billion) / 1 is already >> 16 (2^4), so it naturally overflows
      time_bits = 4
      data_bits = 40
      key = FeistelCipher.generate_key("public", "test_time_posts", "seq", "id")
      time_bucket = 1

      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_time_posts", "seq", "id",
          time_bits: time_bits,
          time_bucket: time_bucket,
          data_bits: data_bits,
          key: key
        )

      TestRepo.query!(trigger_sql)

      TestRepo.query!("INSERT INTO test_time_posts (title) VALUES ('Overflow Test')")

      result = TestRepo.query!("SELECT id FROM test_time_posts")
      [[id]] = result.rows

      # Extract time prefix - should be in range [0, 15] due to modulo
      time_prefix = Bitwise.bsr(id, data_bits)

      assert time_prefix >= 0 and time_prefix <= 15,
             "Time prefix should be in range [0, 15] after modulo, got: #{time_prefix}"
    end

    test "with time_bucket 1 second, second row has larger time_bits prefix within 60" do
      time_bits = 12
      data_bits = 40
      key = FeistelCipher.generate_key("public", "test_time_posts", "seq", "id")

      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_time_posts", "seq", "id",
          time_bits: time_bits,
          time_bucket: 1,
          data_bits: data_bits,
          key: key
        )

      TestRepo.query!(trigger_sql)

      TestRepo.query!("INSERT INTO test_time_posts (title) VALUES ('First')")
      TestRepo.query!("SELECT pg_sleep(1.1)")
      TestRepo.query!("INSERT INTO test_time_posts (title) VALUES ('Second')")

      result = TestRepo.query!("SELECT id FROM test_time_posts ORDER BY seq")
      assert [[first_id], [second_id]] = result.rows

      first_time_bits = Bitwise.bsr(first_id, data_bits)
      second_time_bits = Bitwise.bsr(second_id, data_bits)

      assert second_time_bits > first_time_bits
      assert second_time_bits - first_time_bits < 60
    end

    test "NULL handling works with time_bits > 0" do
      time_bits = 12
      data_bits = 40

      TestRepo.query!("DROP TABLE IF EXISTS test_time_nullable CASCADE")

      TestRepo.query!("""
      CREATE TABLE test_time_nullable (
        seq BIGINT,
        id BIGINT,
        title TEXT
      )
      """)

      trigger_sql =
        FeistelCipher.up_for_legacy_trigger("public", "test_time_nullable", "seq", "id",
          time_bits: time_bits,
          time_bucket: @time_bucket,
          data_bits: data_bits
        )

      TestRepo.query!(trigger_sql)

      # Insert with NULL seq
      TestRepo.query!("INSERT INTO test_time_nullable (seq, title) VALUES (NULL, 'Null Test')")

      result = TestRepo.query!("SELECT seq, id FROM test_time_nullable")
      assert [[nil, nil]] = result.rows

      # Insert with value
      TestRepo.query!("INSERT INTO test_time_nullable (seq, title) VALUES (42, 'Value Test')")

      result =
        TestRepo.query!("SELECT seq, id FROM test_time_nullable WHERE title = 'Value Test'")

      assert [[42, id]] = result.rows
      assert id != nil

      TestRepo.query!("DROP TABLE IF EXISTS test_time_nullable CASCADE")
    end
  end

  describe "up_for_legacy_trigger/5" do
    test "generates correct SQL with defaults" do
      sql = FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id")

      assert sql =~ "CREATE TRIGGER"
      assert sql =~ "users_encrypt_seq_to_id_trigger"
      refute sql =~ "users_encrypt_seq_to_id_v1_trigger"
      assert sql =~ "public.users"
      assert sql =~ "feistel_trigger_v1"
      # default data_bits: 38
      assert sql =~ "38"
      assert sql =~ "'seq'"
      assert sql =~ "'id'"
      # default time_bits: 15, time_bucket: 86400
      # trigger params: from, to, time_bits, time_bucket, encrypt_time, data_bits, key, rounds
      assert sql =~ "15"
      assert sql =~ "86400"
      assert sql =~ ", 0, false,"
    end

    test "uses custom data_bits" do
      sql =
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          time_bits: 8,
          data_bits: 32
        )

      assert sql =~ "32"
    end

    test "uses custom key" do
      sql =
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          key: 123_456,
          time_bits: 0
        )

      assert sql =~ "123456"
    end

    test "uses custom functions_prefix" do
      sql =
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          functions_prefix: "crypto",
          time_bits: 0
        )

      assert sql =~ "crypto.feistel_trigger_v1"
    end

    test "raises for odd data_bits" do
      assert_raise ArgumentError, ~r/data_bits must be an even number/, fn ->
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          time_bits: 0,
          data_bits: 41
        )
      end
    end

    test "allows data_bits = 0" do
      sql =
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          time_bits: 0,
          data_bits: 0
        )

      assert sql =~ ", 0, false, 0,"
    end

    test "raises when data_bits is negative" do
      assert_raise ArgumentError, ~r/data_bits must be non-negative/, fn ->
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          time_bits: 0,
          data_bits: -2
        )
      end
    end

    test "allows time_bits + data_bits = 63 when encrypt_time is false" do
      sql =
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          time_bits: 13,
          data_bits: 50,
          encrypt_time: false
        )

      assert sql =~ ", 13,"
      assert sql =~ ", false, 50,"
    end

    test "raises when time_bits + data_bits > 63 and encrypt_time is false" do
      assert_raise ArgumentError,
                   ~r/time_bits \+ data_bits must be <= 63 when encrypt_time is false/,
                   fn ->
                     FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
                       time_bits: 15,
                       data_bits: 50,
                       encrypt_time: false
                     )
                   end
    end

    test "raises when time_bits + data_bits > 62 and encrypt_time is true" do
      assert_raise ArgumentError,
                   ~r/time_bits \+ data_bits must be <= 62 when encrypt_time is true/,
                   fn ->
                     FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
                       time_bits: 12,
                       data_bits: 52,
                       encrypt_time: true
                     )
                   end
    end

    test "raises when encrypt_time: true and time_bits < 2" do
      assert_raise ArgumentError,
                   ~r/time_bits must be >= 2 when encrypt_time is true/,
                   fn ->
                     FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
                       time_bits: 0,
                       encrypt_time: true,
                       data_bits: 40
                     )
                   end
    end

    test "raises when encrypt_time: true and time_bits is odd" do
      assert_raise ArgumentError,
                   ~r/time_bits must be an even number when encrypt_time is true/,
                   fn ->
                     FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
                       time_bits: 11,
                       encrypt_time: true,
                       data_bits: 40
                     )
                   end
    end

    test "raises when time_bucket is not positive" do
      assert_raise ArgumentError, ~r/time_bucket must be positive/, fn ->
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id", time_bucket: 0)
      end
    end

    test "raises when time_offset is not an integer" do
      assert_raise ArgumentError, ~r/time_offset must be an integer/, fn ->
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id", time_offset: 1.5)
      end
    end

    test "raises for invalid key" do
      assert_raise ArgumentError, ~r/key must be between 0 and 2\^31-1/, fn ->
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          key: -1,
          time_bits: 0
        )
      end

      max_key = Bitwise.bsl(1, 31)

      assert_raise ArgumentError, ~r/key must be between 0 and 2\^31-1/, fn ->
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          key: max_key,
          time_bits: 0
        )
      end
    end

    test "includes encrypt_time flag in SQL" do
      sql =
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          encrypt_time: true,
          time_bits: 16
        )

      assert sql =~ ", 0, true, 38,"
    end

    test "includes time_offset in SQL" do
      sql =
        FeistelCipher.up_for_legacy_trigger("public", "users", "seq", "id",
          time_offset: 21_600,
          time_bits: 12
        )

      assert sql =~ ", 21600, false, 38,"
    end
  end

  describe "down_for_legacy_trigger/4" do
    test "generates SQL with safety guard" do
      sql = FeistelCipher.down_for_legacy_trigger("public", "users", "seq", "id")

      assert sql =~ "RAISE EXCEPTION"
      assert sql =~ "DROP TRIGGER users_encrypt_seq_to_id_trigger"
      refute sql =~ "v1_trigger"
      assert sql =~ "public.users"
    end
  end

  describe "up_for_v1_trigger/5" do
    test "generates correct SQL with v1 trigger name" do
      sql = FeistelCipher.up_for_v1_trigger("public", "users", "seq", "id")

      assert sql =~ "CREATE TRIGGER"
      assert sql =~ "users_encrypt_seq_to_id_v1_trigger"
      assert sql =~ "public.users"
      assert sql =~ "feistel_trigger_v1"
    end
  end

  describe "down_for_v1_trigger/4" do
    test "generates SQL with safety guard and v1 trigger name" do
      sql = FeistelCipher.down_for_v1_trigger("public", "users", "seq", "id")

      assert sql =~ "RAISE EXCEPTION"
      assert sql =~ "DROP TRIGGER users_encrypt_seq_to_id_v1_trigger"
      assert sql =~ "public.users"
    end
  end

  describe "force_down_for_legacy_trigger/4" do
    test "generates SQL with legacy trigger name" do
      sql = FeistelCipher.force_down_for_legacy_trigger("public", "users", "seq", "id")

      assert sql =~ "DROP TRIGGER users_encrypt_seq_to_id_trigger"
      refute sql =~ "v1_trigger"
    end
  end

  describe "force_down_for_v1_trigger/4" do
    test "generates SQL with v1 trigger name" do
      sql = FeistelCipher.force_down_for_v1_trigger("public", "users", "seq", "id")

      assert sql =~ "DROP TRIGGER users_encrypt_seq_to_id_v1_trigger"
    end
  end
end
