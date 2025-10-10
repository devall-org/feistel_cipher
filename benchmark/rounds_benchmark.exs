alias FeistelCipher.TestRepo

# Start the test repo
{:ok, _} = TestRepo.start_link()

# Create feistel functions using the library
Ecto.Migrator.run(TestRepo, [{0, FeistelCipher.TestMigrations.AddFeistelCipher}], :up, all: true)

# Create benchmark utility function that encrypts multiple values
TestRepo.query!("""
CREATE OR REPLACE FUNCTION public.feistel_encrypt_batch(
  start_val bigint,
  end_val bigint,
  bits int,
  key bigint,
  rounds int
) RETURNS bigint AS $$
DECLARE
  i bigint;
  result bigint;
BEGIN
  FOR i IN start_val..end_val LOOP
    result := public.feistel_encrypt(i, bits, key, rounds);
  END LOOP;
  RETURN result;
END;
$$ LANGUAGE plpgsql;
""")

IO.puts("✓ Feistel functions created")

# Test data - encrypting 100,000 values
start_val = 1
end_val = 100_000
bits = 52
key = 987_654_321

IO.puts("\n=== Feistel Cipher Rounds Benchmark ===\n")
IO.puts("Encrypting #{end_val - start_val + 1} values (#{start_val} to #{end_val})")
IO.puts("Bits: #{bits}")
IO.puts("Key: #{key}\n")

Benchee.run(
  %{
    "1 round" => fn ->
      TestRepo.query!("SELECT public.feistel_encrypt_batch($1, $2, $3, $4, 1)", [
        start_val,
        end_val,
        bits,
        key
      ])
    end,
    "2 rounds (diagram)" => fn ->
      TestRepo.query!("SELECT public.feistel_encrypt_batch($1, $2, $3, $4, 2)", [
        start_val,
        end_val,
        bits,
        key
      ])
    end,
    "4 rounds" => fn ->
      TestRepo.query!("SELECT public.feistel_encrypt_batch($1, $2, $3, $4, 4)", [
        start_val,
        end_val,
        bits,
        key
      ])
    end,
    "8 rounds" => fn ->
      TestRepo.query!("SELECT public.feistel_encrypt_batch($1, $2, $3, $4, 8)", [
        start_val,
        end_val,
        bits,
        key
      ])
    end,
    "16 rounds (default)" => fn ->
      TestRepo.query!("SELECT public.feistel_encrypt_batch($1, $2, $3, $4, 16)", [
        start_val,
        end_val,
        bits,
        key
      ])
    end,
    "32 rounds" => fn ->
      TestRepo.query!("SELECT public.feistel_encrypt_batch($1, $2, $3, $4, 32)", [
        start_val,
        end_val,
        bits,
        key
      ])
    end
  },
  warmup: 1,
  time: 3,
  memory_time: 0,
  formatters: [
    {Benchee.Formatters.Console, comparison: true, extended_statistics: true}
  ]
)

# Cleanup
TestRepo.query!(
  "DROP FUNCTION IF EXISTS public.feistel_encrypt_batch(bigint, bigint, int, bigint, int)"
)

Ecto.Migrator.run(TestRepo, [{0, FeistelCipher.TestMigrations.AddFeistelCipher}], :down,
  all: true
)

IO.puts("\n✓ Cleanup completed")
