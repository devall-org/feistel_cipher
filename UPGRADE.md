# Upgrading FeistelCipher

## From v0.14.0 or v0.15.0 to v1.0.0

v0.14.0/v0.15.0 → v1.0.0 is **fully backward compatible** when using `time_bits: 0`. The cipher algorithm (HMAC-SHA256) is identical; only the API and PostgreSQL function names changed.

### What changed

- **PG function names**: `feistel_cipher` → `feistel_cipher_v1`, `feistel_column_trigger` → `feistel_column_trigger_v1`. Old functions are left untouched so they coexist during upgrade.
- **`bits` option renamed to `data_bits`** (default changed from 52 to 40)
- **New `time_bits` option** (default: 12) for time-based prefix. Use `time_bits: 0` to keep the old behavior.
- **`time_offset` option removed**
- **New options**: `time_bucket` (default: 86400), `encrypt_time` (default: false)

### Steps

1. Update dependency to `~> 1.0`

2. Run the upgrade task to generate a database migration:

```bash
mix feistel_cipher.upgrade
```

3. Edit the generated migration to fill in your `functions_salt` (find it in the migration with timestamp 19730501000000):

```elixir
def up do
  # Install v1 functions (coexist with old v0.x functions).
  FeistelCipher.up_for_functions(functions_prefix: "public", functions_salt: YOUR_SALT)
end

def down do
  FeistelCipher.down_for_functions(functions_prefix: "public")
end
```

4. Generate trigger migration(s):

   **For Ash users**: Run `mix ash.codegen --name upgrade_feistel_triggers_to_v1`. In the generated migration's `up` function, replace `down_for_trigger` (or `down_for_v1_trigger`) with `force_down_for_legacy_trigger` to drop legacy triggers. Also in the `down` function, replace `up_for_trigger` with `up_for_legacy_trigger` and `bits:` with `time_bits: 0, data_bits:`.

   **For plain Ecto users**: Create a separate migration to upgrade each trigger from v0.x to v1. For each table using Feistel cipher, drop the old trigger and recreate with v1:

   ```elixir
   # bits: N  ->  time_bits: 0, data_bits: N  (old default for bits was 52)
   execute FeistelCipher.force_down_for_legacy_trigger("public", "posts", "seq", "id")
   execute FeistelCipher.up_for_v1_trigger("public", "posts", "seq", "id",
     time_bits: 0, data_bits: 52, functions_prefix: "public")
   ```

5. **(Optional)** Drop old v0.x functions in your **last** migration. Which functions exist depends on the version you're upgrading from:

   ```elixir
   # v0.15.0
   execute "DROP FUNCTION IF EXISTS public.feistel_cipher(bigint, int, bigint, int)"
   execute "DROP FUNCTION IF EXISTS public.feistel_column_trigger()"

   # v0.14.0
   execute "DROP FUNCTION IF EXISTS public.feistel_encrypt(bigint, int, bigint, int)"
   execute "DROP FUNCTION IF EXISTS public.feistel_column_trigger()"

   # v0.13.x or earlier
   execute "DROP FUNCTION IF EXISTS public.feistel(bigint, int, bigint)"
   execute "DROP FUNCTION IF EXISTS public.handle_feistel_encryption()"
   ```

6. Run `mix ecto.migrate`

---

## From v0.13.x or earlier to v1.0.0

v0.14.0 introduced a **breaking change to the cipher algorithm**: the round function was hardened from a simple hash to HMAC-SHA256. This means **encryption results are different** — the same input produces different output.

### Impact

- **Existing encrypted data remains valid** as long as the old PostgreSQL functions (`feistel_cipher`) stay in the database.
- **New rows will use `feistel_cipher_v1`** which produces different encrypted values than the old `feistel_cipher` for the same input.
- There are **no primary key collisions** because both old and new functions are bijective (one-to-one mapping) within their bit range. The old function maps input space A → output space A (a permutation), and the new function maps input space A → output space A (a different permutation). Since each is collision-free independently, mixing them does not cause collisions.
- However, the **1:1 reversibility property is lost for old rows**: calling `feistel_cipher_v1(old_encrypted_id)` will NOT return the original `seq` value.

### When this matters

- If your application **decrypts IDs** (e.g., `id → seq` lookup using the cipher function), old rows will decrypt incorrectly with the new function.
- If your application only uses encrypted IDs as **opaque identifiers** (lookup by `id` directly), this is not an issue.

### Steps

Follow the same steps as "From v0.14.0 or v0.15.0 to v1.0.0" above. The upgrade task works the same way.

If you need to maintain decryption capability for old rows, keep the old `feistel_cipher` function in the database (skip Step 3) and use it for decrypting pre-upgrade data.
