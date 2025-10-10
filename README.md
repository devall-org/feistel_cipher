# FeistelCipher

Generate non-sequential, unpredictable IDs while maintaining the performance benefits of sequential primary keys.

## Why?

**Problem**: Sequential IDs (1, 2, 3...) leak business information:
- Competitors can estimate your growth rate
- Users can enumerate resources (`/posts/1`, `/posts/2`...)
- Total record counts are exposed

**Common Solutions & Issues**:
- UUIDs: Poor database performance (index fragmentation, 16 bytes storage)
- Random integers: Collision risks, complex generation logic

**This Library's Approach**:
- Store sequential integers internally (fast, efficient indexing)
- Expose encrypted integers externally (non-sequential, reversible)
- Automatic encryption via database trigger

## How It Works

The Feistel cipher is a symmetric structure used in the construction of block ciphers. This library implements a 4-round Feistel network that transforms sequential integers into non-sequential encrypted integers in a reversible manner.

<p align="center">
  <img src="assets/feistel-diagram-v2.png" alt="Feistel Cipher Diagram">
</p>

### Algorithm Details

For each round, the Feistel function `F` is defined as:

```
F(x, key, salt) = (((x ⊕ salt) × salt) ⊕ key) & half_mask
```

Where:
- `⊕` is XOR operation
- `×` is multiplication
- `&` is bitwise AND
- `half_mask` ensures the result fits in N/2 bits

### Self-Inverse Property

The Feistel cipher is **self-inverse**: applying the same function twice returns the original value. This means encryption and decryption use the exact same algorithm.

**Mathematical Proof:**

Let's denote the input as $(L_1, R_1)$ and the round function as $F(x)$.

**First application (Encryption):**

$$
\begin{aligned}
L_2 &= R_1, & R_2 &= L_1 \oplus F(R_1) \\
L_3 &= R_2, & R_3 &= L_2 \oplus F(R_2) \\
L_4 &= R_3, & R_4 &= L_3 \oplus F(R_3) \\
L_5 &= R_4, & R_5 &= L_4 \oplus F(R_4) \\
\text{Output} &= (R_5, L_5)
\end{aligned}
$$

**Second application (Decryption) - Starting with $(R_5, L_5)$:**

$$
\begin{aligned}
L_2' &= L_5, & R_2' &= R_5 \oplus F(L_5) \\
&= L_5, & &= R_5 \oplus F(R_4) \\
&= L_5, & &= (L_4 \oplus F(R_4)) \oplus F(R_4) \\
&= L_5, & &= L_4 \quad \text{(XOR cancellation)} \\
\\
L_3' &= R_2' = L_4, & R_3' &= L_2' \oplus F(R_2') \\
&= L_4, & &= L_5 \oplus F(L_4) \\
&= L_4, & &= R_4 \oplus F(R_3) \\
&= L_4, & &= (L_3 \oplus F(R_3)) \oplus F(R_3) \\
&= L_4, & &= L_3 \quad \text{(XOR cancellation)} \\
\\
L_4' &= R_3' = L_3, & R_4' &= L_3' \oplus F(R_3') \\
&= L_3, & &= L_4 \oplus F(L_3) \\
&= L_3, & &= R_3 \oplus F(R_2) \\
&= L_3, & &= (L_2 \oplus F(R_2)) \oplus F(R_2) \\
&= L_3, & &= L_2 = R_1 \\
\\
L_5' &= R_4' = R_1, & R_5' &= L_4' \oplus F(R_4') \\
&= R_1, & &= L_3 \oplus F(R_1) \\
&= R_1, & &= R_2 \oplus F(R_1) \\
&= R_1, & &= (L_1 \oplus F(R_1)) \oplus F(R_1) \\
&= R_1, & &= L_1 \quad \text{(XOR cancellation)} \\
\\
\text{Output} &= (R_5', L_5') = (L_1, R_1) \quad \checkmark
\end{aligned}
$$

**Key Insight:** The XOR operation's property $a \oplus b \oplus b = a$ ensures that each transformation is reversed when applied twice.

**Database Implementation:**

In the database trigger implementation, this means:
```sql
-- Encryption: seq → id
id = feistel_encrypt(seq, bits, key)

-- Decryption: id → seq (using the same function!)
seq = feistel_encrypt(id, bits, key)
```

### Key Properties

- **Deterministic**: Same input always produces same output
- **Non-sequential**: Sequential inputs produce seemingly random outputs
- **Collision-free**: One-to-one mapping within the bit range

## Installation

### Using igniter (Recommended)

```bash
mix igniter.install feistel_cipher
```

### Manual Installation

```elixir
# mix.exs
def deps do
  [{:feistel_cipher, "~> 0.9.0"}]
end
```

Then run:
```bash
mix deps.get
mix feistel_cipher.install
```

### Installation Options

Both methods support the following options:

* `--repo` or `-r`: Specify an Ecto repo (required for manual installation)
* `--functions-prefix` or `-p`: PostgreSQL schema prefix (default: `public`)
* `--functions-salt` or `-s`: Cipher salt constant, max 2^31-1 (default: `1_076_943_109`)


## Usage Example

### 1. Create Migration

```elixir
defmodule MyApp.Repo.Migrations.CreatePosts do
  use Ecto.Migration

  def up do
    create table(:posts, primary_key: false) do
      add :seq, :bigserial
      add :id, :bigint, primary_key: true
      add :title, :string
      
      timestamps()
    end

    execute FeistelCipher.up_for_trigger("public", "posts", "seq", "id")
  end

  def down do
    execute FeistelCipher.down_for_trigger("public", "posts", "seq", "id")
    drop table(:posts)
  end
end
```

### 2. Define Schema

```elixir
defmodule MyApp.Post do
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  schema "posts" do
    field :seq, :id, autogenerate: true
    field :title, :string
    
    timestamps()
  end
  
  # Use @derive to control JSON serialization
  @derive {Jason.Encoder, except: [:seq]}  # Hide seq in API responses
end
```

Now when you insert a record, `seq` auto-increments and the trigger automatically sets `id = feistel_encrypt(seq)`:

```elixir
%Post{title: "Hello"} |> Repo.insert()
# => %Post{id: 8234567, seq: 1, title: "Hello"}

# In API responses, only id is exposed (seq is hidden)
```

**Security Note**: Keep `seq` internal. Only expose `id` in APIs to prevent enumeration attacks.

## Trigger Options

The `up_for_trigger/5` function accepts these options:

- `prefix`, `table`, `source`, `target`: Table and column names (required)
- `bits`: Cipher bit size (default: 52, max: 62, must be even) - **Cannot be changed after creation**
  - Default 52 ensures JavaScript compatibility (`Number.MAX_SAFE_INTEGER = 2^53 - 1`)
  - Use 62 for maximum range if no browser/JS interaction needed
- `rounds`: Number of Feistel rounds (default: 16, min: 1, max: 32)
  - Default 16 provides good security/performance balance
  - Diagram shows 4 rounds for illustration purposes
  - More rounds = more secure but slower
  - Odd rounds (1, 3, 5...) and even rounds (2, 4, 6...) are both supported
- `key`: Encryption key (auto-generated if not specified)
- `functions_prefix`: Schema where cipher functions reside (default: `public`)

Example with custom options:
```elixir
execute FeistelCipher.up_for_trigger(
  "public", "posts", "seq", "id", 
  bits: 40, 
  key: 123456789,
  rounds: 8,
  functions_prefix: "crypto"
)
```

## Performance

Benchmark results encrypting 100,000 sequential values:

| Rounds | Total Time | Per Encryption | Use Case |
|--------|------------|----------------|----------|
| 1      | 104.64 ms  | ~1.0μs         | Minimal obfuscation |
| 4      | 174.34 ms  | ~1.7μs         | Diagram example |
| **16** | **464.85 ms** | **~4.6μs**  | **Default (recommended)** |

The overhead per INSERT is negligible (microseconds) even with 16 rounds.

### Benchmark Environment

- **CPU**: Apple M3 Pro (12 cores)
- **Database**: PostgreSQL 17 (Postgres.app)
- **OS**: macOS 15.6
- **Elixir**: 1.18.3 / OTP 27

### Running Benchmarks

```bash
MIX_ENV=test mix run benchmark/rounds_benchmark.exs
```

The benchmark encrypts 100,000 sequential values (1 to 100,000) using a SQL batch function to minimize overhead and measure pure encryption performance.

## License

MIT