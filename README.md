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
- Store sequential `seq` (fast, efficient indexing)
- Expose encrypted `id` (non-sequential, reversible)
- Transform via database trigger (zero application overhead)

## How It Works

The Feistel cipher is a symmetric structure used in the construction of block ciphers. This library implements a 4-round Feistel network that transforms sequential integers into non-sequential encrypted integers in a reversible manner.

```mermaid
flowchart TB
    Input["Input: N bits"]
    
    subgraph Initial["Input Split"]
        L0["L0<br/>(Left N/2 bits)"]
        R0["R0<br/>(Right N/2 bits)"]
    end
    
    subgraph Round1["Round 1"]
        direction LR
        XOR1["⊕"]
        F1["F(R0)"]
        L1["L1"]
        R1["R1"]
    end
    
    subgraph Round2["Round 2"]
        direction LR
        XOR2["⊕"]
        F2["F(R1)"]
        L2["L2"]
        R2["R2"]
    end
    
    subgraph Round3["Round 3"]
        direction LR
        XOR3["⊕"]
        F3["F(R2)"]
        L3["L3"]
        R3["R3"]
    end
    
    subgraph Round4["Round 4"]
        direction LR
        XOR4["⊕"]
        F4["F(R3)"]
        L4["L4"]
        R4["R4"]
    end
    
    subgraph Final["Final Swap"]
        L5["L5"]
        R5["R5"]
    end
    
    Input --> Initial
    
    L0 --> XOR1
    R0 --> F1
    R0 -.Copy.-> L1
    F1 --> XOR1
    XOR1 --> R1
    
    L1 --> XOR2
    R1 --> F2
    R1 -.Copy.-> L2
    F2 --> XOR2
    XOR2 --> R2
    
    L2 --> XOR3
    R2 --> F3
    R2 -.Copy.-> L3
    F3 --> XOR3
    XOR3 --> R3
    
    L3 --> XOR4
    R3 --> F4
    R3 -.Copy.-> L4
    F4 --> XOR4
    XOR4 --> R4
    
    L4 --> R5
    R4 --> L5
    
    L5 --> Output["Output: N bits"]
    R5 --> Output
    
    style Input fill:#e1f5ff
    style Output fill:#e1f5ff
    style L0 fill:#ffe1e1
    style R0 fill:#e1ffe1
    style L1 fill:#ffe1e1
    style R1 fill:#e1ffe1
    style L2 fill:#ffe1e1
    style R2 fill:#e1ffe1
    style L3 fill:#ffe1e1
    style R3 fill:#e1ffe1
    style L4 fill:#ffe1e1
    style R4 fill:#e1ffe1
    style L5 fill:#ffe1e1
    style R5 fill:#e1ffe1
    style F1 fill:#fff4e1
    style F2 fill:#fff4e1
    style F3 fill:#fff4e1
    style F4 fill:#fff4e1
```

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

Let's denote the input as $(L_0, R_0)$ and the round function as $F(x)$.

**First application (Encryption):**

```math
\begin{aligned}
L_1 &= R_0, & R_1 &= L_0 \oplus F(R_0) \\
L_2 &= R_1, & R_2 &= L_1 \oplus F(R_1) \\
L_3 &= R_2, & R_3 &= L_2 \oplus F(R_2) \\
L_4 &= R_3, & R_4 &= L_3 \oplus F(R_3) \\
\text{Output} &= (R_4, L_4)
\end{aligned}
```

**Second application (Decryption) - Starting with $(R_4, L_4)$:**

```math
\begin{aligned}
L_1' &= L_4, & R_1' &= R_4 \oplus F(L_4) \\
&= L_4, & &= R_4 \oplus F(R_3) \\
&= L_4, & &= (L_3 \oplus F(R_3)) \oplus F(R_3) \\
&= L_4, & &= L_3 \quad \text{(XOR cancellation)} \\
\\
L_2' &= R_1' = L_3, & R_2' &= L_1' \oplus F(R_1') \\
&= L_3, & &= L_4 \oplus F(L_3) \\
&= L_3, & &= R_3 \oplus F(R_2) \\
&= L_3, & &= (L_2 \oplus F(R_2)) \oplus F(R_2) \\
&= L_3, & &= L_2 \quad \text{(XOR cancellation)} \\
\\
L_3' &= R_2' = L_2, & R_3' &= L_2' \oplus F(R_2') \\
&= L_2, & &= L_3 \oplus F(L_2) \\
&= L_2, & &= R_2 \oplus F(R_1) \\
&= L_2, & &= (L_1 \oplus F(R_1)) \oplus F(R_1) \\
&= L_2, & &= L_1 = R_0 \\
\\
L_4' &= R_3' = R_0, & R_4' &= L_3' \oplus F(R_3') \\
&= R_0, & &= L_2 \oplus F(R_0) \\
&= R_0, & &= R_1 \oplus F(R_0) \\
&= R_0, & &= (L_0 \oplus F(R_0)) \oplus F(R_0) \\
&= R_0, & &= L_0 \quad \text{(XOR cancellation)} \\
\\
\text{Output} &= (R_4', L_4') = (L_0, R_0) \quad \checkmark
\end{aligned}
```

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
  [{:feistel_cipher, "~> 0.7.2"}]
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
- `key`: Encryption key (auto-generated if not specified)
- `functions_prefix`: Schema where cipher functions reside (default: `public`)

Example with custom options:
```elixir
execute FeistelCipher.up_for_trigger(
  "public", "posts", "seq", "id", 
  bits: 40, 
  key: 123456789,
  functions_prefix: "crypto"
)
```

## License

MIT