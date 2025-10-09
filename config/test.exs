import Config

config :feistel_cipher, FeistelCipher.TestRepo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "feistel_cipher_test",
  pool: Ecto.Adapters.SQL.Sandbox,
  priv: "test/support"

config :feistel_cipher, ecto_repos: [FeistelCipher.TestRepo]

config :logger, level: :warning
