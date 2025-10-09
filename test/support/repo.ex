defmodule FeistelCipher.TestRepo do
  use Ecto.Repo,
    otp_app: :feistel_cipher,
    adapter: Ecto.Adapters.Postgres
end
