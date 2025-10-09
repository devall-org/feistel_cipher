defmodule FeistelCipher.TestMigrations do
  @moduledoc """
  Test migrations for FeistelCipher
  """

  defmodule AddFeistelCipher do
    use Ecto.Migration

    def up do
      FeistelCipher.Migration.up(functions_prefix: "public", functions_salt: 1_076_943_109)
    end

    def down do
      FeistelCipher.Migration.down(functions_prefix: "public")
    end
  end

  defmodule AddFeistelCipherCrypto do
    use Ecto.Migration

    def up do
      FeistelCipher.Migration.up(functions_prefix: "crypto", functions_salt: 1_076_943_109)
    end

    def down do
      FeistelCipher.Migration.down(functions_prefix: "crypto")
    end
  end

  defmodule AddFeistelCipherCustomSalt do
    use Ecto.Migration

    def up do
      FeistelCipher.Migration.up(functions_prefix: "public", functions_salt: 999_999_999)
    end

    def down do
      FeistelCipher.Migration.down(functions_prefix: "public")
    end
  end
end
