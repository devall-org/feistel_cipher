defmodule FeistelCipher.TestMigrations do
  @moduledoc """
  Test migrations for FeistelCipher
  """

  defmodule AddFeistelCipher do
    use Ecto.Migration

    def up do
      FeistelCipher.up_for_functions(functions_prefix: "public", functions_salt: 1_076_943_109)
    end

    def down do
      FeistelCipher.down_for_functions(functions_prefix: "public")
    end
  end

  defmodule AddFeistelCipherCrypto do
    use Ecto.Migration

    def up do
      FeistelCipher.up_for_functions(functions_prefix: "crypto", functions_salt: 1_076_943_109)
    end

    def down do
      FeistelCipher.down_for_functions(functions_prefix: "crypto")
    end
  end

  defmodule AddFeistelCipherCustomSalt do
    use Ecto.Migration

    def up do
      FeistelCipher.up_for_functions(functions_prefix: "public", functions_salt: 999_999_999)
    end

    def down do
      FeistelCipher.down_for_functions(functions_prefix: "public")
    end
  end
end
