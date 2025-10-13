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

  defmodule CreatePosts do
    use Ecto.Migration

    def up do
      create table(:posts, primary_key: false) do
        add(:seq, :bigserial)
        add(:id, :bigint, primary_key: true)
        add(:title, :string)
      end

      execute(FeistelCipher.up_for_trigger("public", "posts", "seq", "id"))
    end

    def down do
      execute(FeistelCipher.force_down_for_trigger("public", "posts", "seq", "id"))
      drop(table(:posts))
    end
  end
end
