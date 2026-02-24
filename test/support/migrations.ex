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

    # 2025-01-01 00:00:00 UTC
    @time_offset 1_735_689_600
    # 1 hour
    @time_bucket 3600

    def up do
      create table(:posts) do
        add(:seq, :bigserial)
        add(:title, :string)
      end

      execute(
        FeistelCipher.up_for_trigger("public", "posts", "seq", "id",
          time_offset: @time_offset,
          time_bucket: @time_bucket
        )
      )
    end

    def down do
      execute(FeistelCipher.force_down_for_trigger("public", "posts", "seq", "id"))
      drop(table(:posts))
    end
  end
end
