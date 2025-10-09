defmodule FeistelCipher.TestRepo.Migrations.AddFeistelCipher do
  use Ecto.Migration

  def up do
    FeistelCipher.Migration.up(functions_prefix: "public", functions_salt: 1_076_943_109)
  end

  def down do
    FeistelCipher.Migration.down(functions_prefix: "public")
  end
end
