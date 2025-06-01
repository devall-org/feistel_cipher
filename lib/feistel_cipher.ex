defmodule FeistelCipher do
  @moduledoc false

  def key_for_table(table) do
    <<key::31, _::481>> = :crypto.hash(:sha512, table)
    key
  end

  def trigger_name(table, source, target) do
    "#{table}_encrypt_#{source}_to_#{target}_trigger"
  end

  def with_defaults(opts) do
    opts = Enum.into(opts, %{prefix: default_prefix()})

    opts
    |> Map.put_new(:create_schema, opts.prefix != default_prefix())
    |> Map.put_new(:xor, default_xor())
    |> Map.put_new(:mul, default_mul())
    |> Map.put(:quoted_prefix, inspect(opts.prefix))
    |> Map.put(:escaped_prefix, String.replace(opts.prefix, "'", "\\'"))
  end

  def default_prefix do
    "public"
  end

  def default_xor do
    1_076_943_109
  end

  def default_mul do
    1_552_717_019
  end
end
