defmodule FeistelCipher do
  @moduledoc false

  def key(table, source, target, bits) do
    <<key::31, _::481>> = :crypto.hash(:sha512, "#{table}_#{source}_#{target}_#{bits}")
    key
  end

  def trigger_name(table, source, target) do
    "#{table}_encrypt_#{source}_to_#{target}_trigger"
  end

  def with_defaults(opts) do
    opts = Enum.into(opts, %{prefix: default_prefix(), seed: default_seed()})

    opts
    |> Map.put_new(:create_schema, opts.prefix != default_prefix())
    |> Map.put(:quoted_prefix, inspect(opts.prefix))
    |> Map.put(:escaped_prefix, String.replace(opts.prefix, "'", "\\'"))
  end

  def default_prefix do
    "public"
  end

  def default_seed do
    1_076_943_109
  end
end
