defmodule FeistelCipher do
  @moduledoc false

  def default_seed do
    1_076_943_109
  end

  def random_key do
    <<key::31, _::1>> = :crypto.strong_rand_bytes(4)
    key
  end
end
