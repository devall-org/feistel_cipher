defmodule FeistelCipher.Post do
  @moduledoc """
  Test schema for FeistelCipher integration testing
  """
  use Ecto.Schema

  # Hide seq in API responses
  @derive {Jason.Encoder, except: [:seq]}

  @primary_key {:id, :id, autogenerate: false, read_after_writes: true}
  schema "posts" do
    field(:seq, :id, read_after_writes: true)
    field(:title, :string)
  end
end
