defmodule Mix.Tasks.FeistelCipher.InstallTest do
  use ExUnit.Case, async: true

  import Igniter.Test

  @moduletag :igniter

  describe "install" do
    test "installing without an available ecto repo" do
      assert {:error, [warning]} =
               test_project()
               |> Igniter.compose_task("feistel_cipher.install", [])
               |> apply_igniter()

      assert warning =~ "No ecto repos found for :test"
    end
  end
end
