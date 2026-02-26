defmodule FeistelCipher.EctoIntegrationTest do
  use ExUnit.Case, async: false
  alias FeistelCipher.{TestRepo, Post}

  setup_all do
    # Create cipher functions and posts table with trigger
    Ecto.Migrator.run(
      TestRepo,
      [
        {0, FeistelCipher.TestMigrations.AddFeistelCipher},
        {1, FeistelCipher.TestMigrations.CreatePosts}
      ],
      :up,
      all: true,
      log: false
    )

    on_exit(fn ->
      Ecto.Migrator.run(
        TestRepo,
        [
          {1, FeistelCipher.TestMigrations.CreatePosts},
          {0, FeistelCipher.TestMigrations.AddFeistelCipher}
        ],
        :down,
        all: true,
        log: false
      )
    end)

    :ok
  end

  setup do
    # Clean up posts before each test
    TestRepo.delete_all(Post)
    :ok
  end

  describe "Ecto Schema integration" do
    test "automatically encrypts seq to id on INSERT" do
      # Insert a post
      post = %Post{title: "Hello World"} |> TestRepo.insert!()

      # Verify seq and id are both set
      assert is_integer(post.seq)
      assert post.seq > 0
      assert is_integer(post.id)
      # id should be different from seq (encrypted)
      assert post.id != post.seq
      assert post.title == "Hello World"

      # Verify we can query by the encrypted id
      found_post = TestRepo.get!(Post, post.id)
      assert found_post.seq == post.seq
      assert found_post.id == post.id
      assert found_post.title == "Hello World"
    end

    test "encrypts multiple posts with different encrypted IDs" do
      post1 = %Post{title: "First Post"} |> TestRepo.insert!()
      post2 = %Post{title: "Second Post"} |> TestRepo.insert!()
      post3 = %Post{title: "Third Post"} |> TestRepo.insert!()

      # seq should be sequential and incrementing
      assert is_integer(post1.seq)
      assert is_integer(post2.seq)
      assert is_integer(post3.seq)
      assert post2.seq == post1.seq + 1
      assert post3.seq == post2.seq + 1

      # id should be encrypted (non-sequential)
      assert post1.id != post1.seq
      assert post2.id != post2.seq
      assert post3.id != post3.seq

      # All encrypted IDs should be different
      assert post1.id != post2.id
      assert post2.id != post3.id
      assert post1.id != post3.id

      # Verify all posts can be queried by their encrypted IDs
      assert TestRepo.get!(Post, post1.id).title == "First Post"
      assert TestRepo.get!(Post, post2.id).title == "Second Post"
      assert TestRepo.get!(Post, post3.id).title == "Third Post"
    end

    test "data part encryption is deterministic and reversible" do
      # Insert and get the encrypted id
      post = %Post{title: "Test"} |> TestRepo.insert!()
      seq = post.seq
      encrypted_id = post.id

      # With time_bits: 14 (default), data_bits: 38 (default)
      data_bits = 38
      data_mask = Bitwise.bsl(1, data_bits) - 1
      data_component = Bitwise.band(encrypted_id, data_mask)

      # Verify data part decrypts back to seq
      key = FeistelCipher.generate_key("public", "posts", "seq", "id")

      %{rows: [[decrypted_seq]]} =
        TestRepo.query!(
          "SELECT public.feistel_cipher_v1($1::bigint, $2, $3::bigint, 16)",
          [data_component, data_bits, key]
        )

      assert decrypted_seq == seq

      # Verify determinism: encrypting seq gives the same data_component
      %{rows: [[db_data_component]]} =
        TestRepo.query!(
          "SELECT public.feistel_cipher_v1($1::bigint, $2, $3::bigint, 16)",
          [seq, data_bits, key]
        )

      assert db_data_component == data_component
    end

    test "id includes time prefix when time_bits > 0" do
      post = %Post{title: "Hello"} |> TestRepo.insert!()

      assert is_integer(post.seq)
      assert is_integer(post.id)
      assert post.id != post.seq
      assert post.title == "Hello"

      # Default: time_bits: 14, time_bucket: 86400, data_bits: 38
      time_bits = 14
      data_bits = 38
      time_bucket = 86400

      epoch_now = System.os_time(:second)
      time_mask = Bitwise.bsl(1, time_bits) - 1

      expected_time_prefix =
        div(epoch_now, time_bucket) |> Bitwise.band(time_mask)

      actual_time_prefix = Bitwise.bsr(post.id, data_bits)
      assert actual_time_prefix == expected_time_prefix
    end
  end
end
