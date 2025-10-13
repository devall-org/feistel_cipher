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

    test "encryption is deterministic" do
      # Insert and get the encrypted id
      post = %Post{title: "Test"} |> TestRepo.insert!()
      seq = post.seq
      encrypted_id = post.id

      # Verify determinism using the cipher function directly
      %{rows: [[db_encrypted_id]]} =
        TestRepo.query!(
          "SELECT public.feistel_encrypt($1::bigint, 52, $2::bigint, 16) as encrypted_id",
          [seq, FeistelCipher.generate_key("public", "posts", "seq", "id")]
        )

      assert db_encrypted_id == encrypted_id
    end

    test "matches README example behavior" do
      # This test verifies the exact behavior shown in the README
      post = %Post{title: "Hello"} |> TestRepo.insert!()

      # Should have both seq and encrypted id
      assert is_integer(post.seq)
      assert is_integer(post.id)
      assert post.id != post.seq
      assert post.title == "Hello"
    end
  end
end
