defmodule BubblprocTest do
  use ExUnit.Case
  doctest Bubbleproc

  setup do
    tmp_dir = System.tmp_dir!() |> Path.join("bubbleproc_test_#{:rand.uniform(100_000)}")
    File.mkdir_p!(tmp_dir)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)
    {:ok, tmp_dir: tmp_dir}
  end

  describe "run/2" do
    test "executes simple commands" do
      assert {:ok, %{code: 0, stdout: stdout}} = Bubbleproc.run("echo hello")
      assert String.trim(stdout) == "hello"
    end

    test "blocks network by default" do
      {:ok, result} = Bubbleproc.run("curl -s --connect-timeout 2 https://example.com || echo blocked")
      assert String.contains?(result.stdout, "blocked")
    end

    test "allows network when enabled" do
      {:ok, result} = Bubbleproc.run("curl -s --connect-timeout 5 https://example.com | head -c 50", network: true)
      assert String.length(result.stdout) > 0
    end

    test "allows read-write to specified paths", %{tmp_dir: tmp_dir} do
      test_file = Path.join(tmp_dir, "test.txt")
      
      {:ok, _} = Bubbleproc.run("echo hello > #{test_file}", rw: [tmp_dir])
      
      assert File.exists?(test_file)
      assert File.read!(test_file) |> String.trim() == "hello"
    end

    test "blocks write to system paths" do
      assert {:error, %Bubbleproc.Error{}} = Bubbleproc.run("ls", rw: ["/usr/bin"])
    end
  end

  describe "Sandbox" do
    test "can be reused for multiple commands", %{tmp_dir: tmp_dir} do
      {:ok, sandbox} = Bubbleproc.Sandbox.new(rw: [tmp_dir])
      
      {:ok, _} = Bubbleproc.Sandbox.run(sandbox, "touch #{Path.join(tmp_dir, "file1.txt")}")
      {:ok, _} = Bubbleproc.Sandbox.run(sandbox, "touch #{Path.join(tmp_dir, "file2.txt")}")
      
      assert File.exists?(Path.join(tmp_dir, "file1.txt"))
      assert File.exists?(Path.join(tmp_dir, "file2.txt"))
    end
  end

  describe "aider_sandbox/2" do
    test "creates sandbox with correct defaults", %{tmp_dir: tmp_dir} do
      {:ok, sandbox} = Bubbleproc.aider_sandbox(tmp_dir)
      
      assert sandbox.network == true
      assert sandbox.share_home == true
      assert tmp_dir in sandbox.rw
      assert "ANTHROPIC_API_KEY" in sandbox.env_passthrough
    end
  end
end
