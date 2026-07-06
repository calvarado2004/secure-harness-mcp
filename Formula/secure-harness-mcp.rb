# Homebrew formula for the secure-harness MCP server.
#
# Install (HEAD, no release needed):
#   brew tap calvarado2004/secure-harness https://github.com/calvarado2004/secure-harness-mcp
#   brew install --HEAD secure-harness-mcp
# or directly from a clone:
#   brew install --HEAD ./Formula/secure-harness-mcp.rb
#
# Provides two commands:
#   secure-harness-mcp     - the MCP server (stdio) for Qwen Code / Claude Code / Cursor
#   secure-harness-proxy   - the transparent OpenAI-compatible hardening proxy
class SecureHarnessMcp < Formula
  desc "Verify-and-repair secure-coding harness as an MCP server + transparent proxy"
  homepage "https://github.com/calvarado2004/secure-harness-mcp"
  head "https://github.com/calvarado2004/secure-harness-mcp.git", branch: "main"
  license "MIT"

  # For a tagged release, uncomment and fill in:
  # url "https://github.com/calvarado2004/secure-harness-mcp/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "..."

  depends_on "go"            # build check for generated Go
  depends_on "python@3.12"

  def install
    venv = libexec/"venv"
    system Formula["python@3.12"].opt_bin/"python3.12", "-m", "venv", venv
    system venv/"bin/pip", "install", "--quiet", "--upgrade", "pip"
    system venv/"bin/pip", "install", "--quiet", *File.read("requirements.txt").split
    libexec.install Dir["*.py"], Dir["*.txt"], "vuln_patterns.yaml"

    (bin/"secure-harness-mcp").write <<~SH
      #!/bin/bash
      exec "#{venv}/bin/python" "#{libexec}/secure_coding_mcp.py" "$@"
    SH
    (bin/"secure-harness-proxy").write <<~SH
      #!/bin/bash
      exec "#{venv}/bin/python" "#{libexec}/secure_proxy.py" "$@"
    SH
    chmod 0755, bin/"secure-harness-mcp"
    chmod 0755, bin/"secure-harness-proxy"
  end

  def caveats
    <<~EOS
      Configure a model backend before use, e.g.:
        export SECURE_HARNESS_MODEL_URL=http://localhost:11434/v1
        export SECURE_HARNESS_MODEL=qwen2.5-coder:32b

      Register the MCP server with Qwen Code:
        qwen mcp add secure-coding secure-harness-mcp

      A Go toolchain is required for the build check (installed as a dependency).
    EOS
  end

  test do
    # The scorer self-test needs no network and proves the instruments fire.
    assert_predicate bin/"secure-harness-proxy", :exist?
    system bin/"secure-harness-proxy", "--self-test"
  end
end
