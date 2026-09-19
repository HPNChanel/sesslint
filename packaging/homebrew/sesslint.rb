# Homebrew formula template for the self-hosted tap (HPNChanel/homebrew-tap).
# Rendered by scripts/render_manifests.py: placeholder markers are substituted
# and own-line {if:key}...{/if:key} blocks kept only when the artifact exists
# in the release sums. Rendered output is committed to the tap repo, not here.
class Sesslint < Formula
  desc "Offline session-integrity checker and conservative repair tool for AI agent session ledgers"
  homepage "https://github.com/{repo}"
  version "{version}"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "{url_macos_arm64}"
      sha256 "{sha256_macos_arm64}"
    end
{if:macos_x86_64}
    if Hardware::CPU.intel?
      url "{url_macos_x86_64}"
      sha256 "{sha256_macos_x86_64}"
    end
{/if:macos_x86_64}
  end

  on_linux do
    if Hardware::CPU.intel?
      url "{url_linux_x86_64}"
      sha256 "{sha256_linux_x86_64}"
    end
{if:linux_arm64}
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "{url_linux_arm64}"
      sha256 "{sha256_linux_arm64}"
    end
{/if:linux_arm64}
  end

  def install
    bin.install Dir["sesslint-*"].first => "sesslint"
  end

  test do
    assert_match "{version}", shell_output("#{bin}/sesslint version --json")
    system bin/"sesslint", "check", "--help"
  end
end
