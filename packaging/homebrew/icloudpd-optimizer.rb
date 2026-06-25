class IcloudpdOptimizer < Formula
  desc "Fail-closed iCloudPD RAW optimization helper"
  homepage "https://github.com/bytware-alpha/icloudpd-optimizer"
  license "MIT"
  head "https://github.com/bytware-alpha/icloudpd-optimizer.git", branch: "main"

  depends_on "rust" => :build
  depends_on "exiftool"
  depends_on "imagemagick"
  depends_on "libheif"

  def install
    system "cargo", "install", *std_cargo_args
  end

  def caveats
    <<~EOS
      Create a monitor config, then install the macOS service wrapper:

        icloudpd-optimizer monitor init --config ~/.config/icloudpd-optimizer/monitor.json ...
        icloudpd-optimizer service install --config ~/.config/icloudpd-optimizer/monitor.json

      On macOS, grant iCloudPD Optimizer.app Network Volumes or Full Disk Access
      before starting the service.
    EOS
  end

  test do
    assert_match "Fail-closed iCloudPD RAW optimization helper", shell_output("#{bin}/icloudpd-optimizer --help")
  end
end
