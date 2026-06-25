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
    (etc/"icloudpd-optimizer").mkpath
    (var/"log/icloudpd-optimizer").mkpath
  end

  service do
    run [
      opt_bin/"icloudpd-optimizer",
      "monitor",
      "run",
      "--config",
      etc/"icloudpd-optimizer/monitor.json",
    ]
    keep_alive true
    log_path var/"log/icloudpd-optimizer/stdout.log"
    error_log_path var/"log/icloudpd-optimizer/stderr.log"
    environment_variables PATH: std_service_path_env
  end

  def caveats
    <<~EOS
      Create a monitor config, then start the Homebrew service:

        icloudpd-optimizer monitor init --config #{etc}/icloudpd-optimizer/monitor.json ...
        brew services start icloudpd-optimizer

      For a custom config path, use:

        icloudpd-optimizer service install --config ~/.config/icloudpd-optimizer/monitor.json
        icloudpd-optimizer service start

      On macOS, grant Network Volumes or Full Disk Access to the service binary
      after installing or updating it if launchd cannot read your NAS mount.
      Replacing or re-signing the binary after granting access can invalidate the
      macOS privacy grant.
    EOS
  end

  test do
    assert_match "Fail-closed iCloudPD RAW optimization helper", shell_output("#{bin}/icloudpd-optimizer --help")
  end
end
