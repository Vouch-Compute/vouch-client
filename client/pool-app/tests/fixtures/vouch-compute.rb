cask "vouch-compute" do
  version "0.1.0"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  url "https://downloads.vouchcompute.com/macos/#{version}/VouchCompute-#{version}-macos-arm64.dmg",
      verified: "downloads.vouchcompute.com/macos/"
  name "Vouch Compute"
  desc "Contributor client for a paid, verified AI inference pool"
  homepage "https://www.vouchcompute.com/"

  # The app's own update manifest (Tauri updater, static format) is the version source.
  livecheck do
    url "https://downloads.vouchcompute.com/desktop/stable/latest.json"
    strategy :json do |json|
      json["version"]
    end
  end

  auto_updates true
  depends_on arch: :arm64
  depends_on macos: ">= :ventura"

  app "Vouch Compute.app"

  # launchctl: the "Start at sign-in" login item is a LaunchAgent named after the app (~/Library/LaunchAgents/Vouch
  # Compute.plist). quit: the bundle id of the release build. script: the agent helper (pool-core) keeps running
  # after the app quits, so it is stopped by path; must_succeed is false because it is not always running.
  uninstall launchctl: "Vouch Compute",
            quit:      "com.vouchcompute.app",
            script:    {
              executable:   "/usr/bin/pkill",
              args:         ["-f", "#{appdir}/Vouch Compute.app/Contents/MacOS/pool-core"],
              must_succeed: false,
            }

  # Application Support holds the agent's state, device keys, session token, downloaded models and logs. The others
  # are the WebView's storage for the app's bundle id (settings kept in localStorage, caches, window state).
  zap trash: [
    "~/Library/Application Support/com.vouchcompute.app",
    "~/Library/Caches/com.vouchcompute.app",
    "~/Library/HTTPStorages/com.vouchcompute.app",
    "~/Library/Preferences/com.vouchcompute.app.plist",
    "~/Library/Saved Application State/com.vouchcompute.app.savedState",
    "~/Library/WebKit/com.vouchcompute.app",
  ]
end
