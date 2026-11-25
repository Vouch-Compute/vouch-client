# Mac acceptance checklist (test builds)

No version is tagged or published until the owner has run this checklist on their Mac with a test build and every
step passes (owner rule T-227). Takes about 45 minutes, most of it waiting.

## Get the test build

1. On GitHub, open **Actions → client-test-build → Run workflow**, pick the branch, keep `macos`, and run it.
2. When it is green, download the artifact `VouchCompute-test-<commit>-macos-arm64` from the run page and unzip it.
   It holds `VouchCompute-test-<commit>-macos-arm64.dmg` and `SHA256SUMS.txt`.
3. Optional: check the file with `shasum -a 256 VouchCompute-test-*.dmg` and compare it with `SHA256SUMS.txt`.

A test build is never published and never offered as an update. It uses the production servers, so it is a real
device on the owner's account.

## Steps

Before you start: the Mac runs 0.2.1, is registered to your account and is plugged in.

| # | Do | You must see |
|---|----|--------------|
| 1 | Quit Vouch Compute (menu-bar icon → Quit). Open the .dmg and drag the app onto Applications → **Replace**. First start: right-click the app → **Open** → **Open**. | The app opens straight to Home, with no setup steps. **Settings → About → Agent version** shows `0.2.1-test.<commit>`. |
| 2 | Look at Settings → Account. If it says "Not signed in" (the 0.2.1 sign-in on this Mac was revoked on 25 November), press **Sign in** and finish in the browser. | "Signed in on this computer." and a **Sign out** button. There is no **Start over** button (the computer is registered). Signing in again keeps the same device: no new registration and no setup steps. |
| 3 | Wait up to a minute on Home. | The status moves from "Connecting…" to **online** (Idle, waiting for jobs, or a benchmark running). It doesn't stay on "Offline". The **Device** page shows this Mac as online. |
| 4 | Model download: on the Device page, watch the benchmark card (or press **Run now** if offered). | The model (bge-m3, about 2.3 GB) downloads once. Progress shows, and it doesn't restart from zero. |
| 5 | Speed test: let the benchmark run. Keep the keyboard and mouse still (it pauses while you use the Mac). | The benchmark runs and finishes. The **Performance** card shows a speed in **tokens per second** and "Received by the server". The server's status and tier appear next to it. |
| 6 | Leave the app running for **at least 30 minutes**, then come back. | Still online and still signed in. **Earnings** and the **estimate** load without "Your sign-in has expired". This step checks that sign-in renewals don't sign you out. |
| 7 | Quit from the menu-bar icon, then reopen the app. | Back online within a minute. Still signed in and registered; no setup steps. |
| 8 | Check that "Start over" is refused: Settings → Account. | No **Start over** button on a registered computer. Nothing you can do in the app clears its registration except **Remove this device**, which needs typing `REMOVE`. |
| 9 | Offline message: turn off Wi-Fi for 2 minutes, then turn it back on. | While Wi-Fi is off, Home shows **Offline** with "Can't reach the Vouch Compute network right now. Retrying in …", plus the last problem underneath. When Wi-Fi is back, the app reconnects by itself within a few minutes (or at once with **Try again now**). |

If a step fails, send the step number and the last 50 lines of the log:

```
tail -n 50 ~/Library/Application\ Support/com.vouchcompute.app/logs/core.log
```

Every connection problem is now logged with its reason ("job server not contacted: …" or "could not connect to the
job server at …"). The log holds no keys or tokens.

## What the result means

- All 9 pass: the version can be tagged and published (the coordinator does this; never from a test build).
- Any step fails: no tag. Fix, make a new test build, and run the whole list again.
