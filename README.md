# Disk Cleaner

A free, fast macOS menu bar app for finding and safely removing junk: caches, logs, developer
build files, old installers, unused apps and their leftovers. Written in Rust. Inspired by
[Mole](https://github.com/tw93/Mole), whose safety rules it follows.

It lives only in the menu bar. Click the disk icon to open the panel, drag it by its header to
keep it open, press Esc or click elsewhere to close it.

| Tab | What it does |
| --- | --- |
| **Clean** | Finds regenerable files by category (app caches, system caches, logs, developer tools, AI tools, browsers, installers, Trash). Pick categories or single items, review, clean. |
| **Apps** | Every installed app with its size, the data it keeps in `~/Library`, and when it was last opened. Uninstall moves the app and its data to the Trash. Also lists launch agents. |
| **Analyze** | Maps your home folder so you can drill into the biggest folders and files and move them to the Trash. |
| **Optimize** | A few safe maintenance commands (thin Time Machine snapshots, flush DNS, rebuild Spotlight, …). Each one shows its exact command and runs only after you confirm. |
| **Status** | CPU, memory, disk, network, battery and the apps using the most memory. |

## Safety

Deleting the wrong thing is worse than not deleting anything, so:

- **Allow-list, not block-list.** Clean only touches known cache, log and build locations. Every
  path is checked again right before deletion: it must be inside your home folder, under an
  allowed root, contain no symlinks and match no protected name.
- **Protected data is never touched**: keychains, iCloud, Mail, Messages, Photos, browser cookies,
  history, passwords and local storage. Apps that keep real data in their cache folder are
  skipped, following Mole's protection list. Examples: Raycast clipboard history, Cursor,
  Discord, WhatsApp, Slack, Spotify and JetBrains. Password manager, VPN, input method, cloud
  sync, Docker/OrbStack, security/MDM, Microsoft/Adobe and Codex caches are skipped too. Apple
  caches are skipped except for a short list that macOS rebuilds itself.
- **Nothing in use is deleted.** Caches of running apps are skipped. That includes updaters,
  helpers and background services detected by the folders they run from, not only by name. Right
  before cleaning, every open file is checked (`lsof`), and open files and live SQLite databases
  are left alone.
- **Some things are kept even inside a cache being emptied**: cookie stores, offline web
  storage (`CacheStorage`), IDE Local History and Apple's compiled model caches.
- **Things you might want back go to the Trash**: uninstalled apps, their data, startup items,
  and anything removed from Analyze. Only regenerable caches and logs are deleted permanently,
  plus the Trash and installers if you choose them (both off by default).
- **The UI never sends paths to delete.** It sends item numbers from the current scan, and
  the scan is checked to be the same one.
- Deletion walks folders by file descriptor (`openat`/`unlinkat` with `O_NOFOLLOW`). So it
  never follows a symlink, even one swapped in mid-way, and it never crosses onto other disks.
- Uninstall re-checks that the app on disk is the same one that was scanned, and refuses to act
  on a stale app list. Startup items can only be turned off from `~/Library/LaunchAgents`.
  Analyze can only trash items it actually found, never the inside of a Photos library, VM or
  app bundle, and never system or account data.
- Optimize tasks check their preconditions. Simulators are only deleted when every runtime is
  ready, and DNS isn't flushed while a VPN is connected.

## Caching

Scan results are saved to `~/Library/Application Support/DiskCleaner/state.json`. Opening the
panel shows the last results instantly while a fresh scan runs in the background, with live
progress. The full home-folder map in Analyze runs only when you ask, and is updated in place
when you remove something. Your manual selections are remembered across scans.

## Install

Requires Rust (`rustup`) and Xcode command line tools.

```sh
./build.sh            # builds "build/Disk Cleaner.app"
./build.sh install    # also copies it to /Applications and launches it
```

To start it at login, add it in System Settings → General → Login Items.

**Full Disk Access (recommended):** System Settings → Privacy & Security → Full Disk Access →
add *Disk Cleaner*. Without it macOS won't let any app measure the Trash or some protected
folders, and you may see a permission prompt for Desktop, Documents and Downloads. The app
only reads sizes and dates; it never reads file contents or sends anything anywhere.

## Command line

```sh
target/release/disk-cleaner --report          # dry run: what Clean would find (deletes nothing)
target/release/disk-cleaner --analyze-report  # dry run: biggest folders and files in your home
```

## Notes

- If cleaning frees less than expected, Time Machine local snapshots may still hold the space.
  Use Optimize → Thin Time Machine local snapshots.
- "Last opened" comes from Spotlight. If the Spotlight index is broken, the app estimates it
  from when the app last wrote its own data.
