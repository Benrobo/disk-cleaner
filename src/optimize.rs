//! Optimize: a short list of safe maintenance commands. Each is fixed (no user input is
//! ever interpolated) and is confirmed with a dialog before it runs.

use crate::util;

pub struct Task {
    pub title: &'static str,
    pub detail: &'static str,
    pub admin: bool,
    pub shell: &'static str,
}

pub const TASKS: &[Task] = &[
    Task {
        title: "Thin Time Machine local snapshots",
        detail: "Local snapshots hold on to deleted files, so cleaning may not free space until they are thinned. Removes the hourly restore points kept on this Mac since your last backup; backups on your backup disk are not affected.",
        admin: true,
        shell: "/usr/bin/tmutil thinlocalsnapshots / 999999999999 4",
    },
    Task {
        title: "Delete unavailable iOS simulators",
        detail: "Removes simulators whose iOS runtime is no longer installed.",
        admin: false,
        shell: "/usr/bin/xcrun simctl delete unavailable",
    },
    Task {
        title: "Refresh Quick Look thumbnails",
        detail: "Resets the Quick Look thumbnail cache and generators. Fixes stale or blank previews.",
        admin: false,
        shell: "/usr/bin/qlmanage -r cache; /usr/bin/qlmanage -r",
    },
    Task {
        title: "Rebuild Launch Services database",
        detail: "Fixes duplicate or missing entries in “Open With” menus.",
        admin: false,
        shell: "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -r -domain local -domain system -domain user",
    },
    Task {
        title: "Flush DNS cache",
        detail: "Clears cached DNS lookups. Helps when websites fail to resolve after network changes.",
        admin: true,
        shell: "/usr/bin/dscacheutil -flushcache; /usr/bin/killall -HUP mDNSResponder",
    },
    Task {
        title: "Free inactive memory",
        detail: "Flushes disk caches from memory. The Mac may feel slower for a moment.",
        admin: true,
        shell: "/usr/sbin/purge",
    },
    Task {
        title: "Restart Dock",
        detail: "Restarts the Dock (also Launchpad and Mission Control). Fixes a stuck or glitchy Dock.",
        admin: false,
        shell: "/usr/bin/killall Dock",
    },
    Task {
        title: "Rebuild Spotlight index",
        detail: "Erases and rebuilds the Spotlight index for the startup disk. Search is incomplete and the Mac is busier for a while (can be an hour or more). Only do this if search is broken.",
        admin: true,
        shell: "/usr/bin/mdutil -E /",
    },
];

pub fn run(task: &Task) -> Result<(), String> {
    precheck(task)?;
    if task.admin {
        util::run_admin(task.shell)
    } else {
        util::run("/bin/sh", &["-c", task.shell]).map(|_| ())
    }
}

pub fn local_snapshot_count() -> usize {
    util::run("/usr/bin/tmutil", &["listlocalsnapshots", "/"])
        .map(|s| s.lines().filter(|l| l.contains("com.apple.TimeMachine")).count())
        .unwrap_or(0)
}

/// Refuse tasks whose preconditions aren't met (mirrors Mole's checks).
fn precheck(task: &Task) -> Result<(), String> {
    if task.shell.contains("simctl delete unavailable") {
        // If a runtime image just isn't mounted yet, its simulators look "unavailable" and
        // would be deleted with their data. Only run when every runtime is Ready.
        let list = util::run("/usr/bin/xcrun", &["simctl", "runtime", "list"]).map_err(|_| "Xcode's simulator tools aren't available.".to_string())?;
        let not_ready = list.lines().filter(|l| l.contains(" - ") && !l.contains("(Ready)")).count();
        if not_ready > 0 {
            return Err(format!("{not_ready} simulator runtime(s) aren't ready. Open Xcode once, then try again."));
        }
    }
    if task.shell.contains("mDNSResponder") {
        let vpn = util::run("/usr/sbin/scutil", &["--nc", "list"]).unwrap_or_default();
        if vpn.lines().any(|l| l.contains("(Connected)")) {
            return Err("A VPN is connected; flushing DNS now could drop it. Disconnect first.".into());
        }
    }
    Ok(())
}
