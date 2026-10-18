//! Apps: installed applications with size, data size, last-used date, and uninstall
//! (app + its leftovers go to the Trash so everything is recoverable).

use crate::safety;
use crate::util::{self, Progress, h, home, size_of};
use std::sync::atomic::Ordering;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct App {
    pub path: PathBuf,
    pub name: String,
    pub bundle_id: String,
    pub version: String,
    pub size: u64,
    pub data: Vec<(PathBuf, u64)>,
    pub last_used: Option<u64>,
    pub menu_bar: bool,
    /// Why this app can't be uninstalled here, if so.
    pub locked: Option<String>,
}

impl App {
    pub fn data_size(&self) -> u64 {
        self.data.iter().map(|d| d.1).sum()
    }
    pub fn ids(&self) -> Vec<String> {
        let stem = self.path.file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
        vec![self.bundle_id.to_lowercase(), self.name.to_lowercase(), stem]
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct AppsScan {
    pub apps: Vec<App>,
    pub scanned_at: u64,
}

/// Apps that must be removed with their vendor's own uninstaller (security / MDM agents).
const VENDOR_MANAGED: &[&str] = &["*crowdstrike*", "*sentinel*", "*jamf*", "*eset*", "*paloalto*", "*globalprotect*", "*cisco*", "*alibaba.security*", "*kandji*", "*mosyle*", "*addigy*"];
const SYSTEM_APPS: &[&str] = &["com.apple.Safari", "com.apple.finder", "com.apple.systempreferences"];

/// Names too generic to safely match leftover folders by name (bundle-id matching still applies).
const GENERIC_NAMES: &[&str] = &[
    "music", "notes", "helper", "agent", "sync", "cloud", "manager", "utility", "google", "microsoft", "adobe",
    "apple", "jetbrains", "mozilla", "electron", "chrome", "app", "update", "updater", "launcher", "data", "cache",
    "logs", "steam", "epic", "unity", "android", "code helper", "default",
];

fn app_paths() -> Vec<PathBuf> {
    let mut out = vec![];
    for root in [PathBuf::from("/Applications"), h("Applications")] {
        let Ok(rd) = fs::read_dir(&root) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            if !is_dir {
                continue;
            }
            if p.extension().is_some_and(|x| x == "app") {
                out.push(p);
            } else if !p.file_name().is_some_and(|n| n == "Utilities") {
                // One level of folders, e.g. /Applications/Adobe Photoshop 2025/*.app
                if let Ok(rd2) = fs::read_dir(&p) {
                    for e2 in rd2.flatten() {
                        if e2.path().extension().is_some_and(|x| x == "app") && e2.file_type().is_ok_and(|t| t.is_dir()) {
                            out.push(e2.path());
                        }
                    }
                }
            }
        }
    }
    out
}

fn info(path: &Path) -> Option<(String, String, String, bool)> {
    let plist::Value::Dictionary(d) = plist::Value::from_file(path.join("Contents/Info.plist")).ok()? else { return None };
    let s = |k: &str| d.get(k).and_then(|v| v.as_string()).map(String::from);
    let id = s("CFBundleIdentifier")?;
    let stem = path.file_stem()?.to_string_lossy().into_owned();
    let name = s("CFBundleDisplayName").or(s("CFBundleName")).unwrap_or_else(|| stem.clone());
    let version = s("CFBundleShortVersionString").or(s("CFBundleVersion")).unwrap_or_default();
    let menu_bar = d.get("LSUIElement").is_some_and(|v| v.as_boolean() == Some(true) || v.as_string() == Some("1"));
    Some((id, name, version, menu_bar))
}

/// Candidate leftover locations for an app (only exact bundle-id or exact-name matches).
fn leftover_candidates(id: &str, names: &[String]) -> Vec<PathBuf> {
    let mut c = vec![];
    for dir in ["Application Support", "Caches", "Logs", "WebKit", "HTTPStorages", "Containers", "Application Scripts"] {
        c.push(h("Library").join(dir).join(id));
    }
    c.push(h("Library/Preferences").join(format!("{id}.plist")));
    c.push(h("Library/Saved Application State").join(format!("{id}.savedState")));
    c.push(h("Library/HTTPStorages").join(format!("{id}.binarycookies")));
    c.push(h("Library/Cookies").join(format!("{id}.binarycookies")));
    c.push(h("Library/LaunchAgents").join(format!("{id}.plist")));
    if let Ok(rd) = fs::read_dir(h("Library/Preferences/ByHost")) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(&format!("{id}.")) && n.ends_with(".plist") {
                c.push(e.path());
            }
        }
    }
    for name in names {
        for dir in ["Application Support", "Caches", "Logs"] {
            c.push(h("Library").join(dir).join(name));
        }
    }
    c
}

fn valid_bundle_id(id: &str) -> bool {
    id.split('.').count() >= 2 && id.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c)) && !id.contains("..")
}

pub fn scan(prog: &Progress) -> AppsScan {
    let paths = app_paths();
    prog.total.store(paths.len() as u64, Ordering::Relaxed);
    let mut apps: Vec<App> = paths
        .par_iter()
        .filter_map(|p| {
            let (bundle_id, name, version, menu_bar) = info(p)?;
            let size = util::size_with(p, Some(prog));
            prog.done.fetch_add(1, Ordering::Relaxed);
            prog.bytes.fetch_add(size, Ordering::Relaxed);
            prog.add_to_group(&name, size, true);
            let locked = if SYSTEM_APPS.contains(&bundle_id.as_str()) {
                Some("part of macOS".to_string())
            } else if VENDOR_MANAGED.iter().any(|g| safety::glob_match(g, &bundle_id)) {
                Some("use the vendor's own uninstaller".to_string())
            } else if bundle_id.starts_with("com.apple.") && !p.starts_with("/Applications") {
                Some("part of macOS".to_string())
            } else {
                None
            };
            Some(App { path: p.clone(), name, bundle_id, version, size, data: vec![], last_used: None, menu_bar, locked })
        })
        .collect();

    prog.set_current("Finding each app's data in your Library…");
    // Leftovers. A location is only attributed to an app if no other installed app claims it.
    let candidates: Vec<Vec<PathBuf>> = apps
        .iter()
        .map(|a| {
            if !valid_bundle_id(&a.bundle_id) {
                return vec![];
            }
            let stem = a.path.file_stem().unwrap().to_string_lossy().into_owned();
            let mut names = vec![a.name.clone()];
            if stem != a.name {
                names.push(stem);
            }
            names.retain(|n| n.chars().count() >= 3 && !GENERIC_NAMES.contains(&n.to_lowercase().as_str()) && !n.contains('/') && !n.starts_with('.'));
            if a.bundle_id.starts_with("com.apple.") {
                names.clear();
            }
            leftover_candidates(&a.bundle_id, &names)
        })
        .collect();
    // APFS is case-insensitive: "Caches/Foo" and "Caches/foo" are the same folder.
    let key = |p: &PathBuf| p.to_string_lossy().to_lowercase();
    let mut claims: HashMap<String, usize> = HashMap::new();
    for set in &candidates {
        for p in set.iter().map(key).collect::<std::collections::HashSet<_>>() {
            *claims.entry(p).or_default() += 1;
        }
    }
    let data: Vec<Vec<(PathBuf, u64)>> = candidates
        .par_iter()
        .map(|set| {
            let mut seen = std::collections::HashSet::new();
            set.iter()
                .filter(|p| claims[&key(p)] == 1 && seen.insert(key(p)))
                .filter(|p| fs::symlink_metadata(p).is_ok_and(|m| !m.file_type().is_symlink()))
                .map(|p| (p.clone(), size_of(p)))
                .collect()
        })
        .collect();
    for (a, d) in apps.iter_mut().zip(data) {
        a.data = d;
    }

    prog.set_current("Reading app icons…");
    // Icons, converted once and cached as PNG.
    apps.par_iter().for_each(|a| ensure_icon(&a.path, &a.bundle_id));

    // Last-used dates from Spotlight, one mdls call for everything.
    let last = last_used(&apps.iter().map(|a| a.path.clone()).collect::<Vec<_>>());
    for (a, l) in apps.iter_mut().zip(last) {
        // Spotlight can be broken or disabled; then use when the app last wrote its own data.
        a.last_used = l.or_else(|| last_activity(a));
    }
    apps.sort_by(|a, b| b.size.cmp(&a.size));
    AppsScan { apps, scanned_at: util::now() }
}

pub fn icon_dir() -> PathBuf {
    h("Library/Application Support/DiskCleaner/icons")
}

/// Safe file name for an app's cached icon.
pub fn icon_file(bundle_id: &str) -> Option<PathBuf> {
    valid_bundle_id(bundle_id).then(|| icon_dir().join(format!("{bundle_id}.png")))
}

fn ensure_icon(app: &Path, bundle_id: &str) {
    let Some(out) = icon_file(bundle_id) else { return };
    let fresh = |o: &Path| -> bool {
        let (Ok(a), Ok(b)) = (fs::metadata(o).and_then(|m| m.modified()), fs::metadata(app).and_then(|m| m.modified())) else { return false };
        a >= b
    };
    if fresh(&out) {
        return;
    }
    let Ok(plist::Value::Dictionary(d)) = plist::Value::from_file(app.join("Contents/Info.plist")) else { return };
    let Some(name) = d.get("CFBundleIconFile").and_then(|v| v.as_string()) else { return };
    let mut icns = app.join("Contents/Resources").join(name);
    if icns.extension().is_none() {
        icns.set_extension("icns");
    }
    if !icns.is_file() {
        return;
    }
    let _ = fs::create_dir_all(icon_dir());
    let _ = std::process::Command::new("/usr/bin/sips")
        .args(["-s", "format", "png", "-Z", "96"])
        .arg(&icns)
        .arg("--out")
        .arg(&out)
        .output();
}

fn last_activity(app: &App) -> Option<u64> {
    let mut paths: Vec<PathBuf> = app.data.iter().map(|d| d.0.clone()).collect();
    paths.push(h("Library/Saved Application State").join(format!("{}.savedState", app.bundle_id)));
    paths
        .iter()
        .filter_map(|p| fs::symlink_metadata(p).and_then(|m| m.modified()).ok())
        .filter_map(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .max()
}

fn last_used(paths: &[PathBuf]) -> Vec<Option<u64>> {
    let mut cmd = std::process::Command::new("/usr/bin/mdls");
    cmd.args(["-name", "kMDItemLastUsedDate", "-raw"]).args(paths);
    let Ok(out) = cmd.output() else { return vec![None; paths.len()] };
    let text = String::from_utf8_lossy(&out.stdout);
    let vals: Vec<Option<u64>> = text.split('\0').map(parse_date).collect();
    if vals.len() >= paths.len() { vals[..paths.len()].to_vec() } else { vec![None; paths.len()] }
}

/// "2025-09-30 14:03:11 +0000" -> unix seconds.
fn parse_date(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = s.split_once(' ')?;
    let time = rest.split(' ').next()?;
    let d: Vec<i64> = date.split('-').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let t: Vec<i64> = time.split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let (y, m, day) = (d[0], d[1], d[2]);
    // days_from_civil (Howard Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + t[0] * 3600 + t[1] * 60 + t[2]) as u64)
}

pub struct UninstallResult {
    pub trashed: u64,
    pub failed: Vec<String>,
}

/// Move the app and its leftovers to the Trash. The caller must already have checked it isn't running.
pub fn uninstall(app: &App) -> UninstallResult {
    let mut res = UninstallResult { trashed: 0, failed: vec![] };
    if let Some(why) = &app.locked {
        res.failed.push(format!("{}: {why}", app.name));
        return res;
    }
    if let Err(e) = safety::check_app_bundle(&app.path) {
        res.failed.push(e);
        return res;
    }
    // The app at this path must still be the same app that was scanned.
    if info(&app.path).map(|i| i.0) != Some(app.bundle_id.clone()) {
        res.failed.push(format!("{} changed since the scan; rescan and try again", app.name));
        return res;
    }
    match util::move_to_trash(&app.path) {
        Ok(()) => res.trashed += app.size,
        Err(_) => {
            // Root-owned app (installed by a .pkg): move it to the Trash with an admin prompt.
            let dest = trash_dest(&app.path);
            let cmd = format!("/bin/mv -n {} {}", shell_quote(&app.path), shell_quote(&dest));
            match util::run_admin(&cmd) {
                Ok(()) if !app.path.exists() => res.trashed += app.size,
                Ok(()) => res.failed.push(format!("{} could not be moved", app.path.display())),
                Err(e) => res.failed.push(format!("{}: {e}", app.name)),
            }
        }
    }
    if app.path.exists() {
        return res; // Don't touch data if the app itself is still there.
    }
    let uid = unsafe { libc::getuid() };
    for (p, size) in &app.data {
        if p.starts_with(h("Library/LaunchAgents")) {
            let _ = util::run("/bin/launchctl", &["bootout", &format!("gui/{uid}"), &p.to_string_lossy()]);
        }
        match safety::check_leftover(p).and_then(|_| util::move_to_trash(p)) {
            Ok(()) => res.trashed += size,
            Err(e) => res.failed.push(format!("{}: {e}", util::tilde(p))),
        }
    }
    res
}

fn trash_dest(p: &Path) -> PathBuf {
    let name = p.file_name().unwrap().to_string_lossy().into_owned();
    let mut dest = home().join(".Trash").join(&name);
    if dest.exists() {
        dest = home().join(".Trash").join(format!("{} {}", util::now(), name));
    }
    dest
}

fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"))
}

#[derive(Clone)]
pub struct StartupItem {
    pub path: PathBuf,
    pub label: String,
    pub user: bool,
}

pub fn startup_items() -> Vec<StartupItem> {
    let mut out = vec![];
    for (dir, user) in [(h("Library/LaunchAgents"), true), (PathBuf::from("/Library/LaunchAgents"), false), (PathBuf::from("/Library/LaunchDaemons"), false)] {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "plist") {
                let label = p.file_stem().unwrap().to_string_lossy().into_owned();
                let kind = if user { "" } else if dir.ends_with("LaunchDaemons") { " (system daemon)" } else { " (all users)" };
                out.push(StartupItem { path: p, label: format!("{label}{kind}"), user });
            }
        }
    }
    out.sort_by(|a, b| a.label.to_lowercase().cmp(&b.label.to_lowercase()));
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_mdls_dates() {
        assert_eq!(super::parse_date("1970-01-02 00:00:00 +0000"), Some(86400));
        assert_eq!(super::parse_date("2024-02-29 12:00:00 +0000"), Some(1709208000));
        assert_eq!(super::parse_date("(null)"), None);
    }
}
