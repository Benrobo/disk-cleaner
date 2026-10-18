//! The safety layer. Every delete or trash operation goes through one of the `check_*`
//! functions right before it happens, independently of how the path was discovered.
//! If anything looks off the operation is refused.

use crate::util::home;
use rayon::prelude::*;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// Path components that must never be inside anything we delete (case-insensitive, exact).
const PROTECTED_COMPONENTS: &[&str] = &[
    "keychains", "mobile documents", "cloudstorage", "mail", "messages", "accounts", "calendars",
    "contacts", "cookies", "local storage", "session storage", "indexeddb", "databases",
    "login data", "history", "bookmarks", "web data", "mobilesync", "photos library.photoslibrary",
    "com.apple.tcc", "com.apple.bird", "cloudkit", "familycircle", "virtualenvs", ".ssh", ".gnupg",
    "service worker", "storage", "extensions", "local extension settings", "sync data",
];

/// Cache folder names (leaf of `~/Library/Caches/<name>`) that are never touched.
/// Matched as case-insensitive globs with `*`.
const PROTECTED_CACHE_NAMES: &[&str] = &[
    // macOS internals: only an explicit allow-list of Apple caches is ever cleaned (see clean.rs).
    "com.apple.*", "cloudkit*", "familycircle", "gippseudonymousid", "cctclearcutlogger", "geoservices",
    "com.crashlytics*", "deno", "displaylink*", "silverfast*", "cotypist*",
    // Password managers / auth.
    "*1password*", "*agilebits*", "*bitwarden*", "*lastpass*", "*dashlane*", "*keepass*", "*authy*", "*yubico*",
    // Input methods & keyboards.
    "*inputmethod*", "*keyboard*", "*karabiner*", "*rime*", "*sogou*",
    // VPN / proxy / network.
    "*tailscale*", "*wireguard*", "*nordvpn*", "*expressvpn*", "*protonvpn*", "*mullvad*", "*surfshark*",
    "*windscribe*", "*openvpn*", "*1dot1dot1dot1*", "*cloudflare*warp*", "*clash*", "*surge*", "*shadowsocks*",
    "*v2ray*", "*zerotier*", "*sing-box*", "*hiddify*",
    // Cloud sync engines (cache holds sync state).
    "*dropbox*", "*onedrive*", "*drivefs*", "com.google.drive*", "*backblaze*", "*synology*", "com.box.*",
    // Big vendors whose caches hold licensing/sync state.
    "com.microsoft.*", "adobe*", "com.adobe.*",
    // Containers / VMs.
    "*orbstack*", "dev.kdrag0n.*", "*docker*", "*parallels*", "*vmware*", "*utm*",
    // Security / MDM agents.
    "*crowdstrike*", "*sentinel*", "*jamf*", "*eset*", "*paloalto*", "*cisco*",
    // Codex keeps runtimes and session state next to its caches (Mole protects it too).
    "*codex*",
    // Apps that keep real data (clipboard history, sessions, update state) in their cache
    // folder. Mirrors Mole's DATA_PROTECTED_BUNDLES; safe parts are cleaned by explicit rules.
    "com.raycast.*", "com.todesktop.*", "com.hnc.discord*", "net.whatsapp.*", "org.videolan.vlc", "dev.warp.*",
    "org.mozilla.*", "mozilla", "com.spotify.client", "com.tinyspeck.slackmacgap", "us.zoom.*", "org.telegram.*",
    "ru.keepcoder.*", "com.tencent.*", "md.obsidian", "notion.id", "com.runningwithcrayons.*", "com.jetbrains.*",
    "com.github.githubdesktop", "com.postmanlabs.*", "com.mongodb.compass", "com.googlecode.iterm2", "com.setapp.*",
    "com.paddle.*", "org.sparkle-project.*", "homebrew.mxcl.*", "com.teamviewer.*", "com.anydesk.*", "com.cleanshot.*",
    "*loon*", "*quantumult*", "*amnezia*", "mihomo*", "*nekoray*", "ms-playwright*",
    // Folders holding Apple's compiled ML models (in-use processes break if removed).
    "icloudmailagent", "animoji", "amsdatamigratortool",
    // Ourselves.
    "*diskcleaner*",
];

/// Roots (relative to home) under which Clean is allowed to delete.
const CLEAN_ROOTS: &[&str] = &[
    "Library/Caches",
    "Library/Logs",
    "Library/Application Support",
    "Library/Developer/Xcode/DerivedData",
    "Library/Developer/Xcode/iOS DeviceSupport",
    "Library/Developer/Xcode/watchOS DeviceSupport",
    "Library/Developer/Xcode/tvOS DeviceSupport",
    "Library/Developer/Xcode/visionOS DeviceSupport",
    "Library/Developer/Xcode/macOS DeviceSupport",
    "Library/Developer/Xcode/Archives",
    "Library/Developer/Xcode/UserData/Previews",
    "Library/Developer/CoreSimulator/Caches",
    "Library/iTunes/iPhone Software Updates",
    "Library/pnpm/store",
    ".npm/_cacache",
    ".npm/_npx",
    ".npm/_logs",
    ".yarn/berry/cache",
    ".bun/install/cache",
    ".gradle/caches",
    ".gradle/daemon",
    ".m2/repository",
    ".cargo/registry/cache",
    ".cargo/registry/src",
    ".cargo/git/checkouts",
    ".rustup/downloads",
    ".android/cache",
    ".android/build-cache",
    ".cache",
    ".Trash",
    "Downloads",
];

/// Leaf names allowed for deletion inside `~/Library/Application Support` (Chromium/Electron caches).
pub const APP_SUPPORT_CACHE_NAMES: &[&str] = &[
    "Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GrShaderCache",
    "GraphiteDawnCache", "ShaderCache", "component_crx_cache", "CachedData", "CachedExtensionVSIXs",
    "logs", "sentry", "CrashReporter",
];

/// Top-level home folders that may never be trashed as a whole.
const HOME_ESSENTIALS: &[&str] = &[
    "Applications", "Desktop", "Documents", "Downloads", "Library", "Movies", "Music", "Pictures", "Public",
    ".Trash", ".ssh", ".gnupg", ".config", ".local", ".zshrc", ".bashrc", ".zprofile", ".bash_profile",
    ".profile", ".gitconfig", ".cargo", ".rustup", ".claude", ".codex", ".orbstack", ".docker", ".kube",
    ".aws", ".zsh_history", ".bash_history", ".netrc", ".npmrc", ".gemini",
];

/// Inside ~/Library/Application Support: system and account databases.
const APP_SUPPORT_ESSENTIALS: &[&str] = &[
    "AddressBook", "CallHistoryDB", "CallHistoryTransactions", "Knowledge", "FileProvider", "CloudDocs", "iCloud",
    "MobileSync", "Dock", "com.apple.TCC", "com.apple.sharedfilelist", "Steam", "Epic",
];

/// Bundle-like folders that must be removed whole or not at all.
const PACKAGE_EXTS: &[&str] = &[
    "photoslibrary", "musiclibrary", "fcpbundle", "logicx", "imovielibrary", "pvm", "utm", "vmwarevm",
    "sparsebundle", "app", "tvlibrary", "aplibrary", "migratedphotolibrary",
];

/// Names never removed from *inside* a cache or log folder that is being emptied:
/// cookies, offline web storage, IDE edit history and Apple's compiled model caches.
const KEEP_INSIDE: &[&str] = &[
    ".cookies", "cookies*", "*.binarycookies", "cachestorage", "*.keychain*", "localhistory",
    "com.apple.e5rt.e5bundlecache", "*.sqlite-wal", "*.sqlite-shm",
];

pub fn keep_inside(name: &str) -> bool {
    let lower = name.to_lowercase();
    PROTECTED_COMPONENTS.contains(&lower.as_str()) || KEEP_INSIDE.iter().any(|p| glob_match(p, &lower))
}

/// Inside ~/Library these may never be trashed from Analyze.
const LIBRARY_ESSENTIALS: &[&str] = &[
    "Keychains", "Preferences", "Containers", "Group Containers", "Mobile Documents", "CloudStorage", "Mail",
    "Messages", "Accounts", "Calendars", "Photos", "Safari", "Cookies", "LaunchAgents", "Application Scripts",
    "Daemon Containers", "Biome", "IdentityServices", "Sharing", "Shortcuts", "Passes", "Frameworks",
    "Fonts", "Keyboard Layouts", "Input Methods", "Autosave Information", "Metadata", "Trial",
];

pub fn glob_match(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.to_lowercase(), name.to_lowercase());
    let parts: Vec<&str> = p.split('*').collect();
    if parts.len() == 1 {
        return p == n;
    }
    let mut rest = n.as_str();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(idx) => rest = &rest[idx + part.len()..],
                None => return false,
            }
        }
    }
    true
}

pub fn is_protected_cache_name(name: &str) -> bool {
    PROTECTED_CACHE_NAMES.iter().any(|p| glob_match(p, name))
}

/// Basic hygiene: absolute, no `.`/`..`, no control chars, no symlinks anywhere in the chain,
/// inside the home folder and at least `min_depth` components below it.
fn check_basic(path: &Path, min_depth: usize) -> Result<(), String> {
    check_basic_with(path, min_depth, true)
}

fn check_basic_with(path: &Path, min_depth: usize, protected_components: bool) -> Result<(), String> {
    let s = path.to_string_lossy();
    if !path.is_absolute() || s.chars().any(|c| c.is_control()) {
        return Err(format!("unsafe path {s}"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
        return Err(format!("relative components in {s}"));
    }
    let rel = path.strip_prefix(home()).map_err(|_| format!("outside home: {s}"))?;
    if rel.components().count() < min_depth {
        return Err(format!("too close to home: {s}"));
    }
    let md = fs::symlink_metadata(path).map_err(|e| format!("{s}: {e}"))?;
    if md.file_type().is_symlink() {
        return Err(format!("symlink: {s}"));
    }
    // Resolving the path must give the same path: no symlinked parent can redirect us.
    match fs::canonicalize(path) {
        Ok(c) if c == path => {}
        _ => return Err(format!("path resolves elsewhere: {s}")),
    }
    for comp in rel.components().filter(|_| protected_components) {
        let c = comp.as_os_str().to_string_lossy().to_lowercase();
        if PROTECTED_COMPONENTS.contains(&c.as_str()) {
            return Err(format!("protected location: {s}"));
        }
    }
    Ok(())
}

/// May Clean delete this item (or its contents)?
pub fn check_cleanable(path: &Path) -> Result<(), String> {
    check_basic(path, 2)?;
    let rel = path.strip_prefix(home()).unwrap();
    let root = CLEAN_ROOTS
        .iter()
        .find(|r| rel.starts_with(r))
        .ok_or_else(|| format!("not a cleanable location: {}", path.display()))?;
    if *root == "Library/Caches" {
        let name = rel.components().nth(2).map(|c| c.as_os_str().to_string_lossy().into_owned());
        let allowed_apple = crate::clean::APPLE_CACHES
            .iter()
            .chain(&["com.microsoft.edgemac"])
            .any(|a| rel.starts_with(Path::new("Library/Caches").join(a)));
        match name {
            Some(n) if is_protected_cache_name(&n) && !allowed_apple => return Err(format!("protected cache: {n}")),
            None => return Err("refusing to clean ~/Library/Caches itself".into()),
            _ => {}
        }
    }
    if *root == "Library/Application Support" {
        let leaf = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        if !APP_SUPPORT_CACHE_NAMES.contains(&leaf.as_str()) {
            return Err(format!("not a cache folder: {}", path.display()));
        }
        // Library/Application Support/<app>/<leaf>, or a Chromium profile a few levels down.
        let depth = rel.components().count();
        if !((4..=7).contains(&depth) || (depth == 3 && leaf == "CrashReporter")) {
            return Err(format!("unexpected cache location: {}", path.display()));
        }
        if rel.to_string_lossy().contains("/Codex/") {
            return Err("Codex data is protected".into());
        }
    }
    if *root == "Downloads" && path.is_dir() {
        return Err("only installer files are removed from Downloads".into());
    }
    if *root == ".cache" && rel.components().count() < 2 {
        return Err("refusing to clean ~/.cache itself".into());
    }
    Ok(())
}

/// May Analyze / Apps move this to the Trash? (Recoverable, so the rules are looser.)
pub fn check_trashable(path: &Path) -> Result<(), String> {
    check_basic(path, 1)?;
    let rel = path.strip_prefix(home()).unwrap();
    let comps: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    if comps.len() == 1 && HOME_ESSENTIALS.iter().any(|e| e.eq_ignore_ascii_case(&comps[0])) {
        return Err(format!("~/{} is an essential folder", comps[0]));
    }
    if let Some(pkg) = comps.iter().find(|c| {
        Path::new(c.as_str()).extension().is_some_and(|e| PACKAGE_EXTS.contains(&e.to_string_lossy().to_lowercase().as_str()))
    }) {
        // Removing the whole package is fine; reaching inside one corrupts it.
        if comps.last() != Some(pkg) {
            return Err(format!("inside {pkg}; remove the whole library instead"));
        }
    }
    if comps[0] == "Library" {
        if comps.len() >= 3 && comps[1] == "Application Support" && APP_SUPPORT_ESSENTIALS.iter().any(|e| e.eq_ignore_ascii_case(&comps[2])) {
            return Err(format!("~/Library/Application Support/{} holds system data", comps[2]));
        }
        if comps.len() == 2 {
            return Err("top-level Library folders are managed by macOS".into());
        }
        if LIBRARY_ESSENTIALS.iter().any(|e| e.eq_ignore_ascii_case(&comps[1])) {
            return Err(format!("~/Library/{} holds system or account data", comps[1]));
        }
        if comps.len() == 3 && comps[1] == "Application Support" && comps[2].starts_with("com.apple.") {
            return Err("Apple system data".into());
        }
    }
    Ok(())
}

/// Leftovers of an app being uninstalled: only entries sitting directly inside these
/// Library folders (they are matched by exact bundle id or exact app name).
const LEFTOVER_PARENTS: &[&str] = &[
    "Library/Application Support", "Library/Caches", "Library/Logs", "Library/WebKit", "Library/HTTPStorages",
    "Library/Containers", "Library/Application Scripts", "Library/Preferences", "Library/Preferences/ByHost",
    "Library/Saved Application State", "Library/Cookies", "Library/LaunchAgents",
];

pub fn check_leftover(path: &Path) -> Result<(), String> {
    check_basic_with(path, 3, false)?;
    let rel = path.strip_prefix(home()).unwrap();
    let parent = rel.parent().unwrap_or(Path::new(""));
    if !LEFTOVER_PARENTS.iter().any(|p| parent == Path::new(p)) {
        return Err(format!("not an app data location: {}", path.display()));
    }
    let leaf = rel.file_name().unwrap().to_string_lossy().to_lowercase();
    if ["com.apple.tcc", "com.apple.bird", "cloudkit", "familycircle"].iter().any(|p| leaf.starts_with(p)) {
        return Err(format!("protected: {}", path.display()));
    }
    Ok(())
}

/// A user launch agent that may be turned off: a .plist directly in ~/Library/LaunchAgents.
pub fn check_user_launch_agent(path: &Path) -> Result<(), String> {
    check_basic_with(path, 3, false)?;
    let rel = path.strip_prefix(home()).unwrap();
    let name = rel.file_name().unwrap().to_string_lossy().to_lowercase();
    if rel.parent() != Some(Path::new("Library/LaunchAgents")) || !name.ends_with(".plist") || name.starts_with("com.apple.") {
        return Err(format!("not a user launch agent: {}", path.display()));
    }
    Ok(())
}

/// Apps live outside home; allow only real .app bundles in /Applications or ~/Applications.
pub fn check_app_bundle(path: &Path) -> Result<(), String> {
    let s = path.to_string_lossy();
    let ok_root = path.parent() == Some(Path::new("/Applications")) || path.parent() == Some(&home().join("Applications"));
    if !ok_root || path.extension().is_none_or(|e| e != "app") {
        return Err(format!("not an app bundle in Applications: {s}"));
    }
    let md = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(format!("not a real app bundle: {s}"));
    }
    Ok(())
}

/// Context for one cleaning run.
#[derive(Default)]
pub struct Ctx {
    /// Files currently open by any process (from `lsof`). These are never deleted.
    pub open: HashSet<PathBuf>,
}

impl Ctx {
    pub fn new() -> Ctx {
        Ctx { open: crate::util::open_files() }
    }

    /// Open, or part of an open SQLite database family (db + -wal/-shm/-journal).
    fn in_use(&self, path: &Path) -> bool {
        if self.open.is_empty() {
            return false;
        }
        let s = path.to_string_lossy();
        let base = ["-wal", "-shm", "-journal"].iter().find_map(|x| s.strip_suffix(x)).unwrap_or(&s).to_string();
        [base.clone(), format!("{base}-wal"), format!("{base}-shm"), format!("{base}-journal")]
            .iter()
            .any(|p| self.open.contains(Path::new(p)))
            || self.open.contains(path)
    }
}

/// Delete everything inside `dir`, keeping `dir` itself. Returns bytes freed.
///
/// The walk is done with directory file descriptors (openat/unlinkat with O_NOFOLLOW), so a
/// folder swapped for a symlink mid-way can never redirect it. It stays on one volume, keeps
/// going past anything it can't remove, and skips open files and the `KEEP_INSIDE` names.
pub fn remove_contents(dir: &Path, ctx: &Ctx) -> u64 {
    let Some(fd) = open_dir(libc::AT_FDCWD, &cstr(dir.as_os_str())) else { return 0 };
    let dev = fstat_dev(fd);
    let freed = remove_children(fd, dir, dev, ctx);
    unsafe { libc::close(fd) };
    freed
}

/// Delete a single file or folder (not following symlinks). Returns bytes freed.
pub fn remove_tree(path: &Path, ctx: &Ctx) -> u64 {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else { return 0 };
    let Some(pfd) = open_dir(libc::AT_FDCWD, &cstr(parent.as_os_str())) else { return 0 };
    let dev = fstat_dev(pfd);
    let freed = remove_entry(pfd, &cstr(name), path, dev, ctx);
    unsafe { libc::close(pfd) };
    freed
}

fn cstr(s: &std::ffi::OsStr) -> CString {
    CString::new(s.as_bytes()).unwrap_or_default()
}

fn open_dir(at: libc::c_int, name: &CStr) -> Option<libc::c_int> {
    let fd = unsafe { libc::openat(at, name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    (fd >= 0).then_some(fd)
}

fn fstat_dev(fd: libc::c_int) -> libc::dev_t {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstat(fd, &mut st) };
    st.st_dev
}

fn list(fd: libc::c_int) -> Vec<CString> {
    let mut out = vec![];
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return out;
    }
    let dir = unsafe { libc::fdopendir(dup) };
    if dir.is_null() {
        unsafe { libc::close(dup) };
        return out;
    }
    loop {
        let ent = unsafe { libc::readdir(dir) };
        if ent.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            out.push(name.to_owned());
        }
    }
    unsafe { libc::closedir(dir) };
    out
}

fn remove_children(fd: libc::c_int, dir: &Path, dev: libc::dev_t, ctx: &Ctx) -> u64 {
    let names = list(fd);
    let one = |n: &CString| remove_entry(fd, n, &dir.join(std::ffi::OsStr::from_bytes(n.to_bytes())), dev, ctx);
    if names.len() > 16 { names.par_iter().map(one).sum() } else { names.iter().map(one).sum() }
}

fn remove_entry(parent: libc::c_int, name: &CStr, path: &Path, dev: libc::dev_t, ctx: &Ctx) -> u64 {
    if keep_inside(&name.to_string_lossy()) || ctx.in_use(path) {
        return 0;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(parent, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 || st.st_dev != dev {
        return 0;
    }
    let is_dir = st.st_mode & libc::S_IFMT == libc::S_IFDIR;
    let own = if is_dir || st.st_nlink <= 1 { st.st_blocks as u64 * 512 } else { 0 };
    if is_dir {
        let Some(fd) = open_dir(parent, name) else { return 0 };
        let freed = remove_children(fd, path, dev, ctx);
        unsafe { libc::close(fd) };
        freed + if unsafe { libc::unlinkat(parent, name.as_ptr(), libc::AT_REMOVEDIR) } == 0 { own } else { 0 }
    } else if unsafe { libc::unlinkat(parent, name.as_ptr(), 0) } == 0 {
        own
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob_match("com.apple.*", "com.apple.Safari"));
        assert!(glob_match("*1password*", "com.1password.1password"));
        assert!(glob_match("adobe*", "Adobe Photoshop"));
        assert!(!glob_match("adobe*", "com.foo.adobe"));
        assert!(glob_match("deno", "Deno"));
        assert!(!glob_match("deno", "denox"));
        assert!(glob_match("*cloudflare*warp*", "com.cloudflare.1dot1dot1dot1.warp"));
    }

    #[test]
    fn clean_guard_rejects_dangerous_paths() {
        let h = home();
        for bad in [
            h.to_path_buf(),
            h.join("Library"),
            h.join("Library/Caches"),
            h.join("Documents/foo"),
            h.join("Library/Keychains/login.keychain-db"),
            h.join("Library/Caches/../Preferences"),
            h.join("Library/Application Support/Google/Chrome/Default/Cookies"),
            h.join("Library/Application Support/Google/Chrome/Default/Local Storage"),
            "/System/Library/Caches".into(),
            "/Library/Caches".into(),
        ] {
            assert!(check_cleanable(&bad).is_err(), "should refuse {bad:?}");
        }
    }

    #[test]
    fn trash_guard_rejects_essentials() {
        let h = home();
        for bad in [h.join("Documents"), h.join("Library/Preferences"), h.join("Library/Keychains/x"), h.join("Library/Caches"), h.join(".ssh")] {
            assert!(check_trashable(&bad).is_err(), "should refuse {bad:?}");
        }
    }

    #[test]
    fn keeps_cookies_and_history_inside_caches() {
        for name in [".cookies", "Cookies", "x.binarycookies", "CacheStorage", "LocalHistory", "com.apple.e5rt.e5bundlecache", "IndexedDB"] {
            assert!(keep_inside(name), "{name} must be kept");
        }
        assert!(!keep_inside("Cache.db"));
        assert!(!keep_inside("fsCachedData"));
        assert!(is_protected_cache_name("com.raycast.macos"));
        assert!(is_protected_cache_name("ms-playwright"));
    }

    #[test]
    fn trash_guard_rejects_inside_packages_and_system_data() {
        let h = home();
        for bad in [h.join("Pictures/Old.photoslibrary/originals"), h.join("Library/Application Support/AddressBook"), h.join(".orbstack")] {
            if bad.exists() {
                assert!(check_trashable(&bad).is_err(), "should refuse {bad:?}");
            }
        }
        assert!(check_user_launch_agent(&h.join("Library/Preferences/com.foo.plist")).is_err());
    }

    #[test]
    fn remove_skips_protected_and_open_files() {
        let base = std::env::temp_dir().join(format!("dc-test2-{}", std::process::id()));
        fs::create_dir_all(base.join("sub")).unwrap();
        fs::write(base.join(".cookies"), b"session").unwrap();
        fs::write(base.join("sub/open.db"), b"db").unwrap();
        fs::write(base.join("sub/junk.bin"), vec![0u8; 5000]).unwrap();
        let mut ctx = Ctx::default();
        ctx.open.insert(base.join("sub/open.db"));
        remove_contents(&base, &ctx);
        assert!(base.join(".cookies").exists());
        assert!(base.join("sub/open.db").exists());
        assert!(!base.join("sub/junk.bin").exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn remove_tree_does_not_follow_symlinks() {
        let base = std::env::temp_dir().join(format!("dc-test-{}", std::process::id()));
        let victim = base.join("victim");
        let target = base.join("target");
        fs::create_dir_all(&victim).unwrap();
        fs::create_dir_all(target.join("sub")).unwrap();
        fs::write(victim.join("keep.txt"), b"precious").unwrap();
        fs::write(target.join("sub/a.bin"), vec![0u8; 10_000]).unwrap();
        std::os::unix::fs::symlink(&victim, target.join("link")).unwrap();
        remove_contents(&target, &Ctx::default());
        assert!(target.exists(), "container is kept");
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0, "contents removed");
        assert!(victim.join("keep.txt").exists(), "symlink target untouched");
        fs::remove_dir_all(&base).unwrap();
    }
}
