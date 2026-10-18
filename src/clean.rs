//! Clean: finds regenerable junk (caches, logs, build artifacts...) grouped in categories.
//! Discovery here is rule based; deletion re-validates every path through `safety`.

use crate::safety;
use crate::util::{self, Progress, h, home};
use std::sync::atomic::{AtomicUsize, Ordering};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use crate::status::Running;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Category {
    AppCaches,
    SystemCaches,
    Logs,
    DevTools,
    AiTools,
    Browsers,
    Installers,
    Trash,
}

impl Category {
    pub const ALL: [Category; 8] = [
        Category::AppCaches,
        Category::SystemCaches,
        Category::Logs,
        Category::DevTools,
        Category::AiTools,
        Category::Browsers,
        Category::Installers,
        Category::Trash,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Category::AppCaches => "App Caches",
            Category::SystemCaches => "System Caches",
            Category::Logs => "Logs",
            Category::DevTools => "Developer Tools",
            Category::AiTools => "AI Tools",
            Category::Browsers => "Browsers",
            Category::Installers => "Installers & Updates",
            Category::Trash => "Trash",
        }
    }

    pub fn blurb(self) -> &'static str {
        match self {
            Category::AppCaches => "App temporary files. Regenerated next launch.",
            Category::SystemCaches => "macOS-managed caches. Rebuilt automatically.",
            Category::Logs => "Diagnostic logs and crash reports.",
            Category::DevTools => "Xcode / package manager caches. First build will be slower.",
            Category::AiTools => "AI app caches. Conversations, projects and models are kept.",
            Category::Browsers => "Browser caches. Cookies, history and sessions stay.",
            Category::Installers => "Disk images & installers in Downloads. Deleted permanently.",
            Category::Trash => "Empties your Trash permanently.",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Delete everything inside the folder, keep the folder itself.
    Contents,
    /// Delete the file itself.
    File,
    /// Empty ~/.Trash.
    EmptyTrash,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Item {
    pub path: PathBuf,
    pub label: String,
    pub category: Category,
    pub size: u64,
    pub recommended: bool,
    /// Identifiers (bundle ids / app names, lowercase) of the app owning this cache.
    pub owners: Vec<String>,
    pub note: Option<String>,
    pub mode: Mode,
    /// Newest modification time of anything inside (unix seconds).
    #[serde(default)]
    pub mtime: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CleanScan {
    pub items: Vec<Item>,
    pub scanned_at: u64,
}

/// Apple caches in ~/Library/Caches that are known to be safe to clear.
pub const APPLE_CACHES: &[&str] = &[
    "com.apple.QuickLook.thumbnailcache",
    "com.apple.iconservices.store",
    "com.apple.helpd",
    "com.apple.AppleMediaServices",
    "com.apple.duetexpertd",
    "com.apple.parsecd",
    "com.apple.python",
    "com.apple.WebKit.Networking",
    "com.apple.rosetta.update",
    "com.apple.dt.Xcode",
    "com.apple.dt.instruments",
    "com.apple.Safari",
];

struct Rule {
    cat: Category,
    glob: &'static str,
    label: &'static str,
    rec: bool,
    owners: &'static [&'static str],
    note: Option<&'static str>,
}

const fn r(cat: Category, glob: &'static str, label: &'static str, rec: bool, owners: &'static [&'static str]) -> Rule {
    Rule { cat, glob, label, rec, owners, note: None }
}
const fn rn(cat: Category, glob: &'static str, label: &'static str, rec: bool, owners: &'static [&'static str], note: &'static str) -> Rule {
    Rule { cat, glob, label, rec, owners, note: Some(note) }
}

const XCODE: &[&str] = &["com.apple.dt.xcode", "xcode", "simulator"];
const JETBRAINS: &[&str] = &[
    "com.jetbrains.intellij", "com.jetbrains.intellij.ce", "com.jetbrains.pycharm", "com.jetbrains.pycharm.ce",
    "com.jetbrains.webstorm", "com.jetbrains.goland", "com.jetbrains.clion", "com.jetbrains.rider",
    "com.jetbrains.rustrover", "com.jetbrains.datagrip", "com.jetbrains.phpstorm", "com.jetbrains.rubymine",
    "com.google.android.studio",
];

use Category::*;

/// Explicit rules. `*` matches within one path component. Paths are relative to home.
const RULES: &[Rule] = &[
    // --- Browsers: disk caches only. Never cookies, history, storage or service workers.
    r(Browsers, "Library/Caches/Google/Chrome", "Google Chrome", true, &["com.google.chrome"]),
    r(Browsers, "Library/Caches/Chromium", "Chromium", true, &["org.chromium.chromium"]),
    r(Browsers, "Library/Caches/BraveSoftware/Brave-Browser", "Brave", true, &["com.brave.browser"]),
    r(Browsers, "Library/Caches/Microsoft Edge", "Microsoft Edge", true, &["com.microsoft.edgemac"]),
    r(Browsers, "Library/Caches/com.microsoft.edgemac", "Microsoft Edge", true, &["com.microsoft.edgemac"]),
    r(Browsers, "Library/Caches/Arc", "Arc", true, &["company.thebrowser.browser"]),
    r(Browsers, "Library/Caches/company.thebrowser.Browser", "Arc", true, &["company.thebrowser.browser"]),
    r(Browsers, "Library/Caches/company.thebrowser.dia", "Dia", true, &["company.thebrowser.dia"]),
    r(Browsers, "Library/Caches/Vivaldi", "Vivaldi", true, &["com.vivaldi.vivaldi"]),
    r(Browsers, "Library/Caches/com.vivaldi.Vivaldi", "Vivaldi", true, &["com.vivaldi.vivaldi"]),
    r(Browsers, "Library/Caches/com.operasoftware.Opera", "Opera", true, &["com.operasoftware.opera"]),
    r(Browsers, "Library/Caches/Firefox", "Firefox", true, &["org.mozilla.firefox"]),
    r(Browsers, "Library/Caches/zen", "Zen", true, &["app.zen-browser.zen"]),
    r(Browsers, "Library/Caches/Comet", "Comet", true, &["ai.perplexity.comet"]),
    r(Browsers, "Library/Caches/com.apple.Safari", "Safari", true, &["com.apple.safari"]),
    // --- AI tools: caches only; chats, projects and models are kept.
    r(AiTools, "Library/Caches/com.openai.chat", "ChatGPT", true, &["com.openai.chat"]),
    r(AiTools, "Library/Caches/com.anthropic.claudefordesktop", "Claude", true, &["com.anthropic.claudefordesktop"]),
    r(AiTools, "Library/Caches/claude-cli-nodejs", "Claude Code CLI", true, &[]),
    r(AiTools, "Library/Caches/ai.perplexity.mac", "Perplexity", true, &["ai.perplexity.mac"]),
    r(AiTools, ".cache/opencode", "opencode", true, &[]),
    // --- Developer tools.
    rn(DevTools, "Library/Developer/Xcode/DerivedData", "Xcode DerivedData", true, XCODE, "rebuilt on next build"),
    rn(DevTools, "Library/Developer/Xcode/iOS DeviceSupport/*", "iOS DeviceSupport", true, XCODE, "re-created when the device connects"),
    rn(DevTools, "Library/Developer/Xcode/watchOS DeviceSupport/*", "watchOS DeviceSupport", true, XCODE, "re-created when the device connects"),
    rn(DevTools, "Library/Developer/Xcode/tvOS DeviceSupport/*", "tvOS DeviceSupport", true, XCODE, "re-created when the device connects"),
    rn(DevTools, "Library/Developer/Xcode/visionOS DeviceSupport/*", "visionOS DeviceSupport", true, XCODE, "re-created when the device connects"),
    rn(DevTools, "Library/Developer/Xcode/Archives", "Xcode Archives", false, XCODE, "keep if you ship apps (contains dSYMs)"),
    r(DevTools, "Library/Developer/Xcode/UserData/Previews", "SwiftUI Previews", true, XCODE),
    r(DevTools, "Library/Developer/CoreSimulator/Caches", "Simulator caches", true, XCODE),
    r(DevTools, "Library/Caches/com.apple.dt.Xcode", "Xcode cache", true, XCODE),
    r(DevTools, "Library/Caches/com.apple.dt.instruments", "Instruments cache", true, XCODE),
    r(DevTools, "Library/Caches/org.swift.swiftpm", "SwiftPM cache", true, &[]),
    r(DevTools, "Library/Caches/CocoaPods", "CocoaPods cache", true, &[]),
    r(DevTools, "Library/Caches/Homebrew", "Homebrew downloads", true, &[]),
    r(DevTools, ".npm/_cacache", "npm cache", true, &[]),
    r(DevTools, ".npm/_npx", "npx cache", true, &[]),
    r(DevTools, ".npm/_logs", "npm logs", true, &[]),
    r(DevTools, "Library/Caches/Yarn", "Yarn cache", true, &[]),
    rn(DevTools, ".yarn/berry/cache", "Yarn Berry cache", false, &[], "Plug'n'Play projects need `yarn install` again"),
    r(DevTools, "Library/Caches/pnpm", "pnpm metadata cache", true, &[]),
    rn(DevTools, "Library/pnpm/store", "pnpm store", false, &[], "prefer `pnpm store prune`"),
    r(DevTools, ".bun/install/cache", "Bun cache", true, &[]),
    r(DevTools, "Library/Caches/pip", "pip cache", true, &[]),
    r(DevTools, "Library/Caches/pypoetry/cache", "Poetry cache", true, &[]),
    r(DevTools, "Library/Caches/pypoetry/artifacts", "Poetry artifacts", true, &[]),
    r(DevTools, ".cache/uv", "uv cache", true, &[]),
    r(DevTools, ".cache/pip", "pip cache", true, &[]),
    r(DevTools, ".cache/pre-commit", "pre-commit cache", true, &[]),
    r(DevTools, ".cache/ruff", "Ruff cache", true, &[]),
    r(DevTools, ".cache/mypy", "mypy cache", true, &[]),
    r(DevTools, ".cache/typescript", "TypeScript cache", true, &[]),
    r(DevTools, ".cache/node-gyp", "node-gyp cache", true, &[]),
    r(DevTools, ".cache/electron", "Electron downloads", true, &[]),
    r(DevTools, ".cache/vite", "Vite cache", true, &[]),
    r(DevTools, ".cache/eslint", "ESLint cache", true, &[]),
    r(DevTools, ".cache/prettier", "Prettier cache", true, &[]),
    rn(DevTools, ".cache/puppeteer", "Puppeteer browsers", false, &[], "re-downloaded on next install"),
    r(DevTools, "Library/Caches/typescript", "TypeScript cache", true, &[]),
    r(DevTools, "Library/Caches/node-gyp", "node-gyp cache", true, &[]),
    r(DevTools, "Library/Caches/electron", "Electron downloads", true, &[]),
    r(DevTools, "Library/Caches/electron-builder", "electron-builder cache", true, &[]),
    r(DevTools, "Library/Caches/go-build", "Go build cache", true, &[]),
    r(DevTools, "Library/Caches/golangci-lint", "golangci-lint cache", true, &[]),
    r(DevTools, ".cargo/registry/cache", "Cargo registry cache", true, &[]),
    r(DevTools, ".cargo/registry/src", "Cargo registry sources", true, &[]),
    r(DevTools, ".cargo/git/checkouts", "Cargo git checkouts", true, &[]),
    r(DevTools, ".rustup/downloads", "rustup downloads", true, &[]),
    rn(DevTools, ".gradle/caches", "Gradle caches", false, &["com.google.android.studio"], "next build re-downloads everything"),
    r(DevTools, ".gradle/daemon", "Gradle daemon logs", true, &[]),
    rn(DevTools, ".m2/repository", "Maven repository", false, &[], "re-downloaded on next build"),
    r(DevTools, ".android/cache", "Android SDK cache", true, &[]),
    r(DevTools, ".android/build-cache", "Android build cache", true, &[]),
    rn(DevTools, "Library/Caches/Google/AndroidStudio*", "Android Studio cache", true, &["com.google.android.studio"], "Local History is kept"),
    rn(DevTools, "Library/Caches/JetBrains/*", "JetBrains", false, JETBRAINS, "IDE re-indexes; Local History is kept"),
    r(DevTools, "Library/Caches/Cypress", "Cypress binaries", false, &[]),
    // --- Logs & crash reports.
    r(Logs, "Library/Application Support/CrashReporter", "CrashReporter", true, &[]),
    // --- Installers & updates.
    r(Installers, "Library/iTunes/iPhone Software Updates", "iOS firmware files", true, &[]),
];

/// Electron apps that belong to the AI / developer categories (Application Support folder names).
const AI_APPS: &[&str] = &["Claude", "ChatGPT", "Perplexity", "LM Studio", "Ollama", "Jan", "Msty", "Poe", "Chatbox", "Cherry Studio", "Antigravity", "Qoder"];
const DEV_APPS: &[&str] = &["Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium", "Trae", "Kiro", "Postman", "Insomnia", "GitHub Desktop", "Bruno", "Zed"];

/// Chromium browsers: Application Support folder (profiles inside) and owner bundle id.
const CHROMIUM_SUPPORT: &[(&str, &str, &str)] = &[
    ("Library/Application Support/Google/Chrome", "Chrome", "com.google.chrome"),
    ("Library/Application Support/Chromium", "Chromium", "org.chromium.chromium"),
    ("Library/Application Support/BraveSoftware/Brave-Browser", "Brave", "com.brave.browser"),
    ("Library/Application Support/Microsoft Edge", "Edge", "com.microsoft.edgemac"),
    ("Library/Application Support/Arc/User Data", "Arc", "company.thebrowser.browser"),
    ("Library/Application Support/Dia/User Data", "Dia", "company.thebrowser.dia"),
    ("Library/Application Support/Vivaldi", "Vivaldi", "com.vivaldi.vivaldi"),
    ("Library/Application Support/com.operasoftware.Opera", "Opera", "com.operasoftware.opera"),
];
const CHROMIUM_PROFILE_CACHES: &[&str] = &["Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache"];
const CHROMIUM_ROOT_CACHES: &[&str] = &["GrShaderCache", "GraphiteDawnCache", "ShaderCache", "component_crx_cache"];
const ELECTRON_CACHES: &[&str] = &["Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GrShaderCache", "GraphiteDawnCache", "CachedData", "CachedExtensionVSIXs", "sentry"];

/// Application Support folders never scanned for Electron caches.
const APP_SUPPORT_SKIP: &[&str] = &["Google", "BraveSoftware", "Microsoft Edge", "Arc", "Dia", "Vivaldi", "Chromium", "com.operasoftware.Opera", "Codex", "Steam", "Epic", "MobileSync", "AddressBook", "CallHistoryDB", "Knowledge", "com.apple.TCC"];

const INSTALLER_EXTS: &[&str] = &["dmg", "pkg", "mpkg", "xip", "iso"];

/// Expand a home-relative glob where `*` may appear inside a single path component.
fn expand(glob: &str) -> Vec<PathBuf> {
    let mut paths = vec![home().to_path_buf()];
    for comp in glob.split('/') {
        let mut next = Vec::new();
        for p in &paths {
            if comp.contains('*') {
                if let Ok(rd) = fs::read_dir(p) {
                    for e in rd.flatten() {
                        if safety::glob_match(comp, &e.file_name().to_string_lossy()) {
                            next.push(e.path());
                        }
                    }
                }
            } else {
                next.push(p.join(comp));
            }
        }
        paths = next;
    }
    paths.into_iter().filter(|p| fs::symlink_metadata(p).is_ok_and(|m| !m.file_type().is_symlink())).collect()
}

fn item(path: PathBuf, label: String, cat: Category, rec: bool, owners: Vec<String>, note: Option<String>, mode: Mode) -> Item {
    Item { path, label, category: cat, size: 0, recommended: rec, owners, note, mode, mtime: None }
}

fn name_of(p: &Path) -> String {
    p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default()
}

pub fn scan(p: &Progress) -> CleanScan {
    p.set_current("Looking for caches, logs and leftovers…");
    let mut items: Vec<Item> = Vec::new();
    let mut claimed: HashSet<PathBuf> = HashSet::new();

    // 1. Explicit rules.
    for rule in RULES {
        for path in expand(rule.glob) {
            if !path.is_dir() || !claimed.insert(path.clone()) {
                continue;
            }
            let label = if rule.glob.ends_with('*') { format!("{} {}", rule.label, name_of(&path)) } else { rule.label.to_string() };
            let owners = rule.owners.iter().map(|s| s.to_string()).collect();
            items.push(item(path, label, rule.cat, rule.rec, owners, rule.note.map(String::from), Mode::Contents));
        }
    }

    // 2. Chromium browser profile caches (Code Cache, GPUCache...) in Application Support.
    for (root, name, owner) in CHROMIUM_SUPPORT {
        let root = h(root);
        let Ok(rd) = fs::read_dir(&root) else { continue };
        let mut dirs: Vec<(PathBuf, String)> = CHROMIUM_ROOT_CACHES.iter().map(|c| (root.join(c), format!("{name} · {c}"))).collect();
        for e in rd.flatten() {
            let profile = name_of(&e.path());
            // A Chromium profile has a "Preferences" file.
            if e.path().join("Preferences").is_file() {
                for c in CHROMIUM_PROFILE_CACHES {
                    dirs.push((e.path().join(c), format!("{name} · {profile} · {c}")));
                }
            }
        }
        for (dir, label) in dirs {
            if dir.is_dir() && claimed.insert(dir.clone()) {
                items.push(item(dir, label, Browsers, true, vec![owner.to_string()], None, Mode::Contents));
            }
        }
    }

    // 3. Electron app caches in Application Support (only folders that look like Chromium).
    if let Ok(rd) = fs::read_dir(h("Library/Application Support")) {
        for e in rd.flatten() {
            let app = name_of(&e.path());
            if APP_SUPPORT_SKIP.contains(&app.as_str()) || app.starts_with("com.apple.") || safety::is_protected_cache_name(&app) {
                continue;
            }
            let dir = e.path();
            let is_electron = dir.join("Code Cache").is_dir() || dir.join("GPUCache").is_dir();
            if !is_electron {
                continue;
            }
            let cat = if AI_APPS.contains(&app.as_str()) {
                AiTools
            } else if DEV_APPS.contains(&app.as_str()) {
                DevTools
            } else {
                AppCaches
            };
            let owners = vec![app.to_lowercase()];
            for c in ELECTRON_CACHES {
                let p = dir.join(c);
                if p.is_dir() && claimed.insert(p.clone()) {
                    items.push(item(p, format!("{app} · {c}"), cat, true, owners.clone(), None, Mode::Contents));
                }
            }
            let logs = dir.join("logs");
            if logs.is_dir() && claimed.insert(logs.clone()) {
                items.push(item(logs, format!("{app} logs"), Logs, true, vec![], None, Mode::Contents));
            }
        }
    }

    // 4. Allow-listed Apple caches.
    for name in APPLE_CACHES {
        let p = h("Library/Caches").join(name);
        if p.is_dir() && claimed.insert(p.clone()) {
            let mut owners = vec![name.to_lowercase(), name.trim_start_matches("com.apple.").to_lowercase()];
            if *name == "com.apple.AppleMediaServices" {
                owners.extend(["amsaccountsd".into(), "amsengagementd".into(), "amsondevicestoraged".into()]);
            }
            items.push(item(p, name.to_string(), SystemCaches, true, owners, None, Mode::Contents));
        }
    }

    // 5. Every other folder in ~/Library/Caches -> App Caches (minus protected ones).
    sweep_caches(&h("Library/Caches"), &claimed, &mut items);

    // 6. Logs: each folder/file in ~/Library/Logs.
    if let Ok(rd) = fs::read_dir(h("Library/Logs")) {
        for e in rd.flatten() {
            let p = e.path();
            let name = name_of(&p);
            if ["mole", "com.openai.codex", "DiskCleaner"].contains(&name.as_str()) || claimed.contains(&p) {
                continue;
            }
            let mode = if p.is_dir() { Mode::Contents } else { Mode::File };
            if e.file_type().is_ok_and(|t| !t.is_symlink()) {
                items.push(item(p, name, Logs, true, vec![], None, mode));
            }
        }
    }

    // 7. Installers in Downloads (off by default: these are your files).
    if let Ok(rd) = fs::read_dir(h("Downloads")) {
        for e in rd.flatten() {
            let p = e.path();
            let ext = p.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
            if INSTALLER_EXTS.contains(&ext.as_str()) && e.file_type().is_ok_and(|t| t.is_file()) {
                items.push(item(p.clone(), name_of(&p), Installers, false, vec![], None, Mode::File));
            }
        }
    }

    // 8. Trash (off by default: emptying it is permanent).
    let trash = h(".Trash");
    if trash.is_dir() {
        let count = fs::read_dir(&trash).map(|rd| rd.count()).ok();
        let label = match count {
            Some(n) => format!("Trash ({n} items)"),
            None => "Trash (size needs Full Disk Access)".into(),
        };
        items.push(item(trash, label, Trash, false, vec![], None, Mode::EmptyTrash));
    }

    // Measure everything in parallel, reporting each category as it completes.
    p.total.store(items.len() as u64, Ordering::Relaxed);
    let remaining: Vec<AtomicUsize> = Category::ALL.iter().map(|c| AtomicUsize::new(items.iter().filter(|i| i.category == *c).count())).collect();
    for (c, r) in Category::ALL.iter().zip(&remaining) {
        if r.load(Ordering::Relaxed) > 0 {
            p.add_to_group(c.title(), 0, false);
        }
    }
    items.par_iter_mut().for_each(|it| {
        let (size, newest) = util::measure(&it.path, Some(p));
        it.size = size;
        it.mtime = (newest > 0).then_some(newest);
        let ci = Category::ALL.iter().position(|c| *c == it.category).unwrap();
        let finished = remaining[ci].fetch_sub(1, Ordering::Relaxed) == 1;
        p.add_to_group(it.category.title(), it.size, finished);
        p.bytes.fetch_add(it.size, Ordering::Relaxed);
        p.done.fetch_add(1, Ordering::Relaxed);
    });
    // Drop empty entries (keep Trash so it can always be emptied).
    for it in items.iter_mut().filter(|it| it.mode != Mode::File) {
        // The folder entry itself is kept, so don't count it.
        it.size = it.size.saturating_sub(fs::symlink_metadata(&it.path).map(|m| std::os::unix::fs::MetadataExt::blocks(&m) * 512).unwrap_or(0));
    }
    items.retain(|it| it.size >= 16 * 1024 || (it.mode == Mode::EmptyTrash && !it.label.ends_with("(0 items)")));
    items.sort_by(|a, b| b.size.cmp(&a.size));
    CleanScan { items, scanned_at: util::now() }
}

fn sweep_caches(dir: &Path, claimed: &HashSet<PathBuf>, items: &mut Vec<Item>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = name_of(&p);
        if claimed.contains(&p) || !e.file_type().is_ok_and(|t| t.is_dir()) || safety::is_protected_cache_name(&name) {
            continue;
        }
        if name == "pypoetry" || p.join("com.apple.e5rt.e5bundlecache").exists() {
            continue; // virtualenvs / Apple compiled models: never part of a sweep.
        }
        // If some claimed path lives inside, descend so each piece lands in its own category.
        if claimed.iter().any(|c| c.starts_with(&p)) {
            sweep_caches(&p, claimed, items);
            continue;
        }
        let lower = name.to_lowercase();
        let mut owners = vec![lower.clone()];
        if let Some(app) = lower.strip_suffix(".shipit") {
            owners.push(app.to_string()); // the Squirrel updater of that app
        }
        items.push(item(p, pretty_cache_name(&name), AppCaches, true, owners, None, Mode::Contents));
    }
}

/// "com.spotify.client" -> "com.spotify.client"; keep ids, they are unambiguous.
fn pretty_cache_name(name: &str) -> String {
    name.to_string()
}

pub struct Report {
    pub freed: u64,
    pub cleaned: usize,
    pub skipped_running: Vec<String>,
    pub refused: Vec<String>,
}

pub fn is_running(item: &Item, running: &Running) -> bool {
    running.holds(&item.owners, &item.path)
}

/// Delete the given items. Re-checks running apps and the safety rules for every item.
pub fn clean(items: &[Item], running: &Running, ctx: &safety::Ctx, p: &Progress) -> Report {
    let mut report = Report { freed: 0, cleaned: 0, skipped_running: vec![], refused: vec![] };
    let results: Vec<Result<u64, String>> = items
        .par_iter()
        .map(|it| {
            if is_running(it, running) {
                return Err(format!("running:{}", it.label));
            }
            p.set_current(util::tilde(&it.path));
            let r = clean_one(it, ctx);
            if let Ok(n) = r {
                p.bytes.fetch_add(n, Ordering::Relaxed);
                p.add_to_group(it.category.title(), n, false);
            }
            p.done.fetch_add(1, Ordering::Relaxed);
            r
        })
        .collect();
    for r in results {
        match r {
            Ok(n) => {
                report.freed += n;
                report.cleaned += 1;
            }
            Err(e) if e.starts_with("running:") => report.skipped_running.push(e[8..].to_string()),
            Err(e) => report.refused.push(e),
        }
    }
    report
}

fn clean_one(it: &Item, ctx: &safety::Ctx) -> Result<u64, String> {
            match it.mode {
                Mode::EmptyTrash => empty_trash(ctx),
                Mode::Contents => {
                    safety::check_cleanable(&it.path)?;
                    if !it.path.is_dir() {
                        return Err(format!("{} is not a folder", it.path.display()));
                    }
                    Ok(safety::remove_contents(&it.path, ctx))
                }
                Mode::File => {
                    safety::check_cleanable(&it.path)?;
                    if !fs::symlink_metadata(&it.path).is_ok_and(|m| m.is_file()) {
                        return Err(format!("{} is not a file", it.path.display()));
                    }
                    Ok(safety::remove_tree(&it.path, ctx))
                }
            }
}

fn empty_trash(ctx: &safety::Ctx) -> Result<u64, String> {
    let trash = h(".Trash");
    // Without Full Disk Access macOS hides the Trash; we never fall back to Finder's
    // "empty trash", which would bypass these checks and empty every disk's Trash.
    let rd = fs::read_dir(&trash).map_err(|_| "Emptying the Trash needs Full Disk Access".to_string())?;
    Ok(rd
        .flatten()
        .map(|e| {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_symlink()) {
                let _ = fs::remove_file(&p); // a symlink in the Trash: remove the link only
                0
            } else if safety::check_cleanable(&p).is_ok() {
                safety::remove_tree(&p, ctx)
            } else {
                0
            }
        })
        .sum())
}
