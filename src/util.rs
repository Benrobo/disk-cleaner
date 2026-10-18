//! Small shared helpers: paths, sizes, formatting, and native dialogs via osascript.

use rayon::prelude::*;
use std::ffi::CStr;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// The real home directory of the current user (from the passwd database, not $HOME).
pub fn home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let from_passwd = unsafe {
            let pw = libc::getpwuid(libc::getuid());
            if pw.is_null() || (*pw).pw_dir.is_null() {
                None
            } else {
                Some(PathBuf::from(CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned()))
            }
        };
        let home = from_passwd
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .expect("cannot determine home directory");
        // Refuse to run against anything that is not a normal user home.
        assert!(
            home.starts_with("/Users/") && home.components().count() == 3,
            "unexpected home directory {home:?}"
        );
        home
    })
}

pub fn h(rel: &str) -> PathBuf {
    home().join(rel)
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Live progress of a background job, polled by the UI a few times per second.
#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub bytes: AtomicU64,
    pub done: AtomicU64,
    pub total: AtomicU64,
    dirs: AtomicU64,
    pub current: Mutex<String>,
    /// (label, bytes, finished): categories, folders or apps as they complete.
    pub groups: Mutex<Vec<(String, u64, bool)>>,
}

impl Progress {
    pub fn set_current(&self, text: impl Into<String>) {
        if let Ok(mut c) = self.current.lock() {
            *c = text.into();
        }
    }

    /// Add bytes to a group, creating it if needed.
    pub fn add_to_group(&self, label: &str, bytes: u64, finished: bool) {
        let mut g = self.groups.lock().unwrap();
        match g.iter_mut().find(|x| x.0 == label) {
            Some(x) => {
                x.1 += bytes;
                x.2 |= finished;
            }
            None => g.push((label.to_string(), bytes, finished)),
        }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        serde_json::json!({
            "files": ld(&self.files), "bytes": ld(&self.bytes), "done": ld(&self.done), "total": ld(&self.total),
            "current": self.current.lock().map(|c| c.clone()).unwrap_or_default(),
            "groups": self.groups.lock().map(|g| g.clone()).unwrap_or_default(),
        })
    }
}

/// Bytes actually allocated on disk for `path` (like `du`), never following symlinks
/// and never crossing onto another volume.
pub fn size_of(path: &Path) -> u64 {
    size_with(path, None)
}

/// Like `size_of`, also counting files and showing the folder being read in `p`.
pub fn size_with(path: &Path, p: Option<&Progress>) -> u64 {
    measure(path, p).0
}

/// (bytes on disk, newest modification time inside as unix seconds).
pub fn measure(path: &Path, p: Option<&Progress>) -> (u64, u64) {
    match fs::symlink_metadata(path) {
        Ok(md) if md.is_dir() => {
            let (size, newest) = dir_size(path, md.dev(), p);
            (md.blocks() * 512 + size, newest.max(md.mtime().max(0) as u64))
        }
        Ok(md) => (md.blocks() * 512, md.mtime().max(0) as u64),
        Err(_) => (0, 0),
    }
}

fn dir_size(path: &Path, dev: u64, p: Option<&Progress>) -> (u64, u64) {
    let Ok(rd) = fs::read_dir(path) else { return (0, 0) };
    let entries: Vec<_> = rd.flatten().collect();
    if let Some(p) = p {
        p.files.fetch_add(entries.len() as u64, Ordering::Relaxed);
        if p.dirs.fetch_add(1, Ordering::Relaxed) % 64 == 0 {
            p.set_current(tilde(path));
        }
    }
    let one = |e: &fs::DirEntry| -> (u64, u64) {
        // DirEntry::metadata does not traverse symlinks.
        let Ok(md) = e.metadata() else { return (0, 0) };
        let own = (md.blocks() * 512, md.mtime().max(0) as u64);
        if md.is_dir() && md.dev() == dev {
            let (s, m) = dir_size(&e.path(), dev, p);
            (own.0 + s, own.1.max(m))
        } else if md.is_dir() {
            (0, 0)
        } else {
            own
        }
    };
    let merge = |a: (u64, u64), b: (u64, u64)| (a.0 + b.0, a.1.max(b.1));
    if entries.len() > 16 {
        entries.par_iter().map(one).reduce(|| (0, 0), merge)
    } else {
        entries.iter().map(one).fold((0, 0), merge)
    }
}

/// Free and total bytes of the startup volume.
pub fn disk_space() -> (u64, u64) {
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c"/".as_ptr(), &mut st) } != 0 {
        return (0, 0);
    }
    let frsize = st.f_frsize as u64;
    (st.f_bavail as u64 * frsize, st.f_blocks as u64 * frsize)
}

/// Human size with decimal units, matching Finder ("5.72 GB").
pub fn fmt_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    match u {
        0 => format!("{bytes} B"),
        _ if v >= 100.0 => format!("{v:.0} {}", UNITS[u]),
        _ if v >= 10.0 => format!("{v:.1} {}", UNITS[u]),
        _ => format!("{v:.2} {}", UNITS[u]),
    }
}

pub fn fmt_ago(ts: u64) -> String {
    let d = now().saturating_sub(ts);
    match d {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", d / 60),
        3600..86400 => plural(d / 3600, "hour"),
        86400..2_592_000 => plural(d / 86400, "day"),
        2_592_000..31_536_000 => plural(d / 2_592_000, "month"),
        _ => plural(d / 31_536_000, "year"),
    }
}

fn plural(n: u64, unit: &str) -> String {
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

pub fn fmt_duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60);
    if d > 0 { format!("{d}d {h}h") } else if h > 0 { format!("{h}h {m}m") } else { format!("{m}m") }
}

/// Path shown relative to home ("~/Library/Caches").
pub fn tilde(p: &Path) -> String {
    match p.strip_prefix(home()) {
        Ok(rel) if rel.as_os_str().is_empty() => "~".into(),
        Ok(rel) => format!("~/{}", rel.display()),
        Err(_) => p.display().to_string(),
    }
}

/// Run an AppleScript with arguments passed via argv, so no string escaping is ever needed.
fn osascript(lines: &[&str], args: &[&str]) -> Option<std::process::Output> {
    let mut cmd = Command::new("/usr/bin/osascript");
    for l in lines {
        cmd.arg("-e").arg(l);
    }
    cmd.args(args).output().ok()
}

pub fn notify(title: &str, message: &str) {
    osascript(
        &["on run argv", "display notification (item 1 of argv) with title (item 2 of argv)", "end run"],
        &[message, title],
    );
}

/// Run a fixed shell command with an administrator password prompt.
pub fn run_admin(shell: &str) -> Result<(), String> {
    let out = osascript(
        &["on run argv", "do shell script (item 1 of argv) with administrator privileges", "end run"],
        &[shell],
    )
    .ok_or("could not run osascript")?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().to_string()) }
}

pub fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd).args(args).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn reveal(path: &Path) {
    let _ = Command::new("/usr/bin/open").arg("-R").arg(path).spawn();
}

pub fn open(target: &str) {
    let _ = Command::new("/usr/bin/open").arg(target).spawn();
}

/// Every file currently held open by one of the user's processes, inside the home folder.
/// Checked right before deleting, so nothing in use (databases, downloads, logs) is removed.
pub fn open_files() -> std::collections::HashSet<PathBuf> {
    let uid = unsafe { libc::getuid() }.to_string();
    let out = Command::new("/usr/sbin/lsof").args(["-n", "-P", "-w", "-F", "n", "-u", &uid]).output();
    let home = home().to_string_lossy().into_owned();
    out.map(|o| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| l.strip_prefix('n'))
            .filter(|p| p.starts_with(&home))
            .map(PathBuf::from)
            .collect()
    })
    .unwrap_or_default()
}

/// Full Disk Access lets us read protected folders without per-folder permission prompts.
pub fn has_full_disk_access() -> bool {
    fs::File::open(h("Library/Application Support/com.apple.TCC/TCC.db")).is_ok()
}

/// Move paths to the user's Trash (recoverable). Uses NSFileManager, so no Finder automation prompt.
pub fn move_to_trash(path: &Path) -> Result<(), String> {
    use trash::macos::{DeleteMethod, TrashContextExtMacos};
    let mut ctx = trash::TrashContext::default();
    ctx.set_delete_method(DeleteMethod::NsFileManager);
    ctx.delete(path).map_err(|e| e.to_string())
}
