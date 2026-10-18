//! Live system status (CPU, memory, disk, network, battery, top apps) and the set of
//! running apps, which Clean and Apps use to avoid touching anything in use.

use crate::util::{self, fmt_size};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use sysinfo::{Networks, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[derive(Clone, Default)]
pub struct Snapshot {
    pub free: u64,
    pub total: u64,
    pub cpu: f32,
    pub mem_used: u64,
    pub mem_total: u64,
    pub swap_used: u64,
    pub load: f64,
    pub cores: usize,
    pub uptime: u64,
    pub net_down: u64,
    pub net_up: u64,
    pub battery: Option<String>,
    /// (app name, memory bytes, cpu %), grouped by app bundle.
    pub top: Vec<(String, u64, f32)>,
    pub running: Running,
    /// Running GUI apps: (display name, bundle id, lowercase ids).
    pub gui_apps: Vec<(String, String, Vec<String>)>,
    pub machine: String,
}

impl Snapshot {
    pub fn health(&self) -> (u32, &'static str) {
        let mem = self.mem_used as f64 / self.mem_total.max(1) as f64 * 100.0;
        let disk = 100.0 - self.free as f64 / self.total.max(1) as f64 * 100.0;
        let mut score = 100.0;
        score -= (self.cpu as f64 - 30.0).max(0.0) * 0.4;
        score -= (mem - 60.0).max(0.0) * 0.6;
        score -= if disk > 95.0 { 30.0 } else if disk > 90.0 { 20.0 } else if disk > 80.0 { 10.0 } else { 0.0 };
        let score = score.clamp(0.0, 100.0) as u32;
        let label = match score {
            85.. => "Excellent",
            70..85 => "Good",
            50..70 => "Fair",
            _ => "Poor",
        };
        (score, label)
    }
}

pub const TOP_N: usize = 6;

pub struct Monitor {
    sys: System,
    nets: Networks,
    bundle_cache: HashMap<PathBuf, Bundle>,
    machine: String,
    battery: Option<String>,
    ticks: u64,
}

impl Monitor {
    pub fn new() -> Self {
        let chip = util::run("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"]).unwrap_or_default();
        let mut sys = System::new();
        sys.refresh_memory();
        let machine = format!(
            "{} · {} RAM · macOS {}",
            chip.trim().trim_start_matches("Apple "),
            fmt_size(sys.total_memory()),
            System::os_version().unwrap_or_default()
        );
        Monitor { sys, nets: Networks::new_with_refreshed_list(), bundle_cache: HashMap::new(), machine, battery: None, ticks: 0 }
    }

    /// Call every `interval_secs`.
    pub fn sample(&mut self, interval_secs: f64) -> Snapshot {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();
        self.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, light_refresh());
        self.nets.refresh(true);
        if self.ticks % 15 == 0 {
            self.battery = battery();
        }
        self.ticks += 1;

        let (free, total) = util::disk_space();
        let (down, up) = self.nets.list().values().fold((0, 0), |(d, u), n| (d + n.received(), u + n.transmitted()));

        let mut running = Running::default();
        let mut gui_apps: HashMap<String, (String, String, Vec<String>)> = HashMap::new();
        let mut by_app: HashMap<String, (u64, f32)> = HashMap::new();
        let procs: Vec<_> = self.sys.processes().values().map(|p| (p.name().to_string_lossy().into_owned(), p.exe().map(Path::to_path_buf), p.memory(), p.cpu_usage())).collect();
        running.paths = process_paths(&self.sys);
        for (name, exe, mem, cpu) in procs {
            running.ids.insert(name.to_lowercase());
            let mut group = name.clone();
            if let Some(app) = exe.as_deref().and_then(outer_app) {
                let b = self.bundle_cache.entry(app.clone()).or_insert_with(|| bundle(&app));
                running.ids.extend(b.ids.iter().cloned());
                if !b.id.is_empty() {
                    gui_apps.entry(b.id.clone()).or_insert_with(|| (b.name.clone(), b.id.clone(), b.ids.clone()));
                }
                group = b.name.clone();
            }
            let e = by_app.entry(group).or_default();
            e.0 += mem;
            e.1 += cpu;
        }
        let mut top: Vec<_> = by_app.into_iter().map(|(n, (m, c))| (n, m, c)).collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        top.truncate(TOP_N);

        Snapshot {
            free,
            total,
            cpu: self.sys.global_cpu_usage(),
            mem_used: self.sys.used_memory(),
            mem_total: self.sys.total_memory(),
            swap_used: self.sys.used_swap(),
            load: System::load_average().one,
            cores: self.sys.cpus().len(),
            uptime: System::uptime(),
            net_down: (down as f64 / interval_secs) as u64,
            net_up: (up as f64 / interval_secs) as u64,
            battery: self.battery.clone(),
            top,
            running,
            gui_apps: gui_apps.into_values().collect(),
            machine: self.machine.clone(),
        }
    }
}

/// Only what we display: memory, CPU and the executable path (read once per process).
fn light_refresh() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_memory()
        .with_cpu()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .with_cwd(UpdateKind::OnlyIfNotSet)
}

/// What is running: names/bundle ids, plus every path a process runs from or was started
/// with inside the home folder (executables, working dirs, arguments). The paths catch
/// updaters (ShipIt, Sparkle), `npx` servers and helpers that live inside a cache folder.
#[derive(Clone, Default)]
pub struct Running {
    pub ids: HashSet<String>,
    pub paths: Vec<PathBuf>,
}

impl Running {
    pub fn holds(&self, owners: &[String], folder: &Path) -> bool {
        owners.iter().any(|o| self.ids.contains(o)) || self.paths.iter().any(|p| p.starts_with(folder))
    }
}

fn process_paths(sys: &System) -> Vec<PathBuf> {
    let home = crate::util::home();
    let mut out = HashSet::new();
    for p in sys.processes().values() {
        let mut cands: Vec<PathBuf> = p.cmd().iter().map(PathBuf::from).filter(|a| a.is_absolute()).collect();
        cands.extend(p.exe().map(Path::to_path_buf));
        cands.extend(p.cwd().map(Path::to_path_buf));
        out.extend(cands.into_iter().filter(|c| c.starts_with(home) && c != home));
    }
    out.into_iter().collect()
}

/// "/Applications/Google Chrome.app/Contents/Frameworks/.../Helper.app/..." -> "/Applications/Google Chrome.app"
fn outer_app(exe: &Path) -> Option<PathBuf> {
    let mut acc = PathBuf::new();
    for c in exe.components() {
        acc.push(c);
        if acc.extension().is_some_and(|e| e == "app") {
            return Some(acc);
        }
    }
    None
}

struct Bundle {
    ids: Vec<String>,
    name: String,
    id: String,
}

fn bundle(app: &Path) -> Bundle {
    let stem = app.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let mut b = Bundle { ids: vec![stem.to_lowercase()], name: stem, id: String::new() };
    if let Ok(plist::Value::Dictionary(d)) = plist::Value::from_file(app.join("Contents/Info.plist")) {
        for key in ["CFBundleIdentifier", "CFBundleName", "CFBundleExecutable"] {
            if let Some(s) = d.get(key).and_then(|v| v.as_string()) {
                b.ids.push(s.to_lowercase());
            }
        }
        b.id = d.get("CFBundleIdentifier").and_then(|v| v.as_string()).unwrap_or_default().to_string();
    }
    b
}

/// A one-off process list, used right before deleting anything.
pub fn running_now() -> Running {
    let mut m = Monitor { sys: System::new(), nets: Networks::new(), bundle_cache: HashMap::new(), machine: String::new(), battery: None, ticks: 1 };
    m.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, light_refresh());
    let mut running = Running { ids: HashSet::new(), paths: process_paths(&m.sys) };
    for p in m.sys.processes().values() {
        running.ids.insert(p.name().to_string_lossy().to_lowercase());
        if let Some(app) = p.exe().and_then(outer_app) {
            running.ids.extend(bundle(&app).ids);
        }
    }
    running
}

fn battery() -> Option<String> {
    let out = util::run("/usr/sbin/ioreg", &["-rn", "AppleSmartBattery"]).ok()?;
    let get = |key: &str| -> Option<i64> {
        out.lines().find_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix(&format!("\"{key}\" = "))?;
            rest.trim().parse().ok().or_else(|| match rest.trim() {
                "Yes" => Some(1),
                "No" => Some(0),
                _ => None,
            })
        })
    };
    let pct = get("CurrentCapacity")?;
    let charging = get("IsCharging") == Some(1);
    let plugged = get("ExternalConnected") == Some(1);
    let state = if charging { "charging" } else if plugged { "on power" } else { "on battery" };
    let mut s = format!("Battery {pct}% · {state}");
    if let (Some(max), Some(design)) = (get("AppleRawMaxCapacity"), get("DesignCapacity")) {
        if design > 0 {
            s += &format!(" · health {}%", (max * 100 / design).min(100));
        }
    }
    if let Some(c) = get("CycleCount") {
        s += &format!(" · {c} cycles");
    }
    Some(s)
}
