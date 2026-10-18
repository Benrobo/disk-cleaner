//! The menu bar panel. A borderless window drops down under the menu bar icon (like Mole's
//! status popover) and hides when you click elsewhere. The UI is a single HTML page
//! (`ui/index.html`); it talks to this controller with small JSON messages. All disk work
//! runs on background threads and comes back as `Ev` events on the main thread.

use crate::analyze::{self, AnalyzeScan, Node};
use crate::apps::{self, App};
use crate::clean::{self, Category, Item};
use crate::status::{self, Snapshot};
use crate::store::Store;
use crate::util::{self, Progress, fmt_ago, fmt_size, tilde};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use crate::{icon, optimize, safety};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use tao::dpi::{LogicalSize, PhysicalPosition, PhysicalSize};
use tao::event_loop::{EventLoopProxy, EventLoopWindowTarget};
use tao::platform::macos::WindowBuilderExtMacOS;
use tao::window::{Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, Rect, TrayIcon, TrayIconBuilder, TrayIconEvent};
use wry::http::{Request, Response};
use wry::{WebView, WebViewBuilder};

const PANEL_W: f64 = 440.0;
const PANEL_H: f64 = 640.0;
const HISTORY: usize = 40;

pub enum Ev {
    Tray(TrayIconEvent),
    Menu(MenuId),
    Ipc(String),
    Focus(bool),
    Status(Snapshot),
    CleanScanned(clean::CleanScan),
    /// Live progress snapshot of a running job, for the UI.
    Progress(&'static str, Value),
    CleanDone(clean::Report, u64, u64),
    AppsScanned(apps::AppsScan),
    Uninstalled(Vec<(String, PathBuf, apps::UninstallResult)>),
    AnalyzeScanned(AnalyzeScan),
    Trashed(PathBuf, Result<(), String>),
    OptimizeDone(usize, Result<(), String>),
}

#[derive(Default)]
struct Busy {
    clean_scan: bool,
    cleaning: bool,
    apps_scan: bool,
    analyzing: bool,
    uninstalling: bool,
    optimizing: Option<usize>,
}

#[derive(Default)]
struct History {
    cpu: VecDeque<f32>,
    mem: VecDeque<f32>,
    down: VecDeque<u64>,
    up: VecDeque<u64>,
}

pub struct Ui {
    proxy: EventLoopProxy<Ev>,
    window: Window,
    webview: WebView,
    tray: TrayIcon,
    open_id: MenuId,
    quit_id: MenuId,
    store: Store,
    snap: Snapshot,
    hist: History,
    running_items: HashSet<usize>,
    /// Selections for Trash / Installers: this session only.
    session_overrides: std::collections::HashMap<String, bool>,
    busy: Busy,
    visible: bool,
    fda: bool,
    /// Dragged away from the menu bar: stays open until closed explicitly.
    pinned: bool,
    ready: bool,
    last_hide: Instant,
    last_icon_pct: i32,
}

fn push_capped<T>(q: &mut VecDeque<T>, v: T) {
    q.push_back(v);
    if q.len() > HISTORY {
        q.pop_front();
    }
}

impl Ui {
    pub fn new(proxy: EventLoopProxy<Ev>, target: &EventLoopWindowTarget<Ev>) -> Ui {
        let store = Store::load();

        // Right-click menu on the icon; left click toggles the panel.
        let menu = Menu::new();
        let open = MenuItem::new("Open Disk Cleaner", true, None);
        let quit = MenuItem::new("Quit Disk Cleaner", true, None);
        let _ = menu.append_items(&[&open, &PredefinedMenuItem::separator(), &quit]);
        let (free, total) = util::disk_space();
        let used = 1.0 - free as f64 / total.max(1) as f64;
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_icon_templated(icon::disk_pie(used))
            .with_title(format!(" {}", fmt_size(free)))
            .with_tooltip("Disk Cleaner")
            .build()
            .expect("create tray icon");

        let window = WindowBuilder::new()
            .with_title("Disk Cleaner")
            .with_inner_size(LogicalSize::new(PANEL_W, PANEL_H))
            .with_decorations(false)
            .with_transparent(true)
            .with_resizable(false)
            .with_visible(false)
            .with_always_on_top(true)
            .with_has_shadow(true)
            .with_visible_on_all_workspaces(true)
            .build(target)
            .expect("create panel window");

        let ipc_proxy = proxy.clone();
        let webview = WebViewBuilder::new()
            .with_transparent(true)
            .with_custom_protocol("dc".into(), |_, req| serve(req))
            .with_ipc_handler(move |req: Request<String>| {
                let _ = ipc_proxy.send_event(Ev::Ipc(req.into_body()));
            })
            .with_url("dc://localhost/")
            .build(&window)
            .expect("create webview");
        // Native frosted popover material with rounded corners, like Control Center.
        let _ = window_vibrancy::apply_vibrancy(
            &window,
            window_vibrancy::NSVisualEffectMaterial::Popover,
            Some(window_vibrancy::NSVisualEffectState::Active),
            Some(12.0),
        );

        let mut ui = Ui {
            proxy,
            window,
            webview,
            tray,
            open_id: open.id().clone(),
            quit_id: quit.id().clone(),
            store,
            snap: Snapshot { free, total, ..Default::default() },
            hist: History::default(),
            running_items: HashSet::new(),
            session_overrides: Default::default(),
            busy: Busy::default(),
            visible: false,
            fda: util::has_full_disk_access(),
            pinned: false,
            ready: false,
            last_hide: Instant::now() - Duration::from_secs(5),
            last_icon_pct: (used * 100.0) as i32,
        };
        // Cached results are shown instantly; fresh scans run in the background.
        ui.start_clean_scan();
        ui.start_apps_scan();
        ui.start_status_thread();
        if std::env::var_os("DC_SHOW").is_some() {
            ui.show(None);
        }
        ui
    }

    // ------------------------------------------------------------ plumbing

    fn spawn(&self, f: impl FnOnce(&EventLoopProxy<Ev>) -> Ev + Send + 'static) {
        let proxy = self.proxy.clone();
        thread::spawn(move || {
            let ev = f(&proxy);
            let _ = proxy.send_event(ev);
        });
    }

    /// Run a job on a background thread while streaming its progress to the UI.
    fn run_job(&self, kind: &'static str, job: impl FnOnce(&Progress) -> Ev + Send + 'static) {
        let progress = Arc::new(Progress::default());
        let finished = Arc::new(AtomicBool::new(false));
        let (p, f, proxy) = (progress.clone(), finished.clone(), self.proxy.clone());
        thread::spawn(move || {
            while !f.load(Ordering::Relaxed) {
                if proxy.send_event(Ev::Progress(kind, p.snapshot())).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(150));
            }
        });
        let proxy = self.proxy.clone();
        thread::spawn(move || {
            let ev = job(&progress);
            finished.store(true, Ordering::Relaxed);
            let _ = proxy.send_event(ev);
        });
    }

    fn send(&self, msg: Value) {
        if self.ready {
            let _ = self.webview.evaluate_script(&format!("window.recv({msg})"));
        }
    }

    fn toast(&self, text: impl Into<String>, error: bool) {
        self.send(json!({"t": "toast", "text": text.into(), "error": error}));
    }

    fn push_all(&self) {
        self.send(json!({"t": "home", "home": util::home(), "fda": util::has_full_disk_access()}));
        self.push_clean();
        self.push_apps();
        self.push_analyze();
        self.push_optimize();
        self.push_status();
    }

    fn start_status_thread(&self) {
        let proxy = self.proxy.clone();
        thread::spawn(move || {
            let mut mon = status::Monitor::new();
            loop {
                if proxy.send_event(Ev::Status(mon.sample(2.0))).is_err() {
                    break;
                }
                thread::sleep(Duration::from_secs(2));
            }
        });
    }

    fn start_clean_scan(&mut self) {
        if self.busy.clean_scan || self.busy.cleaning {
            return;
        }
        self.busy.clean_scan = true;
        self.push_clean();
        self.run_job("cleanScan", |p| Ev::CleanScanned(clean::scan(p)));
    }

    fn start_apps_scan(&mut self) {
        if self.busy.apps_scan {
            return;
        }
        self.busy.apps_scan = true;
        self.push_apps();
        self.run_job("appsScan", |p| Ev::AppsScanned(apps::scan(p)));
    }

    // ------------------------------------------------------------ panel

    fn show(&mut self, anchor: Option<Rect>) {
        let scale = self.window.scale_factor();
        let (mut w, mut h) = (PANEL_W * scale, PANEL_H * scale);
        let (mut x, mut y) = (400.0 * scale, 40.0 * scale);
        if let Some(r) = anchor {
            x = r.position.x + r.size.width as f64 / 2.0 - w / 2.0;
            y = r.position.y + r.size.height as f64 + 6.0 * scale;
        }
        let monitor = self.window.available_monitors().find(|m| {
            let (p, s) = (m.position(), m.size());
            x + w / 2.0 >= p.x as f64 && x + w / 2.0 < p.x as f64 + s.width as f64
        });
        if let Some(m) = monitor {
            let (p, s) = (m.position(), m.size());
            let margin = 8.0 * scale;
            h = h.min(s.height as f64 - (y - p.y as f64) - margin);
            w = w.min(s.width as f64 - 2.0 * margin);
            x = x.clamp(p.x as f64 + margin, p.x as f64 + s.width as f64 - w - margin);
        }
        self.window.set_inner_size(PhysicalSize::new(w, h));
        self.window.set_outer_position(PhysicalPosition::new(x, y));
        self.window.set_visible(true);
        self.window.set_focus();
        self.visible = true;
        self.refresh_fda();
        self.send(json!({"t": "shown", "fda": self.fda, "pinned": self.pinned}));
        // Refresh "scanned x ago" labels and anything that changed while hidden.
        self.push_status();
        self.push_clean();
        self.push_apps();
        self.push_analyze();
    }

    /// Pick up a Full Disk Access grant made while running: rescan so the Trash shows up.
    fn refresh_fda(&mut self) {
        let now = util::has_full_disk_access();
        if now && !self.fda {
            self.fda = true;
            self.start_clean_scan();
        }
        self.fda = now;
    }

    /// Restart the app (macOS sometimes applies Full Disk Access only after a relaunch).
    fn relaunch(&self) {
        let bundle = std::env::current_exe().ok().and_then(|e| e.ancestors().find(|a| a.extension().is_some_and(|x| x == "app")).map(Path::to_path_buf));
        if let Some(app) = bundle {
            self.store.save();
            let _ = std::process::Command::new("/bin/sh").arg("-c").arg("sleep 1; /usr/bin/open \"$0\"").arg(&app).spawn();
            std::process::exit(0);
        }
    }

    fn hide(&mut self) {
        if self.visible && std::env::var_os("DC_SHOW").is_none() {
            self.window.set_visible(false);
            self.visible = false;
            self.last_hide = Instant::now();
        }
    }

    // ------------------------------------------------------------ events

    pub fn handle(&mut self, ev: Ev) {
        match ev {
            Ev::Tray(TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Down, rect, .. }) => {
                if self.visible {
                    self.pinned = false;
                    self.hide();
                } else if self.last_hide.elapsed() > Duration::from_millis(300) {
                    self.show(Some(rect));
                }
            }
            Ev::Tray(_) => {}
            Ev::Menu(id) => {
                if id == self.quit_id {
                    self.store.save();
                    std::process::exit(0);
                } else if id == self.open_id {
                    let rect = self.tray.rect();
                    self.show(rect);
                }
            }
            Ev::Focus(false) if !self.pinned => self.hide(),
            Ev::Focus(_) => {}
            Ev::Ipc(body) => {
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    self.on_ipc(v);
                }
            }
            Ev::Status(snap) => self.on_status(snap),
            Ev::CleanScanned(scan) => {
                self.busy.clean_scan = false;
                self.store.clean = Some(scan);
                self.store.save();
                self.running_items = self.compute_running_items();
                self.push_clean();
            }
            Ev::Progress(kind, p) => {
                if self.visible {
                    self.send(json!({"t": "progress", "kind": kind, "p": p}));
                }
            }
            Ev::CleanDone(report, before, after) => {
                self.busy.cleaning = false;
                self.store.history.cleaned_bytes += report.freed;
                self.store.history.cleans += 1;
                self.store.save();
                let hint = report.freed > 1_000_000_000 && after.saturating_sub(before) < report.freed / 4;
                self.send(json!({
                    "t": "done", "kind": "clean", "freed": report.freed, "cleaned": report.cleaned,
                    "skipped": report.skipped_running, "refused": report.refused.len(),
                    "before": before, "after": after, "snapshotHint": hint,
                }));
                if !self.visible {
                    let msg = format!("Freed {}. Disk free: {} → {}", fmt_size(report.freed), fmt_size(before), fmt_size(after));
                    thread::spawn(move || util::notify("Clean finished", &msg));
                }
                self.start_clean_scan();
            }
            Ev::AppsScanned(scan) => {
                self.busy.apps_scan = false;
                self.store.apps = Some(scan);
                self.store.save();
                self.push_apps();
                self.push_analyze();
            }
            Ev::Uninstalled(results) => {
                self.busy.uninstalling = false;
                let mut out = vec![];
                for (name, path, res) in &results {
                    let ok = !path.exists();
                    if ok {
                        if let Some(a) = self.store.apps.as_mut() {
                            a.apps.retain(|x| &x.path != path);
                        }
                        self.store.history.uninstalled += 1;
                    }
                    out.push(json!({"name": name, "ok": ok, "trashed": res.trashed, "failed": res.failed}));
                }
                self.store.save();
                self.send(json!({"t": "done", "kind": "uninstall", "results": out}));
                self.push_apps();
                self.start_clean_scan(); // the Trash grew
            }
            Ev::AnalyzeScanned(scan) => {
                self.busy.analyzing = false;
                self.store.analyze = Some(scan);
                self.store.save();
                self.push_analyze();
            }
            Ev::Trashed(path, res) => {
                match res {
                    Ok(()) => {
                        if let Some(a) = self.store.analyze.as_mut() {
                            analyze::remove_from_tree(a, &path);
                        }
                        self.store.save();
                        self.toast(format!("Moved {} to the Trash", tilde(&path)), false);
                        self.start_clean_scan();
                    }
                    Err(e) => self.toast(e, true),
                }
                self.push_analyze();
            }
            Ev::OptimizeDone(i, res) => {
                self.busy.optimizing = None;
                if res.is_ok() {
                    self.store.history.optimized += 1;
                    self.store.save();
                }
                self.send(json!({"t": "optimized", "i": i, "ok": res.is_ok(), "error": res.err()}));
                self.push_optimize();
            }
        }
    }

    fn on_ipc(&mut self, v: Value) {
        let path = |k: &str| v[k].as_str().map(PathBuf::from);
        match v["t"].as_str().unwrap_or("") {
            "ready" => {
                self.ready = true;
                self.push_all();
                if let Ok(tab) = std::env::var("DC_TAB") {
                    self.send(json!({"t": "tab", "tab": tab}));
                }
            }
            "hide" => {
                self.pinned = false;
                self.hide();
            }
            "drag" => {
                let _ = self.window.drag_window();
                if !self.pinned {
                    self.pinned = true;
                    self.send(json!({"t": "pinned", "on": true}));
                }
            }
            "unpin" => {
                self.pinned = false;
                let rect = self.tray.rect();
                self.show(rect);
            }
            "jsError" => eprintln!("ui error: {}", v["msg"]),
            "quit" => {
                self.store.save();
                std::process::exit(0);
            }
            "rescan" => match v["what"].as_str() {
                Some("clean") => self.start_clean_scan(),
                Some("apps") => self.start_apps_scan(),
                Some("analyze") => self.start_analyze(),
                _ => {}
            },
            "select" => self.select(&v),
            "recommended" => {
                self.session_overrides.clear();
                self.store.overrides.clear();
                self.store.save();
                self.push_clean();
            }
            "clean" => self.clean(&v),
            "quitHolders" => self.quit_holders(),
            "uninstall" => self.uninstall(&v),
            "reveal" => {
                if let Some(p) = path("path") {
                    util::reveal(&p);
                }
            }
            "trash" => {
                if let Some(p) = path("path").filter(|p| self.in_analyze(p)) {
                    self.spawn(move |_| {
                        let res = safety::check_trashable(&p).and_then(|_| util::move_to_trash(&p));
                        Ev::Trashed(p, res)
                    });
                }
            }
            "disableStartup" => {
                if let Some(p) = path("path") {
                    let listed = apps::startup_items().iter().any(|s| s.user && s.path == p);
                    let check = safety::check_user_launch_agent(&p).and_then(|_| if listed { Ok(()) } else { Err("not a listed startup item".into()) });
                    if check.is_ok() {
                        let uid = unsafe { libc::getuid() };
                        let _ = util::run("/bin/launchctl", &["bootout", &format!("gui/{uid}"), &p.to_string_lossy()]);
                    }
                    match check.and_then(|_| util::move_to_trash(&p)) {
                        Ok(()) => self.toast("Startup item disabled and moved to the Trash", false),
                        Err(e) => self.toast(e, true),
                    }
                    self.push_apps();
                }
            }
            "optimize" => {
                let i = v["i"].as_u64().unwrap_or(u64::MAX) as usize;
                if i < optimize::TASKS.len() && self.busy.optimizing.is_none() {
                    self.busy.optimizing = Some(i);
                    self.spawn(move |_| Ev::OptimizeDone(i, optimize::run(&optimize::TASKS[i])));
                }
            }
            "relaunch" => self.relaunch(),
            "open" => match v["what"].as_str() {
                Some("fda") => util::open("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"),
                Some("login") => util::open("x-apple.systempreferences:com.apple.LoginItems-Settings.extension"),
                _ => {}
            },
            _ => {}
        }
    }

    fn on_status(&mut self, snap: Snapshot) {
        let pct_used = 100.0 - snap.free as f64 / snap.total.max(1) as f64 * 100.0;
        self.tray.set_title(Some(format!(" {}", fmt_size(snap.free))));
        if pct_used as i32 != self.last_icon_pct {
            self.last_icon_pct = pct_used as i32;
            let _ = self.tray.set_icon_templated(Some(icon::disk_pie(pct_used / 100.0)));
        }
        push_capped(&mut self.hist.cpu, snap.cpu);
        push_capped(&mut self.hist.mem, (snap.mem_used as f64 / snap.mem_total.max(1) as f64 * 100.0) as f32);
        push_capped(&mut self.hist.down, snap.net_down);
        push_capped(&mut self.hist.up, snap.net_up);
        self.snap = snap;
        let running = self.compute_running_items();
        if running != self.running_items {
            self.running_items = running;
            if self.visible {
                self.push_clean();
            }
        }
        if self.visible {
            if !self.fda {
                self.refresh_fda();
                if self.fda {
                    self.send(json!({"t": "home", "home": util::home(), "fda": true}));
                }
            }
            self.push_status();
        }
    }

    // ------------------------------------------------------------ status

    fn push_status(&self) {
        let s = &self.snap;
        let (score, label) = s.health();
        let h = &self.store.history;
        self.send(json!({
            "t": "status",
            "score": score, "label": label, "machine": s.machine, "uptime": util::fmt_duration(s.uptime),
            "cpu": s.cpu, "load": s.load, "cores": s.cores,
            "memUsed": s.mem_used, "memTotal": s.mem_total, "swap": s.swap_used,
            "free": s.free, "total": s.total,
            "down": s.net_down, "up": s.net_up,
            "battery": s.battery,
            "top": s.top.iter().map(|(n, m, c)| json!([n, m, c])).collect::<Vec<_>>(),
            "hist": {"cpu": self.hist.cpu, "mem": self.hist.mem, "down": self.hist.down, "up": self.hist.up},
            "history": {"cleaned": h.cleaned_bytes, "uninstalled": h.uninstalled, "optimized": h.optimized},
        }));
    }

    // ------------------------------------------------------------ clean

    fn compute_running_items(&self) -> HashSet<usize> {
        let Some(scan) = &self.store.clean else { return HashSet::new() };
        if self.snap.running.ids.is_empty() {
            return HashSet::new();
        }
        scan.items.iter().enumerate().filter(|(_, it)| clean::is_running(it, &self.snap.running)).map(|(i, _)| i).collect()
    }

    fn is_selected(&self, i: usize, it: &Item) -> bool {
        let key = it.path.to_string_lossy();
        !self.running_items.contains(&i)
            && self.session_overrides.get(&*key).or(self.store.overrides.get(&*key)).copied().unwrap_or(it.recommended)
    }

    /// Running GUI apps that hold at least one cache in the scan: (name, bundle id).
    fn holders(&self) -> Vec<(String, String)> {
        let Some(scan) = &self.store.clean else { return vec![] };
        let mut out: Vec<(String, String)> = self
            .snap
            .gui_apps
            .iter()
            .filter(|(_, id, ids)| {
                !id.eq_ignore_ascii_case("com.local.diskcleaner")
                    && self.running_items.iter().any(|i| scan.items[*i].owners.iter().any(|o| ids.contains(o)))
            })
            .map(|(n, id, _)| (n.clone(), id.clone()))
            .collect();
        out.sort();
        out
    }

    fn push_clean(&self) {
        let Some(scan) = &self.store.clean else {
            self.send(json!({"t": "clean", "scan": null, "busy": self.busy.clean_scan}));
            return;
        };
        let cats: Vec<Value> = Category::ALL
            .iter()
            .map(|cat| {
                let items: Vec<Value> = scan
                    .items
                    .iter()
                    .enumerate()
                    .filter(|(_, it)| it.category == *cat)
                    .map(|(i, it)| {
                        json!({
                            "i": i, "label": it.label, "path": tilde(&it.path), "size": it.size,
                            "sel": self.is_selected(i, it), "rec": it.recommended,
                            "running": self.running_items.contains(&i), "note": it.note, "mtime": it.mtime,
                        })
                    })
                    .collect();
                json!({"key": format!("{cat:?}"), "title": cat.title(), "blurb": cat.blurb(), "items": items})
            })
            .filter(|c| !c["items"].as_array().unwrap().is_empty())
            .collect();
        self.send(json!({
            "t": "clean", "scan": scan.scanned_at, "ago": fmt_ago(scan.scanned_at), "cats": cats,
            "holders": self.holders().into_iter().map(|h| h.0).collect::<Vec<_>>(),
            "busy": self.busy.clean_scan, "cleaning": self.busy.cleaning,
        }));
    }

    /// Only indices into the current scan are accepted; the UI never sends paths to delete.
    fn indices(&self, v: &Value) -> Option<Vec<usize>> {
        let scan = self.store.clean.as_ref()?;
        if v["scan"].as_u64() != Some(scan.scanned_at) {
            self.toast("The scan was refreshed in the meantime. Please review again.", true);
            self.push_clean();
            return None;
        }
        Some(v["items"].as_array()?.iter().filter_map(|x| x.as_u64()).map(|x| x as usize).filter(|i| *i < scan.items.len()).collect())
    }

    fn select(&mut self, v: &Value) {
        let Some(idx) = self.indices(v) else { return };
        let on = v["on"].as_bool().unwrap_or(false);
        let Some(scan) = &self.store.clean else { return };
        for i in idx {
            let it = &scan.items[i];
            let key = it.path.to_string_lossy().into_owned();
            // Emptying the Trash or deleting installers is never remembered as a default.
            if matches!(it.category, Category::Trash | Category::Installers) {
                self.session_overrides.insert(key, on);
            } else {
                self.store.overrides.insert(key, on);
            }
        }
        self.store.save();
    }

    fn clean(&mut self, v: &Value) {
        let abort = |ui: &Self, why: &str| {
            ui.toast(why, true);
            ui.send(json!({"t": "aborted"}));
        };
        if self.busy.cleaning || self.busy.clean_scan {
            return abort(self, "A scan is still running. Try again in a moment.");
        }
        let Some(idx) = self.indices(v) else { return self.send(json!({"t": "aborted"})) };
        let scan = self.store.clean.as_ref().unwrap();
        let items: Vec<Item> = idx.into_iter().filter(|i| !self.running_items.contains(i)).map(|i| scan.items[i].clone()).collect();
        if items.is_empty() {
            return abort(self, "Nothing to clean: the selected items are in use.");
        }
        self.busy.cleaning = true;
        self.run_job("clean", move |p| {
            let before = util::disk_space().0;
            let running = status::running_now();
            p.set_current("Checking which files are in use…");
            let ctx = safety::Ctx::new();
            let mut total = clean::Report { freed: 0, cleaned: 0, skipped_running: vec![], refused: vec![] };
            // Trash first, then one category at a time so the UI can show progress.
            let order = [Category::Trash].into_iter().chain(Category::ALL.into_iter().filter(|c| *c != Category::Trash));
            let groups: Vec<(Category, Vec<Item>)> = order
                .map(|cat| (cat, items.iter().filter(|i| i.category == cat).cloned().collect::<Vec<_>>()))
                .filter(|(_, g)| !g.is_empty())
                .collect();
            p.total.store(items.len() as u64, Ordering::Relaxed);
            for (cat, _) in &groups {
                p.add_to_group(cat.title(), 0, false);
            }
            for (cat, g) in groups {
                let r = clean::clean(&g, &running, &ctx, p);
                p.add_to_group(cat.title(), 0, true);
                total.freed += r.freed;
                total.cleaned += r.cleaned;
                total.skipped_running.extend(r.skipped_running);
                total.refused.extend(r.refused);
            }
            Ev::CleanDone(total, before, util::disk_space().0)
        });
    }

    /// Politely ask apps that hold caches to quit (same as choosing Quit in the app).
    fn quit_holders(&mut self) {
        let ids: Vec<String> = self.holders().into_iter().map(|h| h.1).collect();
        thread::spawn(move || {
            for id in ids {
                let _ = util::run("/usr/bin/osascript", &["-e", "on run argv", "-e", "tell application id (item 1 of argv) to quit", "-e", "end run", &id]);
            }
        });
        self.toast("Asked the apps to quit. Their caches unlock once they close.", false);
    }

    // ------------------------------------------------------------ apps

    fn app_running(&self, app: &App) -> bool {
        app.ids().iter().any(|id| self.snap.running.ids.contains(id))
    }

    fn push_apps(&self) {
        let startup: Vec<Value> = apps::startup_items()
            .into_iter()
            .map(|s| json!({"path": s.path, "tilde": tilde(&s.path), "label": s.label, "user": s.user}))
            .collect();
        let Some(scan) = &self.store.apps else {
            self.send(json!({"t": "apps", "scan": null, "busy": self.busy.apps_scan, "startup": startup}));
            return;
        };
        let list: Vec<Value> = scan
            .apps
            .iter()
            .map(|a| {
                let mut data = a.data.clone();
                data.sort_by(|x, y| y.1.cmp(&x.1));
                json!({
                    "path": a.path, "name": a.name, "id": a.bundle_id, "version": a.version,
                    "size": a.size, "data": a.data_size(),
                    "dataItems": data.iter().map(|(p, s)| json!({"path": p, "tilde": tilde(p), "size": s})).collect::<Vec<_>>(),
                    "lastUsed": a.last_used, "lastUsedAgo": a.last_used.map(fmt_ago),
                    "running": self.app_running(a), "menuBar": a.menu_bar, "locked": a.locked,
                    "icon": apps::icon_file(&a.bundle_id).filter(|p| p.exists()).map(|_| format!("dc://localhost/icon/{}.png", a.bundle_id)),
                })
            })
            .collect();
        self.send(json!({
            "t": "apps", "scan": scan.scanned_at, "ago": fmt_ago(scan.scanned_at), "apps": list,
            "busy": self.busy.apps_scan, "uninstalling": self.busy.uninstalling, "startup": startup,
        }));
    }

    fn uninstall(&mut self, v: &Value) {
        if self.busy.uninstalling {
            return;
        }
        let Some(scan) = &self.store.apps else { return };
        if util::now().saturating_sub(scan.scanned_at) > 600 || self.busy.apps_scan {
            // Never act on an old list: refresh it and let the user confirm again.
            self.send(json!({"t": "uninstallBlocked", "names": [], "stale": true}));
            self.start_apps_scan();
            return;
        }
        let wanted: Vec<PathBuf> = v["paths"].as_array().map(|a| a.iter().filter_map(|p| p.as_str().map(PathBuf::from)).collect()).unwrap_or_default();
        // Only apps from our own scan, never arbitrary paths.
        let chosen: Vec<App> = scan.apps.iter().filter(|a| wanted.contains(&a.path)).cloned().collect();
        let running_now = status::running_now();
        let (running, ok): (Vec<App>, Vec<App>) =
            chosen.into_iter().partition(|a| running_now.holds(&a.ids(), &a.path));
        if !running.is_empty() {
            let names: Vec<_> = running.iter().map(|a| a.name.clone()).collect();
            self.send(json!({"t": "uninstallBlocked", "names": names}));
            return;
        }
        if ok.is_empty() {
            return;
        }
        self.busy.uninstalling = true;
        self.run_job("uninstall", move |p| {
            p.total.store(ok.len() as u64, Ordering::Relaxed);
            let mut results = vec![];
            for app in &ok {
                p.set_current(format!("Moving {} and its data to the Trash…", app.name));
                let r = apps::uninstall(app);
                p.add_to_group(&app.name, r.trashed, true);
                p.bytes.fetch_add(r.trashed, Ordering::Relaxed);
                p.done.fetch_add(1, Ordering::Relaxed);
                results.push((app.name.clone(), app.path.clone(), r));
            }
            Ev::Uninstalled(results)
        });
    }

    // ------------------------------------------------------------ analyze

    fn start_analyze(&mut self) {
        if self.busy.analyzing {
            return;
        }
        self.busy.analyzing = true;
        self.push_analyze();
        self.run_job("analyze", |p| Ev::AnalyzeScanned(analyze::scan(p)));
    }

    /// Only paths that are shown in Analyze (tree or large files) can be trashed from it.
    fn in_analyze(&self, p: &Path) -> bool {
        let Some(scan) = &self.store.analyze else { return false };
        if scan.large_files.iter().any(|(f, _)| f == p) {
            return true;
        }
        let Ok(rel) = p.strip_prefix(util::home()) else { return false };
        let mut node = &scan.root;
        for name in rel.components().map(|c| c.as_os_str().to_string_lossy()) {
            match node.children.iter().find(|c| c.other == 0 && c.name == name) {
                Some(n) => node = n,
                None => return false,
            }
        }
        !rel.as_os_str().is_empty()
    }

    fn push_analyze(&self) {
        let (free, total) = util::disk_space();
        let used = total.saturating_sub(free);
        let apps: u64 = self.store.apps.as_ref().map(|a| a.apps.iter().filter(|x| x.path.starts_with("/Applications")).map(|x| x.size).sum()).unwrap_or(0);
        let Some(scan) = &self.store.analyze else {
            self.send(json!({"t": "analyze", "scan": null, "busy": self.busy.analyzing, "disk": {"free": free, "total": total, "used": used, "apps": apps}}));
            return;
        };
        let home = scan.root.size;
        self.send(json!({
            "t": "analyze", "scan": scan.scanned_at, "ago": fmt_ago(scan.scanned_at), "busy": self.busy.analyzing,
            "disk": {"free": free, "total": total, "used": used, "home": home, "apps": apps, "other": used.saturating_sub(home).saturating_sub(apps)},
            "root": node_json(&scan.root, util::home()),
            "large": scan.large_files.iter().map(|(p, s)| json!({
                "path": p, "tilde": tilde(p), "name": p.file_name().map(|n| n.to_string_lossy().into_owned()), "size": s,
                "locked": safety::check_trashable(p).err(),
            })).collect::<Vec<_>>(),
        }));
    }

    // ------------------------------------------------------------ optimize

    fn push_optimize(&self) {
        let snapshots = optimize::local_snapshot_count();
        let tasks: Vec<Value> = optimize::TASKS
            .iter()
            .enumerate()
            .map(|(i, t)| json!({"i": i, "title": t.title, "detail": t.detail, "admin": t.admin, "cmd": t.shell}))
            .collect();
        self.send(json!({"t": "optimize", "tasks": tasks, "snapshots": snapshots, "busy": self.busy.optimizing}));
    }
}

/// Tree for the UI: n=name, s=size, d=is dir, o=folded "other" count, l=why locked, c=children.
fn node_json(node: &Node, path: &Path) -> Value {
    let kids: Vec<Value> = node
        .children
        .iter()
        .map(|c| if c.other > 0 { json!({"n": "", "s": c.size, "o": c.other}) } else { node_json(c, &path.join(&c.name)) })
        .collect();
    let locked = if path == util::home() { Some("home".to_string()) } else { safety::check_trashable(path).err() };
    json!({"n": node.name, "s": node.size, "d": node.is_dir, "l": locked, "c": kids})
}

/// Serves the UI page and cached app icons on the private `dc://` scheme.
fn serve(req: Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    const PAGE: &str = include_str!("ui/index.html");
    let not_found = || Response::builder().status(404).body(Cow::Borrowed(&[][..])).unwrap();
    let path = req.uri().path();
    let (ctype, body): (&str, Cow<'static, [u8]>) = if path == "/" || path == "/index.html" {
        ("text/html; charset=utf-8", Cow::Borrowed(PAGE.as_bytes()))
    } else if let Some(id) = path.strip_prefix("/icon/").and_then(|p| p.strip_suffix(".png")) {
        match apps::icon_file(id).and_then(|f| std::fs::read(f).ok()) {
            Some(bytes) => ("image/png", Cow::Owned(bytes)),
            None => return not_found(),
        }
    } else {
        return not_found();
    };
    Response::builder().header("Content-Type", ctype).body(body).unwrap()
}
