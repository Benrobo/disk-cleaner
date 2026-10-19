mod analyze;
mod apps;
mod clean;
mod icon;
mod optimize;
mod safety;
mod status;
mod store;
mod ui;
mod util;

use tao::event::{Event, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
use tray_icon::TrayIconEvent;
use tray_icon::menu::MenuEvent;
use ui::{Ev, Ui};
use util::fmt_size;

fn main() {
    if std::env::args().any(|a| a == "--analyze-report") {
        let t = std::time::Instant::now();
        let a = analyze::scan(&util::Progress::default());
        let nodes = count(&a.root);
        println!("Home {} scanned in {:.2?}, {nodes} nodes kept", fmt_size(a.root.size), t.elapsed());
        for c in &a.root.children {
            println!("   {:>9}  {}", fmt_size(c.size), if c.other > 0 { format!("{} smaller items", c.other) } else { c.name.clone() });
        }
        for (p, s) in a.large_files.iter().take(8) {
            println!("   file {:>9}  {}", fmt_size(*s), util::tilde(p));
        }
        return;
    }
    if let Some(i) = std::env::args().position(|a| a == "--trash-report") {
        // Read-only diagnosis of what emptying the Trash would skip. Writes to the given file.
        let out_path = std::env::args().nth(i + 1).unwrap_or("/tmp/dc-trash-report.txt".into());
        let trash = util::h(".Trash");
        let ctx = safety::Ctx { trash: true, ..safety::Ctx::new() };
        let running = status::running_now();
        let mut lines = vec![format!("fda={} open_files={}", util::has_full_disk_access(), ctx.open.len())];
        lines.push(format!("trash in use by a process: {}", running.paths.iter().any(|p| p.starts_with(&trash))));
        use std::os::unix::fs::MetadataExt;
        let dev = std::fs::metadata(&trash).map(|m| m.dev()).unwrap_or(0);
        match std::fs::read_dir(&trash) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let p = e.path();
                    let guard = safety::check_trash_item(&p).err().unwrap_or_else(|| "ok".into());
                    lines.push(format!("ITEM {} | symlink={} | guard={guard} | size={}", p.display(), e.file_type().map(|t| t.is_symlink()).unwrap_or(false), util::size_of(&p)));
                    let mut why = vec![];
                    safety::diagnose(&p, &ctx, &mut why, dev as u64);
                    for w in why.iter().take(40) {
                        lines.push(format!("    {w}"));
                    }
                }
            }
            Err(e) => lines.push(format!("cannot read Trash: {e}")),
        }
        let _ = std::fs::write(out_path, lines.join("\n"));
        return;
    }
    if std::env::args().any(|a| a == "--report") {
        return report();
    }
    if !single_instance() {
        eprintln!("Disk Cleaner is already running.");
        return;
    }

    let mut event_loop = EventLoopBuilder::<Ev>::with_user_event().build();
    event_loop.set_activation_policy(ActivationPolicy::Accessory); // menu bar only, no Dock icon
    let proxy = event_loop.create_proxy();
    let p = proxy.clone();
    MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
        let _ = p.send_event(Ev::Menu(e.id));
    }));
    let p = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
        let _ = p.send_event(Ev::Tray(e));
    }));

    let mut ui: Option<Ui> = None;
    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => ui = Some(Ui::new(proxy.clone(), target)),
            Event::WindowEvent { event: WindowEvent::Focused(f), .. } => {
                if let Some(ui) = ui.as_mut() {
                    ui.handle(Ev::Focus(f));
                }
            }
            Event::UserEvent(ev) => {
                if let Some(ui) = ui.as_mut() {
                    ui.handle(ev);
                }
            }
            _ => {}
        }
    });
}

/// Hold an exclusive lock for the life of the process so only one menu bar icon exists.
fn single_instance() -> bool {
    use std::os::fd::AsRawFd;
    let dir = util::h("Library/Application Support/DiskCleaner");
    let _ = std::fs::create_dir_all(&dir);
    let Ok(file) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("lock")) else { return true };
    let ok = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    std::mem::forget(file);
    ok
}

/// `disk-cleaner --report`: print what would be cleaned. Read-only, deletes nothing.
fn report() {
    let t = std::time::Instant::now();
    let scan = clean::scan(&util::Progress::default());
    println!("Clean scan: {} items in {:.2?}\n", scan.items.len(), t.elapsed());
    let running = status::running_now();
    for cat in clean::Category::ALL {
        let items: Vec<_> = scan.items.iter().filter(|i| i.category == cat).collect();
        if items.is_empty() {
            continue;
        }
        let total: u64 = items.iter().map(|i| i.size).sum();
        let rec: u64 = items.iter().filter(|i| i.recommended).map(|i| i.size).sum();
        println!("== {} — {} total, {} recommended ({} items)", cat.title(), fmt_size(total), fmt_size(rec), items.len());
        for it in items.iter().take(12) {
            let flags = format!(
                "{}{}{}",
                if it.recommended { "" } else { " [off]" },
                if clean::is_running(it, &running) { " [in use]" } else { "" },
                if safety::check_cleanable(&it.path).is_err() && it.mode != clean::Mode::EmptyTrash { " [REFUSED BY GUARD]" } else { "" }
            );
            println!("   {:>9}  {}  ({}){flags}", fmt_size(it.size), it.label, util::tilde(&it.path));
        }
        if items.len() > 12 {
            println!("   … {} more", items.len() - 12);
        }
    }
    let refused: Vec<_> = scan.items.iter().filter(|i| i.mode != clean::Mode::EmptyTrash && safety::check_cleanable(&i.path).is_err()).collect();
    println!("\nSafety guard would refuse {} of {} items", refused.len(), scan.items.len());
    for i in refused {
        println!("   {} -> {}", util::tilde(&i.path), safety::check_cleanable(&i.path).unwrap_err());
    }
    let t = std::time::Instant::now();
    let apps = apps::scan(&util::Progress::default());
    println!("\nApps: {} in {:.2?}", apps.apps.len(), t.elapsed());
    for a in apps.apps.iter().take(15) {
        println!(
            "   {:>9}  +{:>9} data  {} {} {}",
            fmt_size(a.size),
            fmt_size(a.data_size()),
            a.name,
            a.last_used.map(util::fmt_ago).unwrap_or_default(),
            a.locked.as_deref().unwrap_or("")
        );
        for (p, s) in &a.data {
            println!("              {:>9}  {}", fmt_size(*s), util::tilde(p));
        }
    }
}

fn count(n: &analyze::Node) -> usize {
    1 + n.children.iter().map(count).sum::<usize>()
}
