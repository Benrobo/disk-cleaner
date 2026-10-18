//! Analyze: a size tree of the home folder (pruned to what matters) plus the largest files.

use crate::util::{self, Progress, home};
use std::sync::atomic::Ordering;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Keep nodes at least this big in the tree.
const MIN_NODE: u64 = 50_000_000;
const MAX_DEPTH: usize = 6;
const MAX_CHILDREN: usize = 20;
const LARGE_FILE: u64 = 200_000_000;
const MAX_LARGE_FILES: usize = 40;
/// Not walked: cloud placeholders would trigger network enumeration.
const SKIP: &[&str] = &["Library/CloudStorage"];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Node {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    /// Number of entries folded into this node when it is the "other items" bucket.
    pub other: u32,
    pub children: Vec<Node>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AnalyzeScan {
    pub root: Node,
    pub large_files: Vec<(PathBuf, u64)>,
    pub scanned_at: u64,
}

pub fn scan(p: &Progress) -> AnalyzeScan {
    let large = Mutex::new(Vec::new());
    let root = home();
    let dev = fs::symlink_metadata(root).map(|m| m.dev()).unwrap_or(0);
    p.total.store(fs::read_dir(root).map(|r| r.count() as u64).unwrap_or(0), Ordering::Relaxed);
    let mut node = walk(root, "~".into(), 0, dev, &large, p);
    node.name = "Home".into();
    let mut large_files = large.into_inner().unwrap();
    large_files.sort_by(|a: &(PathBuf, u64), b| b.1.cmp(&a.1));
    large_files.truncate(MAX_LARGE_FILES);
    AnalyzeScan { root: node, large_files, scanned_at: util::now() }
}

fn walk(path: &Path, name: String, depth: usize, dev: u64, large: &Mutex<Vec<(PathBuf, u64)>>, p: &Progress) -> Node {
    let rel = path.strip_prefix(home()).unwrap_or(path);
    if SKIP.iter().any(|s| rel == Path::new(s)) {
        return Node { name: format!("{name} (cloud, not scanned)"), size: 0, is_dir: true, other: 0, children: vec![] };
    }
    let entries: Vec<fs::DirEntry> = fs::read_dir(path).map(|rd| rd.flatten().collect()).unwrap_or_default();
    p.files.fetch_add(entries.len() as u64, Ordering::Relaxed);
    if depth <= 3 {
        p.set_current(util::tilde(path));
    }
    let mut children: Vec<Node> = entries
        .par_iter()
        .filter_map(|e| {
            let md = e.metadata().ok()?; // lstat: never follows symlinks
            let name = e.file_name().to_string_lossy().into_owned();
            let own = md.blocks() * 512;
            if md.is_dir() {
                if md.dev() != dev {
                    return None;
                }
                let mut n = walk(&e.path(), name, depth + 1, dev, large, p);
                n.size += own;
                p.bytes.fetch_add(own, Ordering::Relaxed);
                if depth == 0 {
                    p.add_to_group(&n.name, n.size, true);
                    p.done.fetch_add(1, Ordering::Relaxed);
                }
                Some(n)
            } else {
                p.bytes.fetch_add(own, Ordering::Relaxed);
                if depth == 0 {
                    p.done.fetch_add(1, Ordering::Relaxed);
                }
                if own >= LARGE_FILE && md.is_file() {
                    large.lock().unwrap().push((e.path(), own));
                }
                Some(Node { name, size: own, is_dir: false, other: 0, children: vec![] })
            }
        })
        .collect();
    let size = children.iter().map(|c| c.size).sum();
    children.sort_by(|a, b| b.size.cmp(&a.size));
    prune(&mut children, depth);
    Node { name, size, is_dir: true, other: 0, children }
}

/// Keep the biggest children; fold the rest into one "other items" node.
fn prune(children: &mut Vec<Node>, depth: usize) {
    if depth >= MAX_DEPTH {
        let (n, s) = (children.len() as u32, children.iter().map(|c| c.size).sum());
        children.clear();
        if n > 0 {
            children.push(Node { name: String::new(), size: s, is_dir: false, other: n, children: vec![] });
        }
        return;
    }
    let keep = children.iter().take(MAX_CHILDREN).take_while(|c| c.size >= MIN_NODE).count();
    let rest: Vec<Node> = children.drain(keep..).collect();
    if !rest.is_empty() {
        let s = rest.iter().map(|c| c.size).sum();
        children.push(Node { name: String::new(), size: s, is_dir: false, other: rest.len() as u32, children: vec![] });
    }
}

/// After trashing `path`, remove it from the cached tree and fix up ancestor sizes.
pub fn remove_from_tree(scan: &mut AnalyzeScan, path: &Path) {
    scan.large_files.retain(|(p, _)| !p.starts_with(path));
    let Ok(rel) = path.strip_prefix(home()) else { return };
    let names: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    fn go(node: &mut Node, names: &[String]) -> u64 {
        let Some(idx) = node.children.iter().position(|c| c.other == 0 && c.name == names[0]) else { return 0 };
        let removed = if names.len() == 1 { node.children.remove(idx).size } else { go(&mut node.children[idx], &names[1..]) };
        node.size = node.size.saturating_sub(removed);
        removed
    }
    if !names.is_empty() {
        go(&mut scan.root, &names);
    }
}
