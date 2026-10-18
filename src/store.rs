//! Persistent cache: last scan results (shown instantly on launch), your manual
//! selections, and cleaning history. Stored in ~/Library/Application Support/DiskCleaner.

use crate::{analyze::AnalyzeScan, apps::AppsScan, clean::CleanScan, util::h};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Serialize, Deserialize, Default)]
pub struct History {
    pub cleaned_bytes: u64,
    pub cleans: u32,
    pub uninstalled: u32,
    pub optimized: u32,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Store {
    pub clean: Option<CleanScan>,
    pub apps: Option<AppsScan>,
    pub analyze: Option<AnalyzeScan>,
    /// Item path -> selected, for items you changed by hand. Survives rescans.
    pub overrides: HashMap<String, bool>,
    pub history: History,
}

const VERSION: u32 = 1;

fn path() -> std::path::PathBuf {
    h("Library/Application Support/DiskCleaner/state.json")
}

impl Store {
    pub fn load() -> Store {
        #[derive(Deserialize)]
        struct Versioned {
            version: u32,
            store: Store,
        }
        fs::read(path())
            .ok()
            .and_then(|b| serde_json::from_slice::<Versioned>(&b).ok())
            .filter(|v| v.version == VERSION)
            .map(|v| v.store)
            .unwrap_or_default()
    }

    pub fn save(&self) {
        #[derive(Serialize)]
        struct Versioned<'a> {
            version: u32,
            store: &'a Store,
        }
        let p = path();
        let _ = fs::create_dir_all(p.parent().unwrap());
        if let Ok(json) = serde_json::to_vec(&Versioned { version: VERSION, store: self }) {
            // Write then rename so a crash never leaves a half-written file.
            let tmp = p.with_extension("tmp");
            if fs::write(&tmp, json).is_ok() {
                let _ = fs::rename(tmp, p);
            }
        }
    }
}
