//! Whole-lifecycle example against the library API:
//! palace → vault → drawers → search → verify.
//!
//! Run: cargo run -p undercroft-cli --example basic_mining

use undercroft_core::Drawer;
use undercroft_store::{PalaceStore, SearchOptions};
use undercroft_vault::{SecurityLevel, VaultManager};

fn main() -> anyhow::Result<()> {
    let dir = tempfile::TempDir::new()?;
    let manager = VaultManager::open(dir.path(), None)?;
    let vault = manager.create("example", SecurityLevel::Sealed)?;
    let mut store = PalaceStore::open(vault)?;

    let notes = [
        (
            "backend",
            "decisions",
            "We chose GraphQL over REST because mobile needed fewer round trips.",
        ),
        (
            "backend",
            "infra",
            "Postgres 16 migration completed; pgbouncer pools at 200.",
        ),
        (
            "team",
            "rituals",
            "Retro every second Friday; demos on Thursdays.",
        ),
    ];
    for (i, (wing, room, text)) in notes.iter().enumerate() {
        let drawer = Drawer::new(wing, room, text.to_string(), None, i as u32, "example");
        store.upsert(&drawer)?;
    }

    let hits = store.search("why did we pick graphql", &SearchOptions::default())?;
    println!(
        "top hit: [{}] {}",
        hits[0].drawer.meta.room, hits[0].drawer.content
    );

    let report = store.verify()?;
    println!(
        "verified {} records, chain ok: {}",
        report.records_checked, report.chain_ok
    );
    Ok(())
}
