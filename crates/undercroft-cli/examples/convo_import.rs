//! Parse a Claude Code-style JSONL transcript and file one verbatim drawer
//! per prose message (what `undercroft sweep` does, via the library API).
//!
//! Run: cargo run -p undercroft-cli --example convo_import

use undercroft_core::{convo, normalize_content, Drawer};
use undercroft_store::PalaceStore;
use undercroft_vault::{SecurityLevel, VaultManager};

const TRANSCRIPT: &str = r#"{"type":"user","message":{"role":"user","content":"what did we decide about caching?"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"We cache at the edge with a 5 minute TTL; stale-while-revalidate covers spikes."}]}}"#;

fn main() -> anyhow::Result<()> {
    let dir = tempfile::TempDir::new()?;
    let manager = VaultManager::open(dir.path(), None)?;
    let mut store = PalaceStore::open(manager.create("convos", SecurityLevel::Sealed)?)?;

    for msg in convo::parse_transcript(TRANSCRIPT) {
        let who = if msg.role == "user" {
            "User"
        } else {
            "Assistant"
        };
        let drawer = Drawer::new(
            "claude-code",
            "session-demo",
            normalize_content(&format!("{who}: {}", msg.text)),
            Some("demo.jsonl".into()),
            msg.line,
            "sweeper",
        );
        store.upsert(&drawer)?;
        println!("filed line {} as {}", msg.line, drawer.id);
    }
    println!("total drawers: {}", store.count()?);
    Ok(())
}
