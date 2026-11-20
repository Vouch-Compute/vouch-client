//! Grep test: after an enrollment and a weekly hardware report in a test profile, no raw hardware identifier
//! (MAC in any notation, serials, SMBIOS UUID, OS install id, GPU UUID) appears in any file of the data dir (state,
//! tokens, keys, models, logs), in the agent's log output at the most verbose level, or in a crash dump (the agent
//! writes none and turns off crash-dump heap capture, `hwids::disable_crash_dumps`). The fixture values are sentinels
//! so the test cannot be fooled by unrelated data.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::*;
use pool_proto::now_ms;
use serde_json::json;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn all_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            all_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_raw_identifier_on_disk_in_logs_or_dumps() {
    let logs = Captured::default();
    let sink = logs.clone();
    tracing_subscriber::fmt().with_env_filter("trace").with_ansi(false).with_writer(move || sink.clone()).init();

    let data = tempfile::tempdir().unwrap();
    let (v, agent) = enrolled(data.path()).await;
    // a weekly report: due after a week
    let p = data.path().join("state.json");
    let mut st: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    st["hw_report_last_sent_ms"] = json!(now_ms() - 8 * 24 * 3600 * 1000);
    std::fs::write(&p, serde_json::to_vec(&st).unwrap()).unwrap();
    let url = agent.cfg.vault_url.clone();
    drop(agent);
    let agent = new_agent(data.path(), &url);
    assert!(agent.hw_report_tick().await.unwrap());
    assert_eq!(v.hw_reports.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(v.problems.lock().unwrap().is_empty(), "{:?}", v.problems.lock().unwrap());
    // the identifiers really were sent (the server received them; the mock checked the closed map and signature)
    assert!(v.registered.lock().unwrap().as_ref().unwrap()["hw_ids"].as_str().is_some_and(|s| s.len() > 100));

    let mac = [0x00u8, 0x1b, 0x21, 0xaa, 0x3f, 0x9a];
    let sentinels: Vec<Vec<u8>> = [
        "BOARD-SENTINEL-7731",
        "GPU-SENTINEL-1c2d",
        "4C4C4544-0039-4810-8052-B4C04F4A3533",
        "6f9619ff-8b86-d011-b42d-00c04fc964ff",
        "00:1b:21:aa:3f:9a",
        "00-1b-21-aa-3f-9a",
        "001b21aa3f9a",
        "1b:21:aa",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .chain([mac.to_vec()])
    .collect();

    let mut files = vec![];
    all_files(data.path(), &mut files);
    assert!(files.iter().any(|f| f.ends_with("state.json")));
    for f in &files {
        let b = std::fs::read(f).unwrap();
        for s in &sentinels {
            assert!(!contains(&b, s), "raw identifier {:?} in {}", String::from_utf8_lossy(s), f.display());
        }
        let name = f.to_string_lossy().to_lowercase();
        assert!(!(name.ends_with(".dmp") || name.contains("core.")), "crash dump in the data dir: {name}");
    }
    let log = logs.0.lock().unwrap().clone();
    assert!(contains(&log, b"hardware identifiers:"), "the collection was logged (as counts)");
    for s in &sentinels {
        assert!(!contains(&log, s), "raw identifier {:?} in the logs", String::from_utf8_lossy(s));
    }
    // the masked form is fine (it is what the server and admins see)
    assert!(!contains(&log, b"3f:9a") || contains(&log, b"**:**:**:**:3f:9a"));
}
