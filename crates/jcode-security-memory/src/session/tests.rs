use super::*;
use crate::{StoreFilter, load_store, merge_entry, save_store};
use anyhow::Result;
use jcode_memory_types::{MemoryCategory, MemoryEntry};
use serde_json::json;
use std::path::Path;
use std::sync::{
    Condvar,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

struct Backend;
impl MemoryBackend for Backend {
    fn remember(&self, path: &Path, entry: MemoryEntry) -> Result<String> {
        Ok(self.remember_batch(path, vec![entry])?.remove(0))
    }
    fn remember_batch(&self, path: &Path, entries: Vec<MemoryEntry>) -> Result<Vec<String>> {
        let mut graph = load_store(path)?;
        let ids = entries
            .into_iter()
            .map(|entry| merge_entry(&mut graph, entry))
            .collect();
        save_store(path, &graph)?;
        Ok(ids)
    }
    fn retrieve(
        &self,
        path: &Path,
        _: &str,
        limit: usize,
        filter: &StoreFilter,
    ) -> Result<Vec<MemoryEntry>> {
        Ok(load_store(path)?
            .active_memories()
            .filter(|e| filter.matches(e))
            .take(limit)
            .cloned()
            .collect())
    }
}

fn options(dir: &Path, mode: super::super::MemoryMode) -> SecurityMemoryOptions {
    SecurityMemoryOptions {
        mode,
        path: Some(dir.join("snapshot.json")),
        delta: Some(dir.join("delta.json")),
        role: "attacker".into(),
        code: "v1".into(),
        run: "1".into(),
        stage: "attack".into(),
        ..Default::default()
    }
}
fn enqueue_test(session: &SecurityMemorySession, status: &str) {
    session.enqueue(
        "bash".into(),
        json!({"command": "pytest -v /tmp/pentests/test_render.py"}),
        format!("/tmp/pentests/test_render.py::test_escape {status}\n"),
        true,
        None,
    );
}

struct Gate {
    started: Mutex<Option<mpsc::Sender<()>>>,
    released: Mutex<bool>,
    wake: Condvar,
}
struct Release(Arc<Gate>);
impl Drop for Release {
    fn drop(&mut self) {
        *self.0.released.lock().unwrap() = true;
        self.0.wake.notify_all();
    }
}
impl MemoryBackend for Gate {
    fn remember(&self, path: &Path, entry: MemoryEntry) -> Result<String> {
        Ok(self.remember_batch(path, vec![entry])?.remove(0))
    }
    fn remember_batch(&self, path: &Path, entries: Vec<MemoryEntry>) -> Result<Vec<String>> {
        if let Some(started) = self.started.lock().unwrap().take() {
            started.send(()).unwrap();
        }
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
        Backend.remember_batch(path, entries)
    }
    fn retrieve(
        &self,
        path: &Path,
        query: &str,
        limit: usize,
        filter: &StoreFilter,
    ) -> Result<Vec<MemoryEntry>> {
        Backend.retrieve(path, query, limit, filter)
    }
}
fn blocked_session() -> (
    tempfile::TempDir,
    Arc<SecurityMemorySession>,
    mpsc::Receiver<()>,
    Release,
) {
    let dir = tempfile::tempdir().unwrap();
    let (sender, started) = mpsc::channel();
    let gate = Arc::new(Gate {
        started: Mutex::new(Some(sender)),
        released: Mutex::new(false),
        wake: Condvar::new(),
    });
    let session = Arc::new(SecurityMemorySession::new(
        options(dir.path(), super::super::MemoryMode::Both),
        gate.clone(),
    ));
    (dir, session, started, Release(gate))
}

#[test]
fn enqueue_returns_while_persistence_is_blocked() {
    let (dir, session, started, release) = blocked_session();
    let (done_tx, done_rx) = mpsc::channel();
    let submit = Arc::clone(&session);
    let submitting = std::thread::spawn(move || {
        enqueue_test(&submit, "FAILED");
        done_tx.send(()).unwrap();
    });
    let entered = started.recv_timeout(Duration::from_secs(5));
    let returned = done_rx.recv_timeout(Duration::from_secs(5));
    let not_yet_saved = !dir.path().join("delta.json").exists();
    drop(release); // Always release before assertions or joining, even on failure.
    submitting.join().unwrap();
    session.close();
    assert!(entered.is_ok());
    assert!(returned.is_ok(), "enqueue waited for persistence");
    assert!(not_yet_saved);
    assert_eq!(
        load_store(&dir.path().join("delta.json"))
            .unwrap()
            .memories
            .len(),
        1
    );
}

#[test]
fn staged_retrieval_does_not_wait_for_the_recorder() {
    let (dir, session, started, release) = blocked_session();
    let mut snapshot = crate::MemoryGraph::new();
    let mut threat = MemoryEntry::new(
        MemoryCategory::Custom("threat".into()),
        "Check escaping in render.py",
    );
    threat.tags = vec!["kind:threat".into(), "role:brief".into(), "code:v1".into()];
    let id = snapshot.add_memory(threat);
    save_store(&dir.path().join("snapshot.json"), &snapshot).unwrap();
    enqueue_test(&session, "FAILED");
    let entered = started.recv_timeout(Duration::from_secs(5));
    let (reply_tx, reply_rx) = mpsc::channel();
    let reader = Arc::clone(&session);
    let retrieving = std::thread::spawn(move || {
        reply_tx.send(reader.retrieve("render.py")).unwrap();
    });
    let result = reply_rx.recv_timeout(Duration::from_secs(5));
    drop(release);
    retrieving.join().unwrap();
    session.close();
    assert!(entered.is_ok());
    let result = result.expect("retrieval waited for recording").unwrap();
    assert_eq!(result.ids, vec![id]);
    assert!(!result.prompt.contains("test_escape")); // Delta is not part of the snapshot.
}

#[test]
fn close_drains_queued_results_in_order_and_is_idempotent() {
    let (dir, session, started, release) = blocked_session();
    enqueue_test(&session, "FAILED");
    let entered = started.recv_timeout(Duration::from_secs(5));
    enqueue_test(&session, "PASSED");
    let (closing_tx, closing_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let closing = Arc::clone(&session);
    let worker = std::thread::spawn(move || {
        closing_tx.send(()).unwrap();
        closing.close();
        done_tx.send(()).unwrap();
    });
    let closing_started = closing_rx.recv_timeout(Duration::from_secs(5));
    let still_draining = done_rx.recv_timeout(Duration::from_millis(30)).is_err();
    drop(release);
    worker.join().unwrap();
    assert!(entered.is_ok());
    assert!(closing_started.is_ok());
    assert!(
        still_draining,
        "close returned before persistence completed"
    );
    let delta = dir.path().join("delta.json");
    let graph = load_store(&delta).unwrap();
    assert_eq!(graph.memories.len(), 2);
    assert_eq!(graph.active_memories().count(), 1);
    assert!(
        graph
            .active_memories()
            .next()
            .unwrap()
            .tags
            .contains(&"status:passed".into())
    );
    let before = std::fs::read(&delta).unwrap();
    assert!(session.close().is_none());
    enqueue_test(&session, "FAILED"); // A late tool cannot rewrite a closed delta.
    assert_eq!(std::fs::read(delta).unwrap(), before);
}

#[test]
fn brief_write_is_processed_before_its_queued_edit() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = options(dir.path(), super::super::MemoryMode::Write);
    options.role = "brief".into();
    let session = SecurityMemorySession::new(options, Arc::new(Backend));
    session.enqueue(
        "write".into(),
        json!({"file_path": "/tmp/brief.md", "content": "## Threats\n- [T1] old claim"}),
        "Written".into(),
        true,
        None,
    );
    session.enqueue("edit".into(), json!({"file_path": "/tmp/brief.md", "old_string": "old claim", "new_string": "updated claim"}), "Edited".into(), true, None);
    session.close();
    let graph = load_store(&dir.path().join("delta.json")).unwrap();
    assert_eq!(graph.memories.len(), 2);
    assert!(
        graph
            .memories
            .values()
            .any(|e| e.content.contains("updated claim"))
    );
}

#[test]
fn drop_persists_accepted_observations() {
    let dir = tempfile::tempdir().unwrap();
    let session = SecurityMemorySession::new(
        options(dir.path(), super::super::MemoryMode::Write),
        Arc::new(Backend),
    );
    enqueue_test(&session, "FAILED");
    drop(session);
    assert_eq!(
        load_store(&dir.path().join("delta.json"))
            .unwrap()
            .memories
            .len(),
        1
    );
}

#[test]
fn off_and_read_only_sessions_have_no_recorder_or_delta() {
    for mode in [
        super::super::MemoryMode::Off,
        super::super::MemoryMode::Read,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let session = SecurityMemorySession::new(options(dir.path(), mode), Arc::new(Backend));
        assert!(!session.writes());
        enqueue_test(&session, "FAILED");
        assert!(session.close().is_none());
        assert!(!dir.path().join("delta.json").exists());
    }
}

struct PanicOnce(AtomicBool);
impl MemoryBackend for PanicOnce {
    fn remember(&self, path: &Path, entry: MemoryEntry) -> Result<String> {
        Backend.remember(path, entry)
    }
    fn remember_batch(&self, path: &Path, entries: Vec<MemoryEntry>) -> Result<Vec<String>> {
        if self.0.swap(false, Ordering::SeqCst) {
            panic!("fixture backend failure");
        }
        Backend.remember_batch(path, entries)
    }
    fn retrieve(
        &self,
        path: &Path,
        query: &str,
        limit: usize,
        filter: &StoreFilter,
    ) -> Result<Vec<MemoryEntry>> {
        Backend.retrieve(path, query, limit, filter)
    }
}

#[test]
fn recorder_panic_does_not_discard_later_observations() {
    let dir = tempfile::tempdir().unwrap();
    let session = SecurityMemorySession::new(
        options(dir.path(), super::super::MemoryMode::Write),
        Arc::new(PanicOnce(AtomicBool::new(true))),
    );
    enqueue_test(&session, "FAILED");
    enqueue_test(&session, "PASSED");
    session.close();
    let graph = load_store(&dir.path().join("delta.json")).unwrap();
    assert_eq!(graph.memories.len(), 1);
    assert!(
        graph
            .active_memories()
            .next()
            .unwrap()
            .tags
            .contains(&"status:passed".into())
    );
}

struct QueryCapture(Mutex<Vec<String>>);
impl MemoryBackend for QueryCapture {
    fn remember(&self, path: &Path, entry: MemoryEntry) -> Result<String> {
        Backend.remember(path, entry)
    }
    fn retrieve(
        &self,
        path: &Path,
        query: &str,
        limit: usize,
        filter: &StoreFilter,
    ) -> Result<Vec<MemoryEntry>> {
        self.0.lock().unwrap().push(query.into());
        Backend.retrieve(path, query, limit, filter)
    }
}

#[test]
fn native_tool_focus_is_retained_in_read_only_and_read_write_sessions() {
    for mode in [
        super::super::MemoryMode::Read,
        super::super::MemoryMode::Both,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(QueryCapture(Mutex::new(Vec::new())));
        let session = SecurityMemorySession::new(options(dir.path(), mode), backend.clone());
        for i in 0..7 {
            if mode == super::super::MemoryMode::Read {
                session.track_focus(json!({"file_path": format!("native_{i}.py")}));
            } else {
                session.enqueue(
                    "read".into(),
                    json!({"file_path": format!("native_{i}.py")}),
                    "file content".into(),
                    true,
                    None,
                );
            }
        }
        session.retrieve("Inspect the renderer");
        let queries = backend.0.lock().unwrap();
        let query = queries.last().unwrap();
        assert!(query.contains("Inspect the renderer"));
        assert!(query.contains("native_6.py"));
        assert!(!query.contains("native_0.py"));
        drop(queries);
        session.close();
    }
}
