use super::*;
use crate::security_memory::{MemoryMode, SecurityMemoryOptions, SecurityMemorySession};

struct TestEnv {
    _home: tempfile::TempDir,
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
}
impl TestEnv {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let keys = [
            "JCODE_HOME",
            "JCODE_NO_TELEMETRY",
            "JCODE_HOOKS_DISABLED",
            "JCODE_SECURITY_MEMORY",
            "JCODE_SECURITY_MEMORY_PATH",
            "JCODE_SECURITY_MEMORY_DELTA",
        ];
        let previous = keys
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        crate::env::set_var("JCODE_HOME", home.path());
        crate::env::set_var("JCODE_NO_TELEMETRY", "1");
        crate::env::set_var("JCODE_HOOKS_DISABLED", "1");
        for key in &keys[3..] {
            crate::env::remove_var(key);
        }
        Self {
            _home: home,
            previous,
        }
    }
}
impl Drop for TestEnv {
    fn drop(&mut self) {
        for (key, value) in self.previous.drain(..) {
            if let Some(value) = value {
                crate::env::set_var(key, value);
            } else {
                crate::env::remove_var(key);
            }
        }
    }
}
#[derive(Clone)]
struct CapturingProvider {
    requests: Arc<StdMutex<Vec<Vec<Message>>>>,
    edit: Option<PathBuf>,
}
#[async_trait]
impl Provider for CapturingProvider {
    async fn complete(
        &self,
        messages: &[Message],
        _tools: &[ToolDefinition],
        _system: &str,
        _resume: Option<&str>,
    ) -> Result<EventStream> {
        let call = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(messages.to_vec());
            requests.len()
        };
        let events = if call == 1 && self.edit.is_some() {
            vec![StreamEvent::ToolUseStart { id: "memory-fixture-edit".into(), name: "write".into() },
                 StreamEvent::ToolInputDelta(serde_json::json!({"file_path": self.edit.as_ref().unwrap(), "content":"def render(value): return escape(value)", "intent":"implement renderer"}).to_string()),
                 StreamEvent::ToolUseEnd, StreamEvent::MessageEnd { stop_reason: Some("tool_use".into()) }]
        } else {
            vec![
                StreamEvent::TextDelta("Done reviewing render.".into()),
                StreamEvent::MessageEnd {
                    stop_reason: Some("end_turn".into()),
                },
            ]
        };
        Ok(Box::pin(futures::stream::iter(events.into_iter().map(Ok))))
    }
    fn name(&self) -> &str {
        "security-memory-fixture"
    }
    fn fork(&self) -> Arc<dyn Provider> {
        Arc::new(self.clone())
    }
}
fn isolated_memory(agent: &mut Agent, options: SecurityMemoryOptions) {
    agent.security_memory = Some(Arc::new(SecurityMemorySession::new(
        options,
        Arc::new(crate::memory::MemoryManager::new_test().with_skills(false)),
    )));
}
async fn session_fixture(streaming: bool, summarize: bool) {
    let _lock = crate::storage::lock_test_env();
    let _env = TestEnv::new();
    let dir = tempfile::tempdir().unwrap();
    let requests = Arc::new(StdMutex::new(Vec::new()));
    let provider: Arc<dyn Provider> = Arc::new(CapturingProvider {
        requests: requests.clone(),
        edit: Some(dir.path().join("render.py")),
    });
    let registry = Registry::new(provider.clone()).await;
    let mut writer = Agent::new(provider, registry);
    writer.memory_enabled = false;
    writer.set_working_dir_for_pending_context(Some(dir.path().display().to_string()));
    let options = SecurityMemoryOptions {
        mode: MemoryMode::Write,
        path: Some(dir.path().join("snapshot.json")),
        delta: Some(dir.path().join("delta.json")),
        role: "feature".into(),
        code: "v1".into(),
        run: "1".into(),
        stage: "feature".into(),
        summarize,
        ..Default::default()
    };
    isolated_memory(&mut writer, options.clone());
    if streaming {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        writer
            .run_once_streaming_mpsc("Implement render", vec![], None, tx)
            .await
            .unwrap();
    } else {
        writer.run_once_capture("Implement render").await.unwrap();
    }
    writer.mark_closed();
    writer.mark_closed();
    assert_eq!(requests.lock().unwrap().len(), 2 + usize::from(summarize));
    let delta = crate::security_memory::load_store(options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(delta.memories.len(), 1 + usize::from(summarize));
    let id = delta
        .active_memories()
        .find(|e| e.category == crate::memory::MemoryCategory::Custom("implementation".into()))
        .unwrap()
        .id
        .clone();
    crate::security_memory::merge_files(
        options.path.as_ref().unwrap(),
        &[options.delta.clone().unwrap()],
    )
    .unwrap();
    let requests = Arc::new(StdMutex::new(Vec::new()));
    let provider: Arc<dyn Provider> = Arc::new(CapturingProvider {
        requests: requests.clone(),
        edit: None,
    });
    let registry = Registry::new(provider.clone()).await;
    let mut reader = Agent::new(provider, registry);
    reader.memory_enabled = false;
    let mut options = options;
    options.mode = MemoryMode::Read;
    options.role = "defender".into();
    options.code = "v2".into();
    isolated_memory(&mut reader, options);
    if streaming {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        reader
            .run_once_streaming_mpsc("Review render", vec![], None, tx)
            .await
            .unwrap();
    } else {
        reader.run_once_capture("Review render").await.unwrap();
    }
    let serialized = serde_json::to_string(&*requests.lock().unwrap()).unwrap();
    assert!(serialized.contains("# Security memory"));
    assert!(serialized.contains(&id));
    assert!(serialized.contains("re-test"));
    assert!(
        !serde_json::to_string(&reader.session.messages)
            .unwrap()
            .contains("<security-memory>")
    );
}
#[tokio::test]
async fn security_memory_fixture_headless() {
    session_fixture(false, false).await;
}
#[tokio::test]
async fn security_memory_fixture_streaming() {
    session_fixture(true, false).await;
}

#[tokio::test]
async fn security_memory_unset_and_off_send_identical_request_bytes() {
    let _lock = crate::storage::lock_test_env();
    let _env = TestEnv::new();
    let requests = Arc::new(StdMutex::new(Vec::new()));
    let provider: Arc<dyn Provider> = Arc::new(CapturingProvider {
        requests: requests.clone(),
        edit: None,
    });
    let registry = Registry::new(provider.clone()).await;
    let mut agent = Agent::new(provider.clone(), registry);
    agent.memory_enabled = false;
    agent.add_message(
        Role::User,
        vec![ContentBlock::Text {
            text: "Review render".into(),
            cache_control: None,
        }],
    );
    let session = agent.session.clone();
    assert!(agent.security_memory.is_none());
    assert!(agent.security_memory_context_message().is_none());
    agent.run_turn(false).await.unwrap();
    let registry = Registry::new(provider.clone()).await;
    let mut off = Agent::new_with_session(provider, registry, session, None);
    off.memory_enabled = false;
    off.set_security_memory_options(SecurityMemoryOptions::default());
    off.run_turn(false).await.unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        serde_json::to_vec(&requests[0]).unwrap(),
        serde_json::to_vec(&requests[1]).unwrap()
    );
}

#[tokio::test]
async fn security_memory_optional_close_summary_calls_own_provider_once() {
    session_fixture(false, true).await;
}

struct PausedRecorder {
    gate: Arc<(StdMutex<bool>, std::sync::Condvar)>,
    started: StdMutex<Option<std::sync::mpsc::Sender<()>>>,
}
impl crate::security_memory::MemoryBackend for PausedRecorder {
    fn remember(
        &self,
        path: &std::path::Path,
        entry: crate::memory::MemoryEntry,
    ) -> Result<String> {
        Ok(self.remember_batch(path, vec![entry])?.remove(0))
    }
    fn remember_batch(
        &self,
        path: &std::path::Path,
        entries: Vec<crate::memory::MemoryEntry>,
    ) -> Result<Vec<String>> {
        if let Some(started) = self.started.lock().unwrap().take() {
            let _ = started.send(());
        }
        let (mutex, wake) = &*self.gate;
        let mut released = mutex.lock().unwrap();
        while !*released {
            released = wake.wait(released).unwrap();
        }
        crate::security_memory::MemoryBackend::remember_batch(
            &crate::memory::MemoryManager::new_test().with_skills(false),
            path,
            entries,
        )
    }
    fn retrieve(
        &self,
        path: &std::path::Path,
        query: &str,
        limit: usize,
        filter: &crate::security_memory::StoreFilter,
    ) -> Result<Vec<crate::memory::MemoryEntry>> {
        crate::security_memory::MemoryBackend::retrieve(
            &crate::memory::MemoryManager::new_test().with_skills(false),
            path,
            query,
            limit,
            filter,
        )
    }
}
struct ReleaseRecorder(Arc<(StdMutex<bool>, std::sync::Condvar)>);
impl Drop for ReleaseRecorder {
    fn drop(&mut self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }
}

async fn background_recording_fixture(streaming: bool) {
    let _lock = crate::storage::lock_test_env();
    let _env = TestEnv::new();
    let dir = tempfile::tempdir().unwrap();
    let requests = Arc::new(StdMutex::new(Vec::new()));
    let provider: Arc<dyn Provider> = Arc::new(CapturingProvider {
        requests: requests.clone(),
        edit: Some(dir.path().join("render.py")),
    });
    let registry = Registry::new(provider.clone()).await;
    let mut agent = Agent::new(provider, registry);
    agent.memory_enabled = false;
    agent.set_working_dir_for_pending_context(Some(dir.path().display().to_string()));
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let gate = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
    let options = SecurityMemoryOptions {
        mode: MemoryMode::Both,
        path: Some(dir.path().join("snapshot.json")),
        delta: Some(dir.path().join("delta.json")),
        role: "feature".into(),
        code: "v1".into(),
        run: "1".into(),
        stage: "feature".into(),
        ..Default::default()
    };
    let mut snapshot = crate::memory_graph::MemoryGraph::new();
    let mut threat = crate::memory::MemoryEntry::new(
        crate::memory::MemoryCategory::Custom("threat".into()),
        "Escape untrusted HTML in render.py",
    );
    threat.tags = vec!["role:brief".into(), "kind:threat".into(), "code:v1".into()];
    snapshot.add_memory(threat);
    crate::security_memory::save_store(options.path.as_ref().unwrap(), &snapshot).unwrap();
    agent.security_memory = Some(Arc::new(SecurityMemorySession::new(
        options.clone(),
        Arc::new(PausedRecorder {
            gate: gate.clone(),
            started: StdMutex::new(Some(started_tx)),
        }),
    )));
    // A watchdog releases the fixture even if a regression blocks the async
    // thread itself. Assert progress, not an embedding performance threshold.
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let watchdog_gate = gate.clone();
    let watchdog = std::thread::spawn(move || {
        if done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .is_err()
        {
            drop(ReleaseRecorder(watchdog_gate));
            true
        } else {
            false
        }
    });
    let release = ReleaseRecorder(gate);
    let result = if streaming {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        agent
            .run_once_streaming_mpsc("Implement render", vec![], None, tx)
            .await
            .map(|_| ())
    } else {
        agent.run_once_capture("Implement render").await.map(|_| ())
    };
    let _ = done_tx.send(());
    let waited_for_recording = watchdog.join().unwrap();
    let recording_started = started_rx.recv_timeout(std::time::Duration::from_secs(5));
    let still_unsaved = !options.delta.as_ref().unwrap().exists();
    drop(release);
    agent.mark_closed();
    result.unwrap();
    assert!(
        !waited_for_recording,
        "model continuation waited for the recorder"
    );
    assert!(recording_started.is_ok());
    assert!(still_unsaved);
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        serde_json::to_string(&requests[1])
            .unwrap()
            .contains("# Security memory")
    );
    assert!(requests[1].iter().flat_map(|m| &m.content).any(|b| matches!(b, ContentBlock::ToolResult { tool_use_id, .. } if tool_use_id == "memory-fixture-edit")));
    assert_eq!(
        crate::security_memory::load_store(options.delta.as_ref().unwrap())
            .unwrap()
            .memories
            .len(),
        1
    );
}

#[tokio::test]
async fn security_memory_recording_does_not_delay_headless_continuation() {
    background_recording_fixture(false).await;
}

#[tokio::test]
async fn security_memory_recording_does_not_delay_streaming_continuation() {
    background_recording_fixture(true).await;
}
