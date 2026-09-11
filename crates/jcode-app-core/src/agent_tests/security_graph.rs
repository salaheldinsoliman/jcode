use super::*;
use crate::security_graph::{ContextOptions, DEFAULT_GRAPH_PATH, SecurityGraph, content_hash};

struct IsolatedEnv {
    _home: tempfile::TempDir,
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl IsolatedEnv {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let previous = ["JCODE_HOME", "JCODE_NO_TELEMETRY", "JCODE_HOOKS_DISABLED"]
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect();
        crate::env::set_var("JCODE_HOME", home.path());
        crate::env::set_var("JCODE_NO_TELEMETRY", "1");
        crate::env::set_var("JCODE_HOOKS_DISABLED", "1");
        Self {
            _home: home,
            previous,
        }
    }
}

impl Drop for IsolatedEnv {
    fn drop(&mut self) {
        for (key, value) in self.previous.drain(..) {
            match value {
                Some(value) => crate::env::set_var(key, value),
                None => crate::env::remove_var(key),
            }
        }
    }
}

#[derive(Clone)]
struct CapturingProvider {
    requests: Arc<StdMutex<Vec<Vec<Message>>>>,
    source: PathBuf,
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
        let events = match call {
            1 => vec![
                StreamEvent::ToolUseStart {
                    id: "read-security-fixture".into(),
                    name: "read".into(),
                },
                StreamEvent::ToolInputDelta(
                    r#"{"file_path":"render.py","intent":"inspect renderer"}"#.into(),
                ),
                StreamEvent::ToolUseEnd,
                StreamEvent::MessageEnd {
                    stop_reason: Some("tool_use".into()),
                },
            ],
            2 => {
                // Simulate an external edit, then exercise empty-response recovery
                // after a tool result. The context suffix must not hide that result.
                std::fs::write(&self.source, "def render(value): return str(value)\n")?;
                vec![StreamEvent::MessageEnd {
                    stop_reason: Some("end_turn".into()),
                }]
            }
            _ => vec![
                StreamEvent::TextDelta("Finished reviewing the renderer.".into()),
                StreamEvent::MessageEnd {
                    stop_reason: Some("end_turn".into()),
                },
            ],
        };
        Ok(Box::pin(futures::stream::iter(events.into_iter().map(Ok))))
    }

    fn name(&self) -> &str {
        "security-graph-test"
    }
    fn fork(&self) -> Arc<dyn Provider> {
        Arc::new(self.clone())
    }
}

fn security_messages(messages: &[Message]) -> Vec<&str> {
    messages
        .iter()
        .flat_map(|m| &m.content)
        .filter_map(|block| match block {
            // Request preparation may prefix user-role messages with a timestamp.
            ContentBlock::Text { text, .. } if text.contains("<security-context>") => {
                Some(text.as_str())
            }
            _ => None,
        })
        .collect()
}

async fn exercise_security_context(streaming: bool, enabled: bool) {
    let _lock = crate::storage::lock_test_env();
    let _env = IsolatedEnv::new();
    let repo = tempfile::tempdir().unwrap();
    let source = repo.path().join("render.py");
    let code = b"def render(value): return value\n";
    std::fs::write(&source, code).unwrap();
    let graph = SecurityGraph::from_json(
        &serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "id": "renderer-test",
            "description": "Repository-specific renderer contract",
            "source_files": {"render.py": content_hash(code)},
            "nodes": [{"id":"trusted-template", "kind":"assumption", "status":"inferred",
                "description":"Template source must remain application controlled",
                "evidence":[{"path":"render.py", "symbol":"render"}]}],
            "edges": []
        }))
        .unwrap(),
    )
    .unwrap();
    graph.save(&repo.path().join(DEFAULT_GRAPH_PATH)).unwrap();
    let requests = Arc::new(StdMutex::new(Vec::new()));
    let provider: Arc<dyn Provider> = Arc::new(CapturingProvider {
        requests: requests.clone(),
        source,
    });
    let registry = Registry::new(provider.clone()).await;
    let mut agent = Agent::new(provider.clone(), registry);
    agent.set_working_dir_for_pending_context(Some(repo.path().display().to_string()));
    agent.memory_enabled = false;
    agent.system_prompt_override = Some("Inspect the requested code.".into());
    agent.set_security_graph_options(ContextOptions {
        enabled,
        graph_path: None,
    });

    if streaming {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        agent
            .run_once_streaming_mpsc("Inspect the renderer", vec![], None, tx)
            .await
            .unwrap();
    } else {
        agent
            .run_once_capture("Inspect the renderer")
            .await
            .unwrap();
    }
    {
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests.len(),
            3,
            "empty post-tool response must still recover"
        );
        for request in requests.iter() {
            assert_eq!(security_messages(request).len(), usize::from(enabled));
        }
        if enabled {
            assert!(
                security_messages(&requests[0])[0].contains("Recorded source-file hashes match")
            );
            assert!(security_messages(&requests[2])[0].contains("SOURCE REVIEW REQUIRED"));
        }
    }
    assert!(
        !serde_json::to_string(&agent.session.messages)
            .unwrap()
            .contains("<security-context>"),
        "context must not accumulate in the persisted conversation"
    );

    // Reconstruct an Agent from a saved session, like a resume after a restart.
    let session = crate::session::Session::load(agent.session_id()).unwrap();
    let registry = Registry::new(provider.clone()).await;
    let mut resumed = Agent::new_with_session(provider, registry, session, None);
    resumed.memory_enabled = false;
    resumed.set_security_graph_options(ContextOptions {
        enabled,
        graph_path: None,
    });
    resumed
        .run_once_capture("Review the changed renderer")
        .await
        .unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(
        security_messages(requests.last().unwrap()).len(),
        usize::from(enabled)
    );
}

#[tokio::test]
async fn security_graph_reaches_headless_requests_and_survives_resume() {
    exercise_security_context(false, true).await;
}

#[tokio::test]
async fn security_graph_reaches_streaming_requests_and_survives_resume() {
    exercise_security_context(true, true).await;
}

#[tokio::test]
async fn security_graph_disabled_condition_has_no_injected_context() {
    exercise_security_context(false, false).await;
    exercise_security_context(true, false).await;
}
