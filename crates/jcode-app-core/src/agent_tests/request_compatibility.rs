//! This fixture intentionally uses no security-memory API so it also runs on
//! the unmodified base commit. Optional captures compare full provider requests.
use super::*;

#[derive(Clone)]
struct RequestCapture(Arc<StdMutex<Vec<serde_json::Value>>>);
#[async_trait]
impl Provider for RequestCapture {
    async fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolDefinition],
        system: &str,
        resume: Option<&str>,
    ) -> Result<EventStream> {
        self.0.lock().unwrap().push(serde_json::json!({"messages":messages, "tools":tools, "system":system, "resume":resume}));
        Ok(Box::pin(futures::stream::iter([
            Ok(StreamEvent::TextDelta("Reviewed.".into())),
            Ok(StreamEvent::MessageEnd {
                stop_reason: Some("end_turn".into()),
            }),
        ])))
    }
    fn name(&self) -> &str {
        "request-compatibility"
    }
    fn fork(&self) -> Arc<dyn Provider> {
        Arc::new(self.clone())
    }
}
#[tokio::test]
async fn security_memory_default_request_compatibility_fixture() {
    let _guard = crate::storage::lock_test_env();
    let home = tempfile::tempdir().unwrap();
    let keys = [
        "JCODE_HOME",
        "JCODE_NO_TELEMETRY",
        "JCODE_HOOKS_DISABLED",
        "JCODE_SECURITY_MEMORY",
        "JCODE_SECURITY_MEMORY_PATH",
        "JCODE_SECURITY_MEMORY_DELTA",
    ];
    let previous: Vec<_> = keys
        .iter()
        .map(|key| (*key, std::env::var_os(key)))
        .collect();
    crate::env::set_var("JCODE_HOME", home.path());
    crate::env::set_var("JCODE_NO_TELEMETRY", "1");
    crate::env::set_var("JCODE_HOOKS_DISABLED", "1");
    for key in &keys[3..] {
        crate::env::remove_var(key);
    }
    let requests = Arc::new(StdMutex::new(Vec::new()));
    let provider: Arc<dyn Provider> = Arc::new(RequestCapture(requests.clone()));
    let registry = Registry::new(provider.clone()).await;
    let mut agent = Agent::new(provider, registry);
    agent.memory_enabled = false;
    agent.allowed_tools = Some(HashSet::from(["read".into()]));
    agent.system_prompt_override = Some("Review the renderer.".into());
    agent.session.messages.clear();
    agent.add_message(
        Role::User,
        vec![ContentBlock::Text {
            text: "Inspect render.py".into(),
            cache_control: None,
        }],
    );
    // Fix the fixture timestamp; avoid comparing the clock between builds.
    for message in &mut agent.session.messages {
        message.timestamp = None;
    }
    agent.run_turn(false).await.unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].to_string().contains("<security-memory>"));
    if let Some(path) = std::env::var_os("JCODE_TEST_REQUEST_CAPTURE") {
        std::fs::write(path, serde_json::to_vec(&requests[0]).unwrap()).unwrap();
    }
    for (key, value) in previous {
        if let Some(value) = value {
            crate::env::set_var(key, value);
        } else {
            crate::env::remove_var(key);
        }
    }
}
