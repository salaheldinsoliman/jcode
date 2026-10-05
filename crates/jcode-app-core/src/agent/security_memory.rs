use super::Agent;
use crate::message::{ContentBlock, Message, Role};
use crate::security_memory::{MemoryMode, SecurityMemoryOptions, SecurityMemorySession};
use std::sync::Arc;

impl Agent {
    pub(super) fn new_security_memory(
        options: SecurityMemoryOptions,
    ) -> Option<Arc<SecurityMemorySession>> {
        (options.mode != MemoryMode::Off).then(|| {
            Arc::new(SecurityMemorySession::new(
                options,
                Arc::new(crate::memory::MemoryManager::new().with_skills(false)),
            ))
        })
    }
    pub fn set_security_memory_options(&mut self, options: SecurityMemoryOptions) {
        self.close_security_memory();
        self.security_memory = Self::new_security_memory(options);
    }
    /// Sync form, for tests and callers outside the runtime. The turn loops use
    /// `security_memory_context_message_async`, which keeps the store read and
    /// the query embedding off the async worker threads.
    pub(super) fn security_memory_context_message(&self) -> Option<Message> {
        let (memory, focus) = self.security_memory_focus()?;
        let result = memory.retrieve(&focus)?;
        Some(self.security_memory_message(result))
    }
    pub(super) async fn security_memory_context_message_async(&self) -> Option<Message> {
        let (memory, focus) = self.security_memory_focus()?;
        let work = tokio::task::spawn_blocking(move || memory.retrieve(&focus));
        let result = match work.await {
            Ok(result) => result?,
            Err(e) => {
                crate::logging::warn(&format!("Security memory retrieval task failed: {e}"));
                return None;
            }
        };
        Some(self.security_memory_message(result))
    }
    fn security_memory_focus(&self) -> Option<(Arc<SecurityMemorySession>, String)> {
        let memory = self.security_memory.as_ref()?;
        let mut focus = String::new();
        if let Some(first) = self.session.messages.iter().find(|m| m.role == Role::User && m.content.iter().any(|b| matches!(b, ContentBlock::Text { text, .. } if !text.starts_with("<system-reminder>")))) {
            for block in &first.content { if let ContentBlock::Text { text, .. } = block { focus.push_str(text); } }
        }
        // History supplies focus after resume; recording still uses only newly
        // executed tool results. Never reconstruct evidence from old history.
        for block in self
            .session
            .messages
            .iter()
            .rev()
            .flat_map(|m| m.content.iter().rev())
            .filter(|b| matches!(b, ContentBlock::ToolUse { .. }))
            .take(6)
        {
            if let ContentBlock::ToolUse { input, .. } = block {
                focus.push(' ');
                focus.push_str(&crate::security_memory::focus_from_tool(input));
            }
        }
        Some((Arc::clone(memory), focus))
    }
    fn security_memory_message(&self, result: crate::security_memory::RetrievedMemory) -> Message {
        use sha2::{Digest, Sha256};
        let prompt = format!("<security-memory>\n{}\n</security-memory>", result.prompt);
        let hash = format!("{:x}", Sha256::digest(prompt.as_bytes()));
        crate::logging::event_info(
            "SECURITY_MEMORY_CONTEXT",
            vec![
                ("session_id", self.session.id.clone()),
                ("context_hash", hash.clone()),
                ("entry_ids", result.ids.join(",")),
            ],
        );
        if super::utils::trace_enabled() {
            eprintln!(
                "[trace] security_memory session={} context_hash={} entry_ids={}",
                self.session.id,
                hash,
                result.ids.join(",")
            );
        }
        Message::user(&prompt)
    }
    /// Capture completed tool evidence for the ordered worker. Parsing,
    /// embeddings and persistence do not delay returning the tool's result.
    pub(super) fn observe_security_tool(
        memory: Option<&Arc<SecurityMemorySession>>,
        tool: &str,
        input: &serde_json::Value,
        result: &anyhow::Result<crate::tool::ToolOutput>,
        project_root: Option<&std::path::Path>,
    ) {
        let Some(memory) = memory else {
            return;
        };
        let input = input.clone();
        if !memory.writes() {
            memory.track_focus(input);
            return;
        }
        let tool = crate::tool::Registry::resolve_tool_name(tool).to_string();
        let (output, succeeded) = match result {
            Ok(output) => (output.output.clone(), true),
            Err(error) => (error.to_string(), false),
        };
        let project_root = project_root.map(std::path::Path::to_path_buf);
        memory.enqueue(tool, input, output, succeeded, project_root);
    }
    pub(super) fn close_security_memory(&mut self) {
        let Some(memory) = self.security_memory.clone() else {
            return;
        };
        // close stops submissions and joins the worker after its FIFO drains.
        let Some(mut memory) = memory.close() else {
            return;
        };
        let Some(prompt) = memory.take_summary_prompt() else {
            return;
        };
        let provider = self.provider.clone();
        // mark_closed is synchronous. A separate runtime avoids blocking its
        // current executor on a nested block_on. This optional call is bounded.
        let worker = std::thread::Builder::new()
            .name("security-memory-summary".into())
            .spawn(move || -> anyhow::Result<()> {
                let runtime = tokio::runtime::Runtime::new()?;
                let summary = runtime.block_on(async {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(20),
                        provider.complete_simple(
                            &prompt,
                            "Summarize observed process lessons briefly; no tools.",
                        ),
                    )
                    .await
                })??;
                memory.summarize_at_end(&summary);
                Ok(())
            });
        let result = match worker {
            Ok(worker) => worker.join(),
            Err(error) => {
                crate::logging::warn(&format!("Security memory summary could not start: {error}"));
                return;
            }
        };
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => crate::logging::warn(&format!("Security memory summary failed: {e:#}")),
            Err(_) => crate::logging::warn("Security memory summary worker panicked"),
        }
    }
}
