use super::Agent;
use crate::logging;
use crate::message::{ContentBlock, Message, ToolDefinition};

impl Agent {
    /// Override discovery for an isolated experiment or an embedding application.
    /// None at construction means use the process environment and project file.
    pub fn set_security_graph_options(&mut self, options: crate::security_graph::ContextOptions) {
        self.security_graph_options = Some(options);
    }

    /// Rebuild outside conversational memory so first requests, tool continuations,
    /// compaction and resumed sessions receive the current graph independently of
    /// memory enablement, expiry and deduplication. Never append it to history.
    pub(super) fn security_context_message(&self) -> anyhow::Result<Option<Message>> {
        let options = match &self.security_graph_options {
            Some(options) => options.clone(),
            None => crate::security_graph::ContextOptions::from_env()?,
        };
        if !options.enabled {
            return Ok(None);
        }
        let working_dir = match &self.session.working_dir {
            Some(directory) => std::path::PathBuf::from(directory),
            None => std::env::current_dir()?,
        };
        let Some(context) = crate::security_graph::load_context(&working_dir, &options)? else {
            return Ok(None);
        };
        let context_hash = crate::security_graph::content_hash(context.prompt.as_bytes());
        if super::utils::trace_enabled() {
            eprintln!(
                "[trace] security_graph loaded session={} path={} graph_hash={} context_hash={} nodes={} edges={} sources_match={} bytes={}",
                self.session.id,
                context.graph_path.display(),
                context.graph_hash,
                context_hash,
                context.node_count,
                context.edge_count,
                context.sources_match,
                context.prompt.len()
            );
        }
        logging::event_info(
            "SECURITY_CONTEXT",
            vec![
                ("session_id".to_string(), self.session.id.clone()),
                (
                    "graph_path".to_string(),
                    context.graph_path.display().to_string(),
                ),
                ("graph_hash".to_string(), context.graph_hash),
                ("context_hash".to_string(), context_hash),
                ("nodes".to_string(), context.node_count.to_string()),
                ("edges".to_string(), context.edge_count.to_string()),
                (
                    "sources_match".to_string(),
                    context.sources_match.to_string(),
                ),
                (
                    "context_bytes".to_string(),
                    context.prompt.len().to_string(),
                ),
            ],
        );
        Ok(Some(Message::user(&context.prompt)))
    }

    /// Inspect the actual ephemeral message passed to the provider. A stream
    /// opening confirms dispatch succeeded, not that the model obeyed the graph.
    /// Log fingerprints only; repository descriptions may contain sensitive data.
    pub(super) fn log_security_context_request(&self, message: Option<&Message>, stage: &str) {
        let Some(message) = message else { return };
        let Some(context) = message.content.iter().find_map(|block| match block {
            ContentBlock::Text { text, .. } => {
                text.find("<security-context>").map(|start| &text[start..])
            }
            _ => None,
        }) else {
            return;
        };
        let context_hash = crate::security_graph::content_hash(context.as_bytes());
        let model = self.provider.model();
        logging::event_info(
            "SECURITY_CONTEXT_REQUEST",
            vec![
                ("session_id".to_string(), self.session.id.clone()),
                ("stage".to_string(), stage.to_string()),
                ("context_hash".to_string(), context_hash.clone()),
                ("model".to_string(), model.clone()),
                ("context_bytes".to_string(), context.len().to_string()),
            ],
        );
        if super::utils::trace_enabled() {
            eprintln!(
                "[trace] security_graph {stage} session={} model={} context_hash={} bytes={}",
                self.session.id,
                model,
                context_hash,
                context.len()
            );
        }
    }

    pub(super) fn log_prompt_prefix_accounting(
        &self,
        split: &crate::prompt::SplitSystemPrompt,
        tools: &[ToolDefinition],
    ) {
        let system_tokens = split.estimated_tokens();
        let tool_tokens = ToolDefinition::aggregate_prompt_token_estimate(tools);
        let prefix_tokens = system_tokens + tool_tokens;
        logging::info(&format!(
            "Prompt prefix estimate: total={} tokens (system={} tools={})",
            prefix_tokens, system_tokens, tool_tokens
        ));
    }

    pub(super) fn build_memory_prompt_nonblocking_shared(
        &self,
        messages: std::sync::Arc<[Message]>,
        _memory_event_tx: Option<crate::memory::MemoryEventSink>,
    ) -> Option<crate::memory::PendingMemory> {
        if !self.memory_enabled {
            return None;
        }

        let session_id = &self.session.id;

        let fresh_user_turn = crate::message::ends_with_fresh_user_turn(&messages);
        let pending = if fresh_user_turn {
            crate::memory::take_pending_memory(session_id)
        } else {
            None
        };

        // Use the persistent memory-agent pipeline as the single source of truth.
        // Running both this and the legacy MemoryManager background retrieval path
        // can prepare overlapping pending prompts for the same turn, which makes
        // memory injection feel overly aggressive.
        // Relevance results are consumed only at the start of a fresh user turn.
        // Enqueuing again after every tool result runs the local embedding model
        // for each provider continuation without creating an additional injection
        // opportunity. One update per user turn keeps memory current while avoiding
        // redundant 512-token inference during tool-heavy agent loops.
        if fresh_user_turn {
            crate::memory_agent::update_context_sync_with_dir(
                session_id,
                messages,
                self.session.working_dir.clone(),
            );
        }

        pending
    }

    fn append_current_turn_system_reminder(&self, split: &mut crate::prompt::SplitSystemPrompt) {
        let Some(reminder) = self
            .current_turn_system_reminder
            .as_ref()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        else {
            return;
        };

        if !split.dynamic_part.is_empty() {
            split.dynamic_part.push_str("\n\n");
        }
        split.dynamic_part.push_str("# System Reminder\n\n");
        split.dynamic_part.push_str(reminder);
    }

    /// Build split system prompt for better caching
    /// Returns static (cacheable) and dynamic (not cached) parts separately
    pub(super) fn build_system_prompt_split(
        &self,
        memory_prompt: Option<&str>,
    ) -> crate::prompt::SplitSystemPrompt {
        if let Some(ref override_prompt) = self.system_prompt_override {
            return crate::prompt::SplitSystemPrompt {
                static_part: override_prompt.clone(),
                dynamic_part: String::new(),
            };
        }

        let skills = self.current_skills_snapshot();
        let skill_prompt = self
            .active_skill
            .as_ref()
            .and_then(|name| skills.get(name).map(|skill| skill.get_prompt().to_string()));

        let available_skills: Vec<crate::prompt::SkillInfo> = self
            .current_skills_snapshot()
            .list()
            .iter()
            .map(|skill| crate::prompt::SkillInfo {
                name: skill.name.clone(),
                description: skill.description.clone(),
            })
            .collect();

        let working_dir = self
            .session
            .working_dir
            .as_ref()
            .map(std::path::PathBuf::from);

        let (mut split, _context_info) = crate::prompt::build_system_prompt_split_with_agents_md(
            skill_prompt.as_deref(),
            &available_skills,
            self.session.is_canary,
            memory_prompt,
            working_dir.as_deref(),
            self.agents_md_snapshot.clone(),
        );

        self.append_current_turn_system_reminder(&mut split);
        crate::prompt::append_swarm_effort_directive(
            &mut split,
            self.provider.reasoning_effort().as_deref(),
        );

        split
    }

    /// Non-blocking memory prompt - takes pending result and spawns check for next turn
    #[cfg(test)]
    pub(super) fn build_memory_prompt_nonblocking(
        &self,
        messages: &[Message],
        _memory_event_tx: Option<crate::memory::MemoryEventSink>,
    ) -> Option<crate::memory::PendingMemory> {
        self.build_memory_prompt_nonblocking_shared(messages.to_vec().into(), _memory_event_tx)
    }
}
