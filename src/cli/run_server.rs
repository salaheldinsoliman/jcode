//! Opt-in native server client for one-shot runs. The daemon owns the coordinator
//! and workers; this client stays attached across worker reports and wake turns.
use super::provider_init::ProviderChoice;
use crate::protocol::{Request, ServerEvent, SwarmMemberStatus};
use crate::transport::{ReadHalf, WriteHalf};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};

struct Connection {
    reader: Lines<BufReader<ReadHalf>>,
    writer: WriteHalf,
    next_id: u64,
}

impl Connection {
    fn id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    async fn send(&mut self, request: Request) -> Result<()> {
        let mut line = serde_json::to_vec(&request)?;
        line.push(b'\n');
        self.writer.write_all(&line).await?;
        Ok(())
    }

    async fn read(&mut self) -> Result<ServerEvent> {
        let line = self
            .reader
            .next_line()
            .await?
            .context("jcode server disconnected before run completion")?;
        serde_json::from_str(&line).context("invalid jcode server event")
    }

    async fn done(&mut self, id: u64) -> Result<()> {
        loop {
            match self.read().await? {
                ServerEvent::Done { id: response } if response == id => return Ok(()),
                ServerEvent::Error { message, .. } => bail!(message),
                _ => {}
            }
        }
    }
}

#[derive(Default)]
struct Lifecycle {
    session_id: String,
    workers: HashMap<String, SwarmMemberStatus>,
    // Status can become ready when a worker reports, before its turn ends.
    // Confirm actual processing state through comm_status before exiting.
    worker_processing: HashMap<String, bool>,
    reports: HashMap<String, String>,
    final_reports: HashMap<String, String>,
    turn_done: bool,
    changed: Option<Instant>,
}

impl Lifecycle {
    fn status(&mut self, members: Vec<SwarmMemberStatus>) {
        for member in members {
            if member.report_back_to_session_id.as_deref() != Some(&self.session_id) {
                continue;
            }
            let changed = self
                .workers
                .get(&member.session_id)
                .is_none_or(|old| old.status != member.status);
            if changed {
                self.worker_processing.remove(&member.session_id);
                if matches!(member.status.as_str(), "running" | "streaming" | "thinking") {
                    self.final_reports.remove(&member.session_id);
                }
                self.changed = Some(Instant::now());
            }
            self.workers.insert(member.session_id.clone(), member);
        }
    }

    fn report(&mut self, from: String, message: String) {
        if self.workers.contains_key(&from) {
            self.reports.insert(from, message);
            self.changed = Some(Instant::now());
        }
    }

    fn workers_finished(&self) -> bool {
        self.workers.values().all(|member| {
            matches!(
                member.status.as_str(),
                "ready" | "completed" | "done" | "failed" | "crashed" | "stopped"
            ) && self.worker_processing.get(&member.session_id) == Some(&false)
        })
    }

    fn settled(&self) -> bool {
        self.turn_done
            && self.workers_finished()
            && self
                .workers
                .keys()
                .all(|id| self.final_reports.contains_key(id))
            && self.reports.is_empty()
            && self
                .changed
                .is_none_or(|time| time.elapsed() >= Duration::from_millis(300))
    }
}

/// The server must already be running with the intended provider, key and hooks.
/// Connecting never starts or changes a shared daemon.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    choice: &ProviderChoice,
    model: Option<&str>,
    resume: Option<&str>,
    message: &str,
    json: bool,
    ndjson: bool,
    timeout_secs: u64,
) -> Result<()> {
    let stream = crate::server::connect_socket(&crate::server::socket_path()).await
        .context("run --server needs a running daemon; start jcode serve with the same provider and environment")?;
    let (reader, writer) = stream.into_split();
    let mut connection = Connection {
        reader: BufReader::new(reader).lines(),
        writer,
        next_id: 1,
    };
    let mut lifecycle = Lifecycle::default();
    let result = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(timeout_secs),
            execute(&mut connection, &mut lifecycle, choice, model, resume, message, json, ndjson)) => {
            result.unwrap_or_else(|_| Err(anyhow::anyhow!("server-backed run exceeded its shared coordinator/worker deadline")))
        }
        signal = tokio::signal::ctrl_c() => {
            signal?;
            Err(anyhow::anyhow!("server-backed run interrupted"))
        }
    };
    if result.is_err() {
        // Stop only this coordinator's children, never unrelated server sessions.
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            let id = connection.id();
            let _ = connection.send(Request::Cancel { id }).await;
            for worker in lifecycle.workers.keys() {
                let id = connection.id();
                let _ = connection
                    .send(Request::CommStop {
                        id,
                        session_id: lifecycle.session_id.clone(),
                        target_session: worker.clone(),
                        force: Some(true),
                    })
                    .await;
            }
        })
        .await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn execute(
    connection: &mut Connection,
    lifecycle: &mut Lifecycle,
    choice: &ProviderChoice,
    model: Option<&str>,
    resume: Option<&str>,
    message: &str,
    json: bool,
    ndjson: bool,
) -> Result<()> {
    let provider = super::provider_init::init_provider_quiet(choice, model).await?;
    let subscribe = connection.id();
    connection
        .send(Request::Subscribe {
            id: subscribe,
            working_dir: Some(std::env::current_dir()?.display().to_string()),
            selfdev: None,
            target_session_id: resume.map(str::to_owned),
            client_instance_id: Some(format!("run-{}", std::process::id())),
            client_has_local_history: false,
            allow_session_takeover: false,
            crash_on_disconnect: false,
            continue_on_disconnect: false,
            terminal_env: crate::terminal_launch::snapshot_client_terminal_env(),
        })
        .await?;
    connection.done(subscribe).await?;
    let history = connection.id();
    connection.send(Request::GetHistory { id: history }).await?;
    let (provider_name, mut provider_model, server_credential) = loop {
        match connection.read().await? {
            ServerEvent::History {
                id,
                session_id,
                provider_name,
                provider_model,
                resolved_credential,
                ..
            } if id == history => {
                lifecycle.session_id = session_id;
                break (
                    provider_name.unwrap_or_default(),
                    provider_model.unwrap_or_default(),
                    resolved_credential,
                );
            }
            ServerEvent::Error { message, .. } => bail!(message),
            _ => {}
        }
    };
    // History carries Agent::provider_name(), which uses display_name(). A
    // compatible gateway can share the "openrouter" implementation name while
    // advertising "OpenAI-compatible" or a named endpoint profile.
    if !provider_name.eq_ignore_ascii_case(&provider.display_name())
        && !provider_name.eq_ignore_ascii_case(provider.name())
    {
        bail!(
            "server session uses provider {provider_name}, but this run requested {}; start a matching server",
            provider.name()
        );
    }
    if let (Some(server), Some(requested)) =
        (server_credential, provider.active_resolved_credential())
    {
        if server != requested {
            bail!("server session uses a different credential mode; start a matching server");
        }
    }
    if let Some(model) = model {
        if provider_model != model {
            let id = connection.id();
            connection
                .send(Request::SetModel {
                    id,
                    model: model.to_owned(),
                })
                .await?;
            loop {
                match connection.read().await? {
                    ServerEvent::ModelChanged {
                        id: response,
                        model,
                        error,
                        ..
                    } if response == id => {
                        if let Some(error) = error {
                            bail!(error);
                        }
                        provider_model = model;
                        break;
                    }
                    ServerEvent::Error { message, .. } => bail!(message),
                    _ => {}
                }
            }
        }
    }
    eprintln!("[trace] session_id {}", lifecycle.session_id);
    if ndjson {
        println!(
            "{}",
            serde_json::json!({"type":"start", "session_id":lifecycle.session_id,
            "provider":provider_name, "model":provider_model})
        );
    }
    let id = connection.id();
    connection
        .send(Request::Message {
            id,
            content: message.to_owned(),
            images: Vec::new(),
            system_reminder: None,
            active_skill: None,
            no_reply: false,
        })
        .await?;
    let mut active_request = id;
    let mut text = String::new();
    let mut usage = crate::agent::TokenUsage::default();
    let mut state_request = None;
    let mut status_requests = HashMap::new();
    let mut context_requests = HashMap::new();
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            event = connection.read() => {
                let event = event?;
                if ndjson {
                    // Preserve the native event schema, including worker/wake events.
                    // The terminal run result is emitted only once, below.
                    if !matches!(event, ServerEvent::Done { .. }) {
                        println!("{}", serde_json::to_string(&event)?);
                    }
                }
                match event {
                    ServerEvent::TextDelta { text: delta } => {
                        text.push_str(&delta);
                        if !json && !ndjson { print!("{delta}"); std::io::stdout().flush()?; }
                    }
                    ServerEvent::TextReplace { text: replacement } => { text = replacement; }
                    ServerEvent::RetryRollback { .. } => { text.clear(); }
                    ServerEvent::TokenUsage { input, output, cache_read_input, cache_creation_input } => {
                        usage = crate::agent::TokenUsage { input_tokens: input, output_tokens: output,
                            cache_read_input_tokens: cache_read_input, cache_creation_input_tokens: cache_creation_input };
                        eprintln!("[trace] token_usage input={input} output={output} cache_read={} cache_write={}",
                            cache_read_input.unwrap_or(0), cache_creation_input.unwrap_or(0));
                    }
                    ServerEvent::SwarmStatus { members } => lifecycle.status(members),
                    ServerEvent::Notification { from_session, message, .. } => lifecycle.report(from_session, message),
                    ServerEvent::WakeRequested { notification, .. } => {
                        // External-wake daemons ask the attached client to continue.
                        lifecycle.reports.insert("wake".to_owned(), notification);
                    }
                    ServerEvent::Done { id } if id == active_request || id == 0 => {
                        lifecycle.turn_done = true;
                        lifecycle.changed = Some(Instant::now());
                    }
                    ServerEvent::CommStatusResponse { id, snapshot } => {
                        if let Some(worker) = status_requests.remove(&id) {
                            let processing = snapshot.activity.is_some_and(|activity| activity.is_processing)
                                || (snapshot.provider_name.is_none()
                                    && !matches!(snapshot.status.as_deref(), Some("failed" | "crashed" | "stopped")));
                            lifecycle.worker_processing.insert(worker, processing);
                        }
                    }
                    ServerEvent::CommContextHistory { id, session_id, messages } => {
                        if context_requests.remove(&id).as_deref() == Some(session_id.as_str()) {
                            // A structured report may contain only a short summary.
                            // Fetch the worker's final assistant response after its
                            // turn stops, so the coordinator gets the actual result.
                            let final_text = messages.iter().rev().find(|message|
                                message.role == "assistant" && !message.content.trim().is_empty()
                                    && message.tool_calls.as_ref().is_none_or(Vec::is_empty))
                                .map(|message| message.content.clone()).unwrap_or_default();
                            lifecycle.final_reports.insert(session_id.clone(), final_text.clone());
                            lifecycle.report(session_id, final_text);
                        }
                    }
                    ServerEvent::State { id, is_processing, .. } if state_request == Some(id) => {
                        state_request = None;
                        if !is_processing && lifecycle.turn_done {
                            if !lifecycle.reports.is_empty() && lifecycle.workers_finished()
                                && lifecycle.workers.keys().all(|id| lifecycle.final_reports.contains_key(id)) {
                                let mut reports: Vec<_> = lifecycle.reports.drain().collect();
                                reports.sort_by(|a,b| a.0.cmp(&b.0));
                                let content = format!("Worker notifications:\n{}\nReview these reports and continue the original task.",
                                    reports.into_iter().map(|(from, message)| {
                                        let result = lifecycle.final_reports.get(&from).map(String::as_str).unwrap_or("");
                                        format!("[{from}] {message}\nFinal worker response:\n{result}")
                                    }).collect::<Vec<_>>().join("\n"));
                                active_request = connection.id();
                                connection.send(Request::Message { id: active_request, content, images: Vec::new(),
                                    system_reminder: None, active_skill: None, no_reply: false }).await?;
                                lifecycle.turn_done = false;
                            } else if lifecycle.settled() { break; }
                        }
                    }
                    ServerEvent::Error { id, retry_after_secs: Some(_), .. } if context_requests.contains_key(&id) => {
                        // A worker can restart between its idle snapshot and read.
                        context_requests.remove(&id);
                    }
                    ServerEvent::Error { message, .. } => bail!(message),
                    ServerEvent::SessionCloseRequested { reason } => bail!("server closed run session: {reason}"),
                    _ => {}
                }
            }
            _ = poll.tick() => {
                if state_request.is_none() {
                    let id = connection.id();
                    state_request = Some(id);
                    connection.send(Request::GetState { id }).await?;
                }
                for worker in lifecycle.workers.keys() {
                    if status_requests.values().any(|pending| pending == worker) { continue; }
                    let id = connection.id();
                    status_requests.insert(id, worker.clone());
                    connection.send(Request::CommStatus { id, session_id: lifecycle.session_id.clone(),
                        target_session: worker.clone() }).await?;
                }
                for (worker, member) in &lifecycle.workers {
                    if lifecycle.final_reports.contains_key(worker) || context_requests.values().any(|pending| pending == worker)
                        || lifecycle.worker_processing.get(worker) != Some(&false) { continue; }
                    if matches!(member.status.as_str(), "failed" | "crashed" | "stopped") {
                        lifecycle.final_reports.insert(worker.clone(), member.detail.clone().unwrap_or_else(|| member.status.clone()));
                    } else if matches!(member.status.as_str(), "ready" | "completed" | "done") {
                        let id = connection.id();
                        context_requests.insert(id, worker.clone());
                        connection.send(Request::CommReadContext { id, session_id: lifecycle.session_id.clone(),
                            target_session: worker.clone() }).await?;
                    }
                }
            }
        }
    }
    let failed: Vec<_> = lifecycle
        .workers
        .values()
        .filter(|member| matches!(member.status.as_str(), "failed" | "crashed" | "stopped"))
        .map(|m| m.session_id.clone())
        .collect();
    if !failed.is_empty() {
        bail!(
            "swarm workers did not complete successfully: {}",
            failed.join(", ")
        );
    }
    let report = serde_json::json!({"session_id":lifecycle.session_id, "provider":provider_name,
        "model":provider_model, "text":text, "usage":usage});
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if ndjson {
        println!("{}", serde_json::json!({"type":"result", "result":report}));
    } else {
        println!();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn polling_does_not_drop_a_partial_socket_event() {
        let (client, mut daemon) = crate::transport::stream_pair().unwrap();
        let (reader, writer) = client.into_split();
        let mut connection = Connection {
            reader: BufReader::new(reader).lines(),
            writer,
            next_id: 1,
        };
        daemon.write_all(b"{\"type\":\"pong\",").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(5), connection.read())
                .await
                .is_err()
        );
        daemon.write_all(b"\"id\":42}\n").await.unwrap();
        assert!(matches!(
            connection.read().await.unwrap(),
            ServerEvent::Pong { id: 42, .. }
        ));
        drop(daemon);
        assert!(
            connection.read().await.is_err(),
            "disconnect must not look like successful completion"
        );
    }

    fn worker(status: &str, parent: &str) -> SwarmMemberStatus {
        serde_json::from_value(serde_json::json!({
            "session_id":"child", "status":status, "report_back_to_session_id":parent
        }))
        .unwrap()
    }

    #[test]
    fn first_parent_done_does_not_finish_running_workers() {
        let mut state = Lifecycle {
            session_id: "parent".into(),
            turn_done: true,
            ..Default::default()
        };
        state.status(vec![worker("running", "parent")]);
        state.changed = None;
        assert!(!state.settled());
        state.status(vec![worker("ready", "parent")]);
        state.changed = None;
        assert!(
            !state.settled(),
            "a report may set ready before the worker actually stops"
        );
        state.worker_processing.insert("child".into(), false);
        assert!(
            !state.settled(),
            "the final assistant report must be collected before exiting"
        );
        state
            .final_reports
            .insert("child".into(), "actual result".into());
        assert!(state.settled());
        state.report("child".into(), "real worker report".into());
        assert!(
            !state.settled(),
            "pending reports require another coordinator turn"
        );
    }

    #[test]
    fn unrelated_sessions_are_not_awaited_or_injected() {
        let mut state = Lifecycle {
            session_id: "parent".into(),
            turn_done: true,
            ..Default::default()
        };
        state.status(vec![worker("running", "other-parent")]);
        state.report("child".into(), "unrelated report".into());
        assert!(state.workers.is_empty());
        assert!(state.reports.is_empty());
        assert!(state.settled());
    }

    #[test]
    fn restarted_worker_invalidates_previous_idle_snapshot() {
        let mut state = Lifecycle {
            session_id: "parent".into(),
            turn_done: true,
            ..Default::default()
        };
        state.status(vec![worker("ready", "parent")]);
        state.worker_processing.insert("child".into(), false);
        state.status(vec![worker("running", "parent")]);
        assert!(!state.workers_finished());
        assert!(!state.worker_processing.contains_key("child"));
    }
}
