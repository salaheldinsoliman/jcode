//! One ordered recorder per session. Retrieval never locks recorder state.
use super::{MemoryBackend, RetrievedMemory, SecurityMemory, SecurityMemoryOptions};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;

struct Observation {
    tool: String,
    input: Arc<Value>,
    output: String,
    succeeded: bool,
    project_root: Option<PathBuf>,
}

#[derive(Default)]
struct Recorder {
    sender: Option<mpsc::Sender<Observation>>,
    worker: Option<JoinHandle<SecurityMemory>>,
}

pub struct SecurityMemorySession {
    // The reader uses only the staged store, without the recorder's mutable state.
    reader: SecurityMemory,
    recent_inputs: Mutex<Vec<Arc<Value>>>,
    recorder: Mutex<Recorder>,
}

impl SecurityMemorySession {
    pub fn new(options: SecurityMemoryOptions, backend: Arc<dyn MemoryBackend>) -> Self {
        let reader = SecurityMemory::new(options.clone(), Arc::clone(&backend));
        let mut recorder = Recorder::default();
        if options.mode.writes() {
            let (sender, receiver) = mpsc::channel::<Observation>();
            let worker = std::thread::Builder::new()
                .name("security-memory-recorder".into())
                .spawn(move || {
                    let mut memory = SecurityMemory::new(options, backend);
                    for observation in receiver {
                        // A backend panic is a recording error, not a session
                        // failure. Keep consuming later observations.
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            memory.set_project_root(observation.project_root.as_deref());
                            memory.observe(
                                &observation.tool,
                                &observation.input,
                                &observation.output,
                                observation.succeeded,
                            );
                        }));
                        if result.is_err() {
                            eprintln!("security memory: recorder panicked on a tool result");
                        }
                    }
                    memory.flush();
                    memory
                });
            match worker {
                Ok(worker) => {
                    recorder.sender = Some(sender);
                    recorder.worker = Some(worker);
                }
                Err(error) => eprintln!("security memory: recorder could not start: {error}"),
            }
        }
        Self {
            reader,
            recent_inputs: Mutex::new(Vec::new()),
            recorder: Mutex::new(recorder),
        }
    }

    pub fn writes(&self) -> bool {
        self.reader.options.mode.writes()
    }

    /// Keep native tool inputs even when they are absent from conversation
    /// history. Parsing focus is deferred to retrieval, not done on submission.
    pub fn track_focus(&self, input: Value) {
        self.track_input(Arc::new(input));
    }

    fn track_input(&self, input: Arc<Value>) {
        if self.reader.options.mode == super::MemoryMode::Off {
            return;
        }
        match self.recent_inputs.lock() {
            Ok(mut inputs) => {
                inputs.push(input);
                if inputs.len() > 6 {
                    inputs.remove(0);
                }
            }
            Err(error) => eprintln!("security memory: focus lock failed: {error}"),
        }
    }

    /// No embedding, parsing or disk work on the caller. The unbounded queue
    /// keeps accepted observations rather than blocking or dropping on capacity.
    /// Its backlog can grow if the backend cannot keep up with tool execution.
    pub fn enqueue(
        &self,
        tool: String,
        input: Value,
        output: String,
        succeeded: bool,
        project_root: Option<PathBuf>,
    ) {
        let input = Arc::new(input);
        if !self.writes() {
            self.track_input(input);
            return;
        }
        let recorder = match self.recorder.lock() {
            Ok(recorder) => recorder,
            Err(error) => {
                eprintln!("security memory: queue lock failed: {error}");
                return;
            }
        };
        let Some(sender) = &recorder.sender else {
            eprintln!("security memory: recorder unavailable or session closed");
            return;
        };
        self.track_input(Arc::clone(&input));
        if let Err(error) = sender.send(Observation {
            tool,
            input,
            output,
            succeeded,
            project_root,
        }) {
            eprintln!("security memory: could not enqueue tool result: {error}");
        }
    }

    pub fn retrieve(&self, focus: &str) -> Option<RetrievedMemory> {
        if !self.reader.options.mode.reads() {
            return None;
        }
        let inputs = match self.recent_inputs.lock() {
            Ok(inputs) => inputs.clone(),
            Err(error) => {
                eprintln!("security memory: focus lock failed: {error}");
                Vec::new()
            }
        };
        let recent = inputs
            .iter()
            .map(|input| super::focus_from_tool(input))
            .collect::<Vec<_>>()
            .join("\n");
        self.reader.retrieve(&format!("{focus}\n{recent}"))
    }

    /// Stop accepting results, drain every accepted observation, and return the
    /// final recorder state for optional summarization. Repeated close is a no-op.
    /// Background tools completing after this boundary are logged and skipped.
    pub fn close(&self) -> Option<SecurityMemory> {
        let worker = {
            let mut recorder = match self.recorder.lock() {
                Ok(recorder) => recorder,
                Err(error) => {
                    eprintln!("security memory: close lock failed: {error}");
                    return None;
                }
            };
            // This is the only sender. Dropping it lets the receiver drain all
            // queued observations and then exit. Release the lock before joining.
            recorder.sender.take();
            recorder.worker.take()
        }?;
        match worker.join() {
            Ok(memory) => Some(memory),
            Err(_) => {
                eprintln!("security memory: recorder worker panicked during shutdown");
                None
            }
        }
    }
}

impl Drop for SecurityMemorySession {
    fn drop(&mut self) {
        // Also persist pending work when a caller replaces/drops the session
        // without an explicit close. Optional provider calls require explicit close.
        self.close();
    }
}

#[cfg(test)]
mod tests;
