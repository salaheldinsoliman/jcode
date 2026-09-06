//! security-context gate for the `write`/`edit` tools.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One taint-analysis finding, reduced from SARIF to what we need to compare
/// baseline vs. candidate scans and to explain a refusal to the model.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Finding {
    pub rule_id: String,
    pub message: String,
    pub uri: String,
    pub line: u64,
    pub column: u64,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}: [{}] {}",
            self.uri, self.line, self.column, self.rule_id, self.message
        )
    }
}

/// Result of comparing a baseline scan (project as it exists on disk) against
/// a candidate scan (project with one file's proposed new content
/// substituted in).
#[derive(Debug, Clone, Default)]
pub struct Assessment {
    /// Findings present in the candidate scan but not the baseline — i.e.
    /// introduced by the write/edit under consideration.
    pub new_findings: Vec<Finding>,
}

impl Assessment {
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Gate verdict, mirroring `jcode_command_risk::GateOutcome`'s shape without
/// the `Reflect`/justification variant — a plain `write`/`edit` call has no
/// justification field to re-issue against, so `Deny` alone is enough: the
/// model sees the refusal as its tool error and can retry with a fix.
pub enum GateOutcome {
    Allow,
    Deny { reason: String },
}

pub fn gate(assessment: &Assessment) -> GateOutcome {
    if assessment.new_findings.is_empty() {
        return GateOutcome::Allow;
    }
    GateOutcome::Deny {
        reason: format_reason(&assessment.new_findings),
    }
}

fn format_reason(findings: &[Finding]) -> String {
    let mut out = String::from(
        "blocked: this write introduces new taint-analysis findings (tiny_taint) not present in the project before:\n",
    );
    for finding in findings {
        out.push_str(&format!("  - {}\n", finding));
    }
    out.push_str("Fix the flagged data flow (e.g. sanitize/validate before it reaches the sink) and retry the write.");
    out
}

/// Directories never worth copying into the scan sandbox: VCS metadata,
/// dependency/build output, caches. Keeps the per-write copy fast and avoids
/// scanning code that isn't part of the project anyway.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "venv",
    ".venv",
    "node_modules",
    "target",
];

/// Assess a proposed write/edit to a Python file: substitute `proposed_content`
/// for `target_abs_path` inside a throwaway copy of `working_dir`, scan
/// before and after, and return only the findings the change introduces.
///
/// Fails open (`Assessment::empty()`, i.e. `GateOutcome::Allow`) whenever the
/// analyzer can't run at all — missing binary, non-UTF8 paths, I/O errors —
/// so a broken/missing analyzer degrades to "no policy" rather than blocking
/// every Python write in every session.
pub fn assess_python_write(
    working_dir: &Path,
    target_abs_path: &Path,
    proposed_content: &str,
) -> Assessment {
    if target_abs_path.extension().and_then(|e| e.to_str()) != Some("py") {
        return Assessment::empty();
    }

    match try_assess(working_dir, target_abs_path, proposed_content) {
        Ok(assessment) => assessment,
        Err(err) => {
            log_warn(&format!("[security-lint] skipping check: {err:#}"));
            Assessment::empty()
        }
    }
}

fn try_assess(
    working_dir: &Path,
    target_abs_path: &Path,
    proposed_content: &str,
) -> Result<Assessment> {
    let binary = resolve_binary()?;
    let rel_path = target_abs_path
        .strip_prefix(working_dir)
        .context("target file is outside the working directory")?
        .to_path_buf();

    let sandbox = tempfile::tempdir().context("creating scan sandbox")?;
    copy_dir_filtered(working_dir, sandbox.path())?;

    let sandboxed_target = sandbox.path().join(&rel_path);

    // Baseline: project exactly as it exists on disk right now.
    let baseline = run_scan(&binary, sandbox.path())?;

    // Candidate: the one file under consideration replaced with its
    // proposed new content; everything else in the sandbox is unchanged.
    if let Some(parent) = sandboxed_target.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&sandboxed_target, proposed_content)
        .with_context(|| format!("writing candidate content for {}", rel_path.display()))?;
    let candidate = run_scan(&binary, sandbox.path())?;

    let baseline_set: HashSet<Finding> = baseline.into_iter().collect();
    let new_findings = candidate
        .into_iter()
        .filter(|f| !baseline_set.contains(f))
        .collect();

    Ok(Assessment { new_findings })
}

/// `JCODE_TAINT_BIN` overrides; otherwise rely on `tiny_taint` being on
/// `PATH` (same convention `bash_destructive_gate`-style external-tool gates
/// use elsewhere, and what the `pre_tool` hook docs recommend for policy
/// scripts).
fn resolve_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("JCODE_TAINT_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        anyhow::bail!("JCODE_TAINT_BIN={} does not exist", path.display());
    }
    Ok(PathBuf::from("tiny_taint"))
}

fn run_scan(binary: &Path, dir: &Path) -> Result<Vec<Finding>> {
    let output = Command::new(binary)
        .arg("sarif")
        .arg(dir)
        .output()
        .with_context(|| format!("spawning {}", binary.display()))?;

    if !output.status.success() {
        anyhow::bail!(
            "{} exited with {}: {}",
            binary.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    parse_sarif(&output.stdout)
}

fn parse_sarif(bytes: &[u8]) -> Result<Vec<Finding>> {
    #[derive(Deserialize)]
    struct Sarif {
        runs: Vec<Run>,
    }
    #[derive(Deserialize)]
    struct Run {
        results: Vec<SarifResult>,
    }
    #[derive(Deserialize)]
    struct SarifResult {
        #[serde(rename = "ruleId")]
        rule_id: String,
        message: Msg,
        locations: Vec<Loc>,
    }
    #[derive(Deserialize)]
    struct Msg {
        text: String,
    }
    #[derive(Deserialize)]
    struct Loc {
        #[serde(rename = "physicalLocation")]
        physical_location: PhysicalLocation,
    }
    #[derive(Deserialize)]
    struct PhysicalLocation {
        #[serde(rename = "artifactLocation")]
        artifact_location: ArtifactLocation,
        region: Region,
    }
    #[derive(Deserialize)]
    struct ArtifactLocation {
        uri: String,
    }
    #[derive(Deserialize)]
    struct Region {
        #[serde(rename = "startLine")]
        start_line: u64,
        #[serde(rename = "startColumn", default)]
        start_column: u64,
    }

    let sarif: Sarif = serde_json::from_slice(bytes).context("parsing tiny_taint SARIF output")?;
    let mut findings = Vec::new();
    for run in sarif.runs {
        for result in run.results {
            let Some(loc) = result.locations.first() else {
                continue;
            };
            findings.push(Finding {
                rule_id: result.rule_id,
                message: result.message.text,
                uri: loc.physical_location.artifact_location.uri.clone(),
                line: loc.physical_location.region.start_line,
                column: loc.physical_location.region.start_column,
            });
        }
    }
    Ok(findings)
}

fn copy_dir_filtered(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if file_type.is_dir() {
            if SKIP_DIRS.contains(&name_str.as_ref()) {
                continue;
            }
            copy_dir_filtered(&entry.path(), &dst.join(&name))?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), dst.join(&name))?;
        }
        // Symlinks are intentionally skipped: not relevant to scanning
        // source text, and avoids escaping the sandbox.
    }
    Ok(())
}

/// Best-effort logging that doesn't pull in `jcode-app-core` (would create a
/// dependency cycle, since this crate is meant to be called from there).
fn log_warn(msg: &str) {
    eprintln!("{msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sarif_results() {
        let sarif = serde_json::json!({
            "runs": [{
                "results": [{
                    "ruleId": "PYTAINT001",
                    "level": "error",
                    "message": {"text": "tainted data reaches `eval`"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "app.py"},
                            "region": {"startLine": 10, "startColumn": 5}
                        }
                    }]
                }]
            }]
        });
        let findings = parse_sarif(sarif.to_string().as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PYTAINT001");
        assert_eq!(findings[0].uri, "app.py");
        assert_eq!(findings[0].line, 10);
    }

    #[test]
    fn non_python_files_are_not_applicable() {
        let assessment = assess_python_write(
            Path::new("/tmp/does-not-matter"),
            Path::new("/tmp/does-not-matter/main.rs"),
            "fn main() {}",
        );
        assert!(assessment.new_findings.is_empty());
    }

    #[test]
    fn missing_binary_fails_open() {
        // SAFETY: single-threaded test process; no other test reads this var.
        unsafe {
            std::env::set_var("JCODE_TAINT_BIN", "/nonexistent/tiny_taint");
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "x = 1\n").unwrap();
        let assessment = assess_python_write(dir.path(), &dir.path().join("app.py"), "y = 2\n");
        unsafe {
            std::env::remove_var("JCODE_TAINT_BIN");
        }
        assert!(assessment.new_findings.is_empty(), "must fail open");
    }
}
