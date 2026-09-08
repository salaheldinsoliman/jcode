
use std::path::{Path, PathBuf};

/// Run the taint-analysis gate for a proposed `.py` write/edit.
///
/// Returns `None` when the write should proceed (non-Python file, analyzer
/// unavailable, or no new findings). Returns `Some(refusal)` when the
/// analyzer found taint paths this write introduces that weren't present in
/// the project before — `refusal` is meant to be surfaced to the model as
/// the tool's error text so it can fix the flagged flow and retry.
pub(crate) async fn python_write_refusal(
    working_dir: Option<PathBuf>,
    target_path: &Path,
    proposed_content: &str,
) -> Option<String> {
    let Some(working_dir) = working_dir else {
        return None;
    };
    let target_path = target_path.to_path_buf();
    let content = proposed_content.to_string();

    // The analyzer shells out and copies the project tree; keep it off the
    // async runtime's worker threads.
    let assessment = tokio::task::spawn_blocking(move || {
        jcode_security_lint::assess_python_write(&working_dir, &target_path, &content)
    })
    .await
    .ok()?;

    match jcode_security_lint::gate(&assessment) {
        jcode_security_lint::GateOutcome::Allow => None,
        jcode_security_lint::GateOutcome::Deny { reason } => {
            crate::logging::warn(&format!(
                "[security-lint] blocked write introducing new taint findings: {}",
                target_path_display(&assessment)
            ));
            Some(reason)
        }
    }
}

fn target_path_display(assessment: &jcode_security_lint::Assessment) -> String {
    assessment
        .new_findings
        .first()
        .map(|f| f.uri.clone())
        .unwrap_or_default()
}
