use super::*;
use jcode_memory_types::graph::EdgeKind;
use serde_json::json;

struct FixtureBackend;
impl MemoryBackend for FixtureBackend {
    fn remember(&self, path: &Path, entry: MemoryEntry) -> Result<String> {
        let mut graph = load_store(path)?;
        let id = merge_entry(&mut graph, entry);
        save_store(path, &graph)?;
        Ok(id)
    }
    fn retrieve(
        &self,
        path: &Path,
        _query: &str,
        limit: usize,
        filter: &StoreFilter,
    ) -> Result<Vec<MemoryEntry>> {
        let graph = load_store(path)?;
        let mut entries: Vec<_> = graph
            .active_memories()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        entries.truncate(limit);
        Ok(entries)
    }
}
fn fixture(mode: MemoryMode, role: &str) -> (tempfile::TempDir, SecurityMemory) {
    let dir = tempfile::tempdir().unwrap();
    let options = SecurityMemoryOptions {
        mode,
        path: Some(dir.path().join("snapshot.json")),
        delta: Some(dir.path().join("delta.json")),
        role: role.into(),
        code: "v1".into(),
        run: "1".into(),
        stage: "test".into(),
        producer: "attacker_brief_threats".into(),
        ..Default::default()
    };
    let mut memory = SecurityMemory::new(options, Arc::new(FixtureBackend));
    memory.set_project_root(Some(Path::new("/project")));
    (dir, memory)
}
fn write_test_file(memory: &mut SecurityMemory, path: &str) {
    memory.observe(
        "write",
        &json!({"file_path": path, "content": "# session-written test"}),
        "Written",
        true,
    );
}
fn test_result(memory: &mut SecurityMemory, status: &str) {
    write_test_file(memory, "tests/test_render.py");
    memory.observe(
        "bash",
        &json!({"command":"pytest -v tests/test_render.py"}),
        &format!("tests/test_render.py::test_untrusted {status}\n"),
        true,
    );
}

#[test]
fn recording_and_reinforcement_use_only_the_delta() {
    let (dir, mut memory) = fixture(MemoryMode::Both, "attacker");
    save_store(memory.options.path.as_ref().unwrap(), &MemoryGraph::new()).unwrap();
    let snapshot = std::fs::read(memory.options.path.as_ref().unwrap()).unwrap();
    test_result(&mut memory, "FAILED");
    test_result(&mut memory, "FAILED");
    let graph = load_store(&dir.path().join("delta.json")).unwrap();
    assert_eq!(graph.memories.len(), 1);
    let entry = graph.active_memories().next().unwrap();
    assert_eq!(entry.strength, 2);
    assert_eq!(entry.trust, TrustLevel::High);
    for tag in [
        "run:1",
        "stage:test",
        "role:attacker",
        "code:v1",
        "kind:finding",
    ] {
        assert!(entry.tags.contains(&tag.into()));
    }
    assert_eq!(
        snapshot,
        std::fs::read(memory.options.path.as_ref().unwrap()).unwrap()
    );
}
#[test]
fn a_status_change_supersedes_instead_of_reinforcing() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    test_result(&mut memory, "FAILED");
    test_result(&mut memory, "PASSED");
    let graph = load_store(&dir.path().join("delta.json")).unwrap();
    assert_eq!(graph.memories.len(), 2);
    assert_eq!(graph.active_memories().count(), 1);
    assert!(
        graph
            .edges
            .values()
            .flatten()
            .any(|e| e.kind == EdgeKind::Supersedes)
    );
    assert!(
        graph
            .active_memories()
            .next()
            .unwrap()
            .tags
            .contains(&"status:passed".into())
    );
}
#[test]
fn brief_claims_and_edits_have_distinct_kinds_and_trust() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "brief");
    memory.observe("write", &json!({"file_path":"/tmp/brief.md", "content":"## Threats\n- [T1] untrusted template in render.py\n## Security points\n- escape output\n## Functional points\n- preserve rendering"}), "Written", true);
    let graph = load_store(&dir.path().join("delta.json")).unwrap();
    assert_eq!(graph.memories.len(), 3);
    assert!(
        graph
            .memories
            .values()
            .all(|e| e.trust == TrustLevel::Medium)
    );
    memory.options.role = "defender".into();
    memory.observe("edit", &json!({"file_path":"render.py", "new_string":"def render(value): return escape(value) # [T1]"}), "Edited", true);
    let graph = load_store(&dir.path().join("delta.json")).unwrap();
    let fix = graph
        .memories
        .values()
        .find(|e| e.category == MemoryCategory::Custom("fix".into()))
        .unwrap();
    assert!(fix.tags.contains(&"function:render".into()));
    assert!(fix.tags.contains(&"brief:T1".into()));
}
#[test]
fn brief_heredocs_are_observed_without_opening_the_file() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "brief");
    memory.observe(
        "bash",
        &json!({"command":"cat > /tmp/brief.md <<'EOF'\n## Threats\n- untrusted template\nEOF\n"}),
        "Command completed successfully (no output)",
        true,
    );
    assert_eq!(
        load_store(&dir.path().join("delta.json"))
            .unwrap()
            .memories
            .len(),
        1
    );
}
#[test]
fn failed_edits_and_unrecognized_tools_do_not_create_evidence() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "defender");
    memory.observe(
        "edit",
        &json!({"file_path":"render.py", "new_string":"def render(): pass"}),
        "Error",
        false,
    );
    memory.observe("ls", &json!({"path":"/tmp/brief.md"}), "report.json", true);
    assert!(!dir.path().join("delta.json").exists());
}
#[test]
fn batch_results_are_paired_with_actual_subcalls() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "feature");
    memory.observe("batch", &json!({"tool_calls":[{"tool":"write", "file_path":"render.py", "content":"def render(): pass"}, {"tool":"write", "file_path":"failed.py", "content":"def broken(): pass"}]}),
        "--- [1] write ---\nWritten\n\n--- [2] write ---\nError: denied\n\nCompleted: 1 succeeded, 1 failed", true);
    let graph = load_store(&dir.path().join("delta.json")).unwrap();
    assert_eq!(graph.memories.len(), 1);
    assert!(
        graph
            .active_memories()
            .next()
            .unwrap()
            .tags
            .contains(&"file:render.py".into())
    );
}
#[test]
fn following_session_retrieves_ids_and_marks_old_code_for_retest() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    test_result(&mut memory, "FAILED");
    merge_files(
        memory.options.path.as_ref().unwrap(),
        &[dir.path().join("delta.json")],
    )
    .unwrap();
    memory.options.mode = MemoryMode::Read;
    memory.options.role = "defender".into();
    memory.options.code = "v2".into();
    let result = memory.retrieve("render.py").unwrap();
    assert!(result.prompt.starts_with("# Security memory"));
    assert!(result.prompt.contains("re-test"));
    assert!(result.prompt.contains(&result.ids[0]));
    memory.options.code = "v1".into();
    assert!(
        !memory
            .retrieve("render.py")
            .unwrap()
            .prompt
            .contains("re-test")
    );
}
#[test]
fn store_filter_obeys_role_kind_and_version() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    test_result(&mut memory, "FAILED");
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    let entry = graph.active_memories().next().unwrap();
    let mut filter = StoreFilter {
        roles: vec!["attacker".into()],
        kinds: vec!["finding".into()],
        codes: vec!["v1".into()],
    };
    assert!(filter.matches(entry));
    filter.codes = vec!["v2".into()];
    assert!(!filter.matches(entry));
    filter.codes.clear();
    filter.roles = vec!["brief".into()];
    assert!(!filter.matches(entry));
}
#[test]
fn off_default_has_no_context_or_files_even_with_paths_set() {
    assert_eq!(
        SecurityMemoryOptions::from_values(|_| None).mode,
        MemoryMode::Off
    );
    let (dir, mut memory) = fixture(MemoryMode::Off, "attacker");
    test_result(&mut memory, "FAILED");
    memory.flush();
    assert!(memory.retrieve("render").is_none());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    assert!(memory.take_summary_prompt().is_none());
}
#[test]
fn conflicts_survive_merges_and_replays_do_not_reinforce_again() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    test_result(&mut memory, "FAILED");
    let delta = dir.path().join("delta.json");
    let store = dir.path().join("store.json");
    merge_files(&store, std::slice::from_ref(&delta)).unwrap();
    memory.options.delta = Some(dir.path().join("other.json"));
    test_result(&mut memory, "PASSED");
    merge_files(&store, &[memory.options.delta.clone().unwrap()]).unwrap();
    let graph = load_store(&store).unwrap();
    assert_eq!(graph.active_memories().count(), 2);
    assert!(
        graph
            .edges
            .values()
            .flatten()
            .any(|e| e.kind == EdgeKind::Contradicts)
    );
    let before = std::fs::read(&store).unwrap();
    merge_files(&store, &[delta, memory.options.delta.clone().unwrap()]).unwrap();
    let after = load_store(&store).unwrap();
    let before: Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(before, serde_json::to_value(after).unwrap());
}
#[test]
fn near_duplicate_embeddings_reinforce_only_same_subject_and_code() {
    let mut graph = MemoryGraph::new();
    let mut first = MemoryEntry::new(
        MemoryCategory::Custom("finding".into()),
        "first observation",
    );
    first.tags = vec![
        "subject:test1".into(),
        "code:v1".into(),
        "role:attacker".into(),
    ];
    first.embedding = Some(vec![1.0, 0.0]);
    merge_entry(&mut graph, first.clone());
    let mut second = first.clone();
    second.id = "second".into();
    second.content = "similar observation".into();
    merge_entry(&mut graph, second.clone());
    assert_eq!(graph.memories.len(), 1);
    merge_entry(&mut graph, second.clone());
    assert_eq!(graph.active_memories().next().unwrap().strength, 2);
    second.id = "different-test".into();
    second.tags[0] = "subject:test2".into();
    merge_entry(&mut graph, second);
    assert_eq!(graph.memories.len(), 2);
}
#[test]
fn corrupt_read_or_unwritable_delta_is_best_effort() {
    let (dir, mut memory) = fixture(MemoryMode::Both, "attacker");
    std::fs::write(memory.options.path.as_ref().unwrap(), "invalid").unwrap();
    memory.options.delta = Some(dir.path().to_path_buf());
    test_result(&mut memory, "FAILED");
    memory.flush();
    assert!(memory.retrieve("render").is_none());
}

#[test]
fn project_edits_exclude_temporary_outputs_and_record_shell_patches() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "defender");
    memory.set_project_root(Some(Path::new("/project")));
    memory.observe(
        "write",
        &json!({"file_path":"/tmp/scratch.py", "content":"def render(): pass"}),
        "Written",
        true,
    );
    assert!(!dir.path().join("delta.json").exists());
    memory.observe("bash", &json!({"command":"apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: /project/render.py\n@@\n+def render(value): return escape(value)\n*** End Patch\nPATCH"}), "Success", true);
    let graph = load_store(&dir.path().join("delta.json")).unwrap();
    assert_eq!(graph.memories.len(), 1);
    assert!(
        graph
            .active_memories()
            .next()
            .unwrap()
            .tags
            .contains(&"file:/project/render.py".into())
    );
}

#[test]
fn optional_summary_uses_only_tool_observations_and_starts_once() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    memory.options.summarize = true;
    test_result(&mut memory, "FAILED");
    let prompt = memory.take_summary_prompt().unwrap();
    assert!(prompt.contains("test_untrusted"));
    assert!(memory.take_summary_prompt().is_none());
    memory.summarize_at_end("Check the template entry point early.");
    let graph = load_store(&dir.path().join("delta.json")).unwrap();
    let lesson = graph
        .memories
        .values()
        .find(|e| e.category == MemoryCategory::Custom("lesson".into()))
        .unwrap();
    assert_eq!(lesson.trust, TrustLevel::Low);
}

#[test]
fn unittest_records_mixed_docstring_and_single_line_results_once() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    for path in ["test_legacy.py", "test_modern.py"] {
        write_test_file(&mut memory, path);
    }
    memory.observe(
        "bash",
        &json!({"command": "python -m unittest -v"}),
        "test_pass (test_legacy.SecurityTests)\n\
         Blocks untrusted templates [T2] and [S1] ... ok\n\
         test_fail (test_legacy.SecurityTests)\n\
         Checks escaping [T3] ... FAIL\n\
         test_error (test_modern.SecurityTests.test_error)\n\
         Handles invalid input [F1] ... ERROR\n\
         test_skip (test_modern.SecurityTests.test_skip)\n\
         Optional dependency [T4] ... skipped 'missing'\n\
         test_plain (test_legacy.SecurityTests) ... ok\n\
         test_plain (test_modern.SecurityTests.test_plain) ... FAIL\n\
         test_plain (test_modern.OtherTests.test_plain) ... ok\n\
         test_unfinished (test_modern.SecurityTests.test_unfinished)\n\
         unrelated output\n\
         Not a test result [T99] ... ok\n\
         Ran 7 tests in 0.1s\n\
         FAILED (failures=2, errors=1, skipped=1)\n",
        true,
    );
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), 7);
    for (subject, status, brief_tags) in [
        (
            "test_legacy.SecurityTests.test_pass",
            "passed",
            vec!["brief:T2", "brief:S1"],
        ),
        (
            "test_legacy.SecurityTests.test_fail",
            "failed",
            vec!["brief:T3"],
        ),
        (
            "test_modern.SecurityTests.test_error",
            "error",
            vec!["brief:F1"],
        ),
        (
            "test_modern.SecurityTests.test_skip",
            "skipped",
            vec!["brief:T4"],
        ),
        ("test_legacy.SecurityTests.test_plain", "passed", vec![]),
        ("test_modern.SecurityTests.test_plain", "failed", vec![]),
        ("test_modern.OtherTests.test_plain", "passed", vec![]),
    ] {
        let matching: Vec<_> = graph
            .memories
            .values()
            .filter(|e| {
                tag(e, "subject:") == Some(format!("attacker_brief_threats|{subject}").as_str())
            })
            .collect();
        assert_eq!(matching.len(), 1, "{subject}");
        let entry = matching[0];
        assert_eq!(tag(entry, "status:"), Some(status));
        assert_eq!(entry.strength, 1);
        assert_eq!(entry.trust, TrustLevel::High);
        for brief in brief_tags {
            assert!(entry.tags.iter().any(|t| t == brief));
        }
        assert!(!entry.tags.contains(&"brief:T99".into()));
    }
}

#[test]
fn unittest_identity_is_stable_across_python_versions_and_frozen_modules() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    write_test_file(&mut memory, "tests/test_t1_x.py");
    for output in [
        "test_escape (tests.test_t1_x.SecurityTests) ... FAIL",
        "test_escape (test_attacker_brief_threats__tests_test_t1_x__s1.SecurityTests.test_escape)\nChecks [T1] ... FAIL",
    ] {
        memory.observe(
            "bash",
            &json!({"command": "python -m unittest -v"}),
            output,
            true,
        );
    }
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), 1);
    let entry = graph.active_memories().next().unwrap();
    assert_eq!(
        tag(entry, "subject:"),
        Some("attacker_brief_threats|tests_test_t1_x.SecurityTests.test_escape")
    );
    assert_eq!(entry.strength, 2);
    assert!(entry.tags.contains(&"brief:T1".into()));
}

fn frozen_fix_chain(defender_code: &str, reverse_merge: bool) {
    let (dir, mut attacker) = fixture(MemoryMode::Write, "attacker");
    attacker.options.stage = "attack".into();
    write_test_file(&mut attacker, "/tmp/pentests/test_t1_x.py");
    attacker.observe(
        "bash",
        &json!({"command": "python -m unittest -v"}),
        "test_attack_escape (test_t1_x.SecurityTests)\nRejects injection [T1] ... FAIL",
        true,
    );
    let mut options = attacker.options.clone();
    options.role = "defender".into();
    options.stage = "fix".into();
    options.code = defender_code.into();
    options.delta = Some(dir.path().join("defender.json"));
    let mut defender = SecurityMemory::new(options, Arc::new(FixtureBackend));
    defender.observe("edit", &json!({"file_path":"render.py", "new_string":"def render(value): return escape(value) # [T1]"}), "Edited", true);
    defender.observe("bash", &json!({"command": "python -m unittest -v"}),
        "test_attack_escape (test_attacker_brief_threats__test_t1_x__s1.SecurityTests.test_attack_escape)\nRejects injection [T1] ... ok", true);
    let mut deltas = vec![
        attacker.options.delta.clone().unwrap(),
        defender.options.delta.clone().unwrap(),
    ];
    if reverse_merge {
        deltas.reverse();
    }
    let store = attacker.options.path.as_ref().unwrap();
    merge_files(store, &deltas).unwrap();
    let graph = load_store(store).unwrap();
    let findings: Vec<_> = graph
        .memories
        .values()
        .filter(|e| tag(e, "kind:") == Some("finding"))
        .collect();
    assert_eq!(findings.len(), 2);
    let failed = findings
        .iter()
        .find(|e| tag(e, "status:") == Some("failed"))
        .unwrap();
    let passed = findings
        .iter()
        .find(|e| tag(e, "status:") == Some("passed"))
        .unwrap();
    assert_eq!(tag(failed, "subject:"), tag(passed, "subject:"));
    assert_eq!(tag(passed, "code:"), Some(defender_code));
    assert!(!failed.active);
    assert!(passed.active);
    assert_eq!(failed.superseded_by.as_deref(), Some(passed.id.as_str()));
    let relations: Vec<_> = graph
        .edges
        .values()
        .flatten()
        .filter(|e| matches!(e.kind, EdgeKind::Supersedes | EdgeKind::Contradicts))
        .collect();
    assert_eq!(relations.len(), 1);
    assert_eq!(relations[0].kind, EdgeKind::Supersedes);
    let mut reader_options = defender.options.clone();
    reader_options.mode = MemoryMode::Read;
    reader_options.run = "2".into();
    let reader = SecurityMemory::new(reader_options, Arc::new(FixtureBackend));
    let retrieved = reader.retrieve("test_escape render.py").unwrap();
    assert!(
        retrieved
            .prompt
            .contains("test_t1_x.SecurityTests.test_attack_escape: attack stopped")
    );
    assert!(retrieved.ids.contains(&passed.id));
    assert!(!retrieved.ids.contains(&failed.id));
    assert!(!retrieved.prompt.contains("conflicting evidence"));
}

#[test]
fn defender_pass_on_new_code_supersedes_frozen_attacker_failure() {
    frozen_fix_chain("v2", false);
}

#[test]
fn later_stage_supersedes_with_the_same_session_start_hash() {
    frozen_fix_chain("v1", false);
}

#[test]
fn late_attacker_delta_cannot_replace_later_stage_evidence() {
    frozen_fix_chain("v2", true);
}

#[test]
fn pytest_frozen_subjects_keep_module_class_and_parameter_identity() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    for path in ["test_t1_x.py", "test_t2_x.py"] {
        write_test_file(&mut memory, path);
    }
    memory.observe(
        "bash",
        &json!({"command": "pytest -v"}),
        "test_t1_x.py::SecurityTests::test_escape[html] FAILED\n\
         test_attacker_brief_threats__test_t1_x__s2.py::SecurityTests::test_escape[html] FAILED\n\
         test_t2_x.py::SecurityTests::test_escape[html] PASSED\n\
         test_t1_x.py::OtherTests::test_escape[html] PASSED\n\
         test_t1_x.py::SecurityTests::test_escape[text] PASSED\n",
        true,
    );
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), 4);
    let matching = graph
        .memories
        .values()
        .find(|e| {
            tag(e, "subject:")
                == Some("attacker_brief_threats|test_t1_x.SecurityTests.test_escape[html]")
        })
        .unwrap();
    assert_eq!(matching.strength, 2);
    assert!(
        !graph
            .edges
            .values()
            .flatten()
            .any(|e| e.kind == EdgeKind::Contradicts)
    );
}

fn runner_fixture(command: &str, output: &str, expected: &[(&str, &str)]) {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    for path in ["tests/test_client.py", "middleware/tests.py"] {
        write_test_file(&mut memory, path);
    }
    memory.observe("bash", &json!({"command": command}), output, true);
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), expected.len());
    for (subject, status) in expected {
        let entry = graph
            .memories
            .values()
            .find(|e| {
                tag(e, "subject:") == Some(format!("attacker_brief_threats|{subject}").as_str())
            })
            .unwrap();
        assert_eq!(tag(entry, "status:"), Some(*status));
        assert_eq!(entry.trust, TrustLevel::High);
    }
}

#[test]
fn nox_session_records_pytest_outcomes() {
    runner_fixture(
        "nox -s tests -- -v",
        "nox > Running session tests\n\
         tests/test_client.py::test_request PASSED [ 50%]\n\
         tests/test_client.py::test_timeout FAILED [100%]\n\
         nox > Session tests failed.\n",
        &[
            ("tests_test_client.test_request", "passed"),
            ("tests_test_client.test_timeout", "failed"),
        ],
    );
}

#[test]
fn tox_environment_records_unittest_outcomes() {
    runner_fixture(
        "tox -e py310 -- -v",
        "py310: commands[0]> python -m unittest -v\n\
         test_request (tests.test_client.ClientTests)\n\
         Rejects input [T2] ... ok\n\
         test_timeout (tests.test_client.ClientTests) ... ERROR\n",
        &[
            ("tests_test_client.ClientTests.test_request", "passed"),
            ("tests_test_client.ClientTests.test_timeout", "error"),
        ],
    );
}

#[test]
fn django_runner_script_records_unittest_outcomes() {
    runner_fixture(
        "python tests/runtests.py middleware --verbosity 2",
        "Testing against Django installed in '/project/django'\n\
         test_escape (middleware.tests.SecurityTests.test_escape)\n\
         Escapes response [T1] ... ok\n\
         test_optional (middleware.tests.SecurityTests.test_optional) ... skipped 'unsupported'\n",
        &[
            ("middleware_tests.SecurityTests.test_escape", "passed"),
            ("middleware_tests.SecurityTests.test_optional", "skipped"),
        ],
    );
}

#[test]
fn large_project_suite_keeps_three_failures_and_five_authored_results() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    write_test_file(&mut memory, "tests/test_session.py");
    let mut output = (0..1000)
        .map(|i| format!("tests/test_project.py::test_case_{i} PASSED\n"))
        .collect::<String>();
    output.push_str("tests/test_project.py::test_bad_a FAILED\ntests/test_project.py::test_bad_b ERROR\ntests/test_project.py::test_bad_c FAILED\n");
    for (i, status) in ["PASSED", "PASSED", "FAILED", "SKIPPED", "PASSED"]
        .iter()
        .enumerate()
    {
        output.push_str(&format!("tests/test_session.py::test_ok_{i} {status}\n"));
    }
    memory.observe("bash", &json!({"command": "pytest -v"}), &output, true);
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), 8);
    assert_eq!(
        graph
            .memories
            .values()
            .filter(|e| tag(e, "test:") == Some("project"))
            .count(),
        3
    );
    assert_eq!(
        graph
            .memories
            .values()
            .filter(|e| tag(e, "test:") == Some("ordinary"))
            .count(),
        5
    );
}

#[test]
fn cap_selects_late_failures_without_reversing_a_status_chain() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    write_test_file(&mut memory, "tests/test_session.py");
    let mut output = String::from("tests/test_session.py::test_attack_chain PASSED\n");
    for i in 0..220 {
        output.push_str(&format!("tests/test_session.py::test_ok_{i} PASSED\n"));
    }
    output.push_str("tests/test_session.py::test_attack_chain FAILED\ntests/test_project.py::test_late_error ERROR\n");
    memory.observe("bash", &json!({"command": "pytest -v"}), &output, true);
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), 200);
    assert!(
        graph
            .active_memories()
            .any(|e| tag(e, "status:") == Some("error"))
    );
    let chain: Vec<_> = graph
        .memories
        .values()
        .filter(|e| tag(e, "subject:").is_some_and(|s| s.ends_with("test_attack_chain")))
        .collect();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain.iter().filter(|e| e.active).count(), 1);
    assert!(
        chain
            .iter()
            .any(|e| e.active && tag(e, "status:") == Some("failed"))
    );
}

#[test]
fn authored_tests_include_edits_patches_and_both_temporary_directories() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    write_test_file(&mut memory, "tests/test_write.py");
    memory.observe(
        "edit",
        &json!({"file_path": "tests/test_edit.py", "old_string": "old", "new_string": "new"}),
        "Edited",
        true,
    );
    memory.observe("apply_patch", &json!({"patch": "*** Begin Patch\n*** Add File: tests/test_patch.py\n+# new test\n*** End Patch"}), "Success", true);
    memory.observe(
        "write",
        &json!({"file_path": "tests/test_failed_write.py", "content": "# test"}),
        "Error",
        false,
    );
    memory.observe("bash", &json!({"command": "pytest -v"}),
        "tests/test_write.py::test_ok_write PASSED\ntests/test_edit.py::test_ok_edit PASSED\ntests/test_patch.py::test_ok_patch PASSED\n/tmp/pentests/test_external.py::test_attack_external PASSED\n/tmp/variants/test_variant.py::test_ok_variant SKIPPED\ntests/test_failed_write.py::test_ok_failed PASSED\n/tmp/pentests_fake/test_fake.py::test_ok_fake PASSED\n", true);
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), 5);
    assert!(
        !graph
            .memories
            .values()
            .any(|e| e.content.contains("test_ok_failed") || e.content.contains("test_ok_fake"))
    );
}

#[test]
fn attack_ordinary_and_error_findings_explain_their_meaning() {
    let (_dir, mut memory) = fixture(MemoryMode::Both, "attacker");
    memory.observe("bash", &json!({"command": "pytest -v /tmp/pentests"}),
        "/tmp/pentests/test_inputs.py::test_attack_bad FAILED\n/tmp/pentests/test_inputs.py::test_ok_bad FAILED\n/tmp/pentests/test_inputs.py::test_attack_stopped PASSED\n/tmp/pentests/test_inputs.py::test_ok_valid PASSED\n/tmp/pentests/test_inputs.py::test_attack_import ERROR\n", true);
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    for (method, kind, meaning) in [
        ("test_attack_bad", "attack", "attack got through"),
        ("test_ok_bad", "ordinary", "ordinary input broken"),
        ("test_attack_stopped", "attack", "attack stopped"),
        ("test_ok_valid", "ordinary", "ordinary input works"),
        ("test_attack_import", "attack", "outcome inconclusive"),
    ] {
        let entry = graph
            .memories
            .values()
            .find(|e| tag(e, "subject:").is_some_and(|s| s.ends_with(method)))
            .unwrap();
        assert_eq!(tag(entry, "test:"), Some(kind));
        assert!(entry.content.contains(meaning));
    }
    merge_files(
        memory.options.path.as_ref().unwrap(),
        &[memory.options.delta.clone().unwrap()],
    )
    .unwrap();
    let prompt = memory.retrieve("test_inputs").unwrap().prompt;
    assert!(prompt.contains("attack got through"));
    assert!(prompt.contains("ordinary input broken"));
}

#[test]
fn frozen_copies_match_their_producer_without_merging_other_attackers() {
    let (dir_a, mut a) = fixture(MemoryMode::Write, "attacker");
    let (_dir_b, mut b) = fixture(MemoryMode::Write, "attacker");
    a.options.producer = "attacker_a".into();
    b.options.producer = "attacker_b".into();
    for memory in [&mut a, &mut b] {
        memory.observe(
            "bash",
            &json!({"command": "pytest -v /tmp/pentests"}),
            "/tmp/pentests/test_shared.py::C::test_attack_x FAILED\n",
            true,
        );
    }
    let store = dir_a.path().join("snapshot.json");
    merge_files(
        &store,
        &[
            a.options.delta.clone().unwrap(),
            b.options.delta.clone().unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(load_store(&store).unwrap().active_memories().count(), 2);
    let mut options = a.options.clone();
    options.role = "defender".into();
    options.producer = "defender".into();
    options.code = "v2".into();
    options.delta = Some(dir_a.path().join("defender.json"));
    let mut defender = SecurityMemory::new(options, Arc::new(FixtureBackend));
    defender.observe(
        "bash",
        &json!({"command": "python -m unittest discover -s /tmp/pentests -v"}),
        "test_attack_x (test_attacker_a__test_shared__s1.C.test_attack_x) ... ok\n",
        true,
    );
    merge_files(&store, &[defender.options.delta.clone().unwrap()]).unwrap();
    let graph = load_store(&store).unwrap();
    assert_eq!(graph.memories.len(), 3);
    assert_eq!(graph.active_memories().count(), 2);
    assert!(graph.active_memories().any(|e| tag(e, "subject:")
        == Some("attacker_a|test_shared.C.test_attack_x")
        && tag(e, "status:") == Some("passed")));
    assert!(graph.active_memories().any(|e| tag(e, "subject:")
        == Some("attacker_b|test_shared.C.test_attack_x")
        && tag(e, "status:") == Some("failed")));
    assert!(
        !graph
            .edges
            .values()
            .flatten()
            .any(|e| e.kind == EdgeKind::Contradicts)
    );
}

#[test]
fn pytest_and_unittest_share_observed_file_identity_in_both_orders() {
    for reverse in [false, true] {
        let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
        write_test_file(&mut memory, "tests/test_x.py");
        let mut results = vec![
            ("pytest -v", "tests/test_x.py::C::test_attack_x FAILED"),
            (
                "python -m unittest -v",
                "test_attack_x (test_x.C.test_attack_x) ... FAIL",
            ),
        ];
        if reverse {
            results.reverse();
        }
        for (command, output) in results {
            memory.observe("bash", &json!({"command": command}), output, true);
        }
        let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
        assert_eq!(graph.memories.len(), 1);
        let entry = graph.active_memories().next().unwrap();
        assert_eq!(
            tag(entry, "subject:"),
            Some("attacker_brief_threats|tests_test_x.C.test_attack_x")
        );
        assert_eq!(entry.strength, 2);
    }
}

#[test]
fn same_named_modules_in_different_directories_stay_distinct() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    for path in ["a/test_x.py", "b/test_x.py"] {
        write_test_file(&mut memory, path);
    }
    memory.observe(
        "bash",
        &json!({"command": "pytest -v"}),
        "a/test_x.py::C::test_attack_x FAILED\nb/test_x.py::C::test_attack_x FAILED\n",
        true,
    );
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), 2);
    assert!(
        graph
            .memories
            .values()
            .any(|e| tag(e, "subject:") == Some("attacker_brief_threats|a_test_x.C.test_attack_x"))
    );
    assert!(
        graph
            .memories
            .values()
            .any(|e| tag(e, "subject:") == Some("attacker_brief_threats|b_test_x.C.test_attack_x"))
    );
}

#[test]
fn unittest_expected_failure_and_unexpected_success_have_distinct_statuses() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    memory.observe("bash", &json!({"command": "python -m unittest discover -s /tmp/pentests -v"}),
        "test_attack_expected (test_x.C.test_attack_expected)\nKnown issue [T2] ... expected failure\ntest_attack_unexpected (test_x.C) ... unexpected success\n", true);
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), 2);
    let expected = graph
        .memories
        .values()
        .find(|e| tag(e, "status:") == Some("expected_failure"))
        .unwrap();
    assert!(expected.content.contains("expected failure"));
    assert!(expected.tags.contains(&"brief:T2".into()));
    let unexpected = graph
        .memories
        .values()
        .find(|e| tag(e, "status:") == Some("unexpected_success"))
        .unwrap();
    assert!(
        unexpected
            .content
            .contains("attack stopped (unexpected success)")
    );
}

#[test]
fn supplied_memory_file_aliases_link_a_later_unittest_observation() {
    let (dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    memory.observe(
        "bash",
        &json!({"command": "pytest -v"}),
        "tests/test_x.py::C::test_case FAILED",
        true,
    );
    merge_files(
        memory.options.path.as_ref().unwrap(),
        &[memory.options.delta.clone().unwrap()],
    )
    .unwrap();
    let mut options = memory.options.clone();
    options.delta = Some(dir.path().join("second.json"));
    let mut next = SecurityMemory::new(options, Arc::new(FixtureBackend));
    next.set_project_root(Some(Path::new("/project")));
    next.observe(
        "bash",
        &json!({"command": "python -m unittest -v"}),
        "test_case (test_x.C.test_case) ... FAIL",
        true,
    );
    merge_files(
        memory.options.path.as_ref().unwrap(),
        &[next.options.delta.clone().unwrap()],
    )
    .unwrap();
    let graph = load_store(memory.options.path.as_ref().unwrap()).unwrap();
    assert_eq!(graph.memories.len(), 1);
    assert_eq!(graph.active_memories().next().unwrap().strength, 2);
}

#[test]
fn pytest_stdout_capture_flag_is_not_a_discovery_directory() {
    let (_dir, mut memory) = fixture(MemoryMode::Write, "attacker");
    memory.observe(
        "bash",
        &json!({"command": "pytest -s -v test_x.py"}),
        "test_x.py::C::test_case FAILED",
        true,
    );
    let graph = load_store(memory.options.delta.as_ref().unwrap()).unwrap();
    let entry = graph.active_memories().next().unwrap();
    assert_eq!(tag(entry, "subject:"), Some("test_x.C.test_case"));
    assert!(entry.tags.contains(&"file:/project/test_x.py".into()));
}
