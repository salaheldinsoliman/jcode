# Repository security graph MVP

Jcode can load a small repository security graph and supply it to the model before
each coding request. The graph is advisory context; existing tool permissions and
security gates retain their separate responsibilities.

Place the graph at `.jcode/security-graph.json`. Discovery starts in the session's
working directory and walks to the nearest enclosing Git root, including worktree
`.git` files. It selects the nearest graph and never searches beyond that Git root.
For directories outside Git, discovery walks their ancestors.

For an experiment, keep the graph outside the target tree and set
`JCODE_SECURITY_GRAPH_PATH` to its absolute path. Relative override paths resolve
against the session working directory. Evidence paths in an explicitly selected
graph also resolve against that directory, so start at the intended repository
root. This lets the no-context condition avoid leaving an otherwise readable copy
of the graph inside the coding workspace.

`JCODE_SECURITY_GRAPH=0` (also `off` or `false`) disables injection even when a graph
file is present. The default is enabled when a graph can be discovered. Missing
default files produce no context. An explicitly selected missing file, malformed
graph, invalid option or oversized context returns an error before model
completion, preventing an experimental condition from silently losing its input.

These environment settings belong to the process executing the Agent. Set them on
`jcode run` for the local one-shot path in this checkout, or when starting an
isolated daemon for interactive sessions. Changing a client's environment does
not reconfigure an already-running daemon. Embedding code can use
`Agent::set_security_graph_options(ContextOptions { enabled, graph_path })` for
in-memory per-agent overrides; these overrides are not persisted in sessions.

The JSON schema is defined by the public Rust types in `jcode-security-graph`.
Unknown fields and enum values are rejected. A minimal example is:

```json
{
  "schema_version": 1,
  "id": "my-repository",
  "description": "Security assumptions for report rendering",
  "source_files": {},
  "nodes": [
    {
      "id": "renderer",
      "kind": "component",
      "status": "observed",
      "description": "Renders the report",
      "evidence": [{"path": "templates.py", "symbol": "render_template", "line": 5}]
    },
    {
      "id": "trusted-template",
      "kind": "assumption",
      "status": "inferred",
      "description": "Template source must remain application-controlled"
    }
  ],
  "edges": [
    {
      "from": "renderer",
      "to": "trusted-template",
      "kind": "depends_on_assumption",
      "status": "inferred"
    }
  ]
}
```

Node kinds: `component`, `dependency`, `asset`, `trust_boundary`, `assumption`,
`threat`, `control`, `finding`, `evidence`. Edge kinds: `calls`, `depends_on`,
`flows_to`, `inside`, `crosses`, `depends_on_assumption`, `threatens`, `violates`,
`mitigates`, `protects`, `supported_by`. Edge direction follows the verb:
caller `calls` callee; control `mitigates` threat; component `inside` boundary.
Nodes and edges each carry a claim status and optional code evidence.

`observed` means recorded implementation or tool evidence, not verified safety.
`inferred` means a conclusion requiring review. `proposed` describes intended
behavior or a control that must not be presumed implemented. The caller is
responsible for reviewing claims; schema validation only checks structure.

`source_files` maps repository-relative paths to the SHA-256 of the reviewed bytes.
For example, obtain hashes using `shasum -a 256 templates.py`. Paths cannot be
absolute or contain parent traversal. Evidence symlinks outside the repository
are not followed for hashing. At request time, each file is marked `matches`,
`changed`, `unavailable`, or `untracked`. Missing hashes and any mismatch add a
source-review warning; they do not silently discard the security assumptions.
Files over 2 MiB cannot be verified by this MVP. Hashes are never updated
automatically. Changes to unlisted files, newly added files, and whether a symbol
or line still supports a claim require review; matching hashes are not a complete
repository snapshot or proof of security.

The complete graph is included, with its relationships and statuses, in one
user-role `<security-context>` message appended to each provider request. The
message is rebuilt after tool results and compaction and on resumed sessions;
it is not appended to conversation history and does not use ordinary memory's
pending queue, decay, or deduplication. It works with memory disabled and custom
system prompts. Both the headless and streaming Agent loops invoke the same
context builder. The graph is read again each request, so saved updates are seen
without restarting the session. Repeated suffix context can increase input and
cache costs; measure these during the experiment.

A `SECURITY_CONTEXT` log event records the graph path/hash, counts, source-match
status and context size. The current UI does not have a separate security graph
panel or event. The context is bounded to 16 KiB, with a 128 KiB file limit,
100 nodes, 300 edges and 100 hashed sources. Oversized graphs need narrower scope;
claims are not silently truncated. This is deliberately a small whole-graph
experiment. Relevance search, generic graph traversal, automatic graph generation,
background updates, SARIF ingestion and enforcement are future work.

To inspect a graph without a model or running daemon, from the Jcode checkout:

```sh
cargo run -p jcode-security-graph --example inspect -- /absolute/graph.json /absolute/repository
```

For an A/B comparison, use identical fresh working copies and fresh sessions. Keep
the feature prompt, provider/model and existing gates the same. Isolate ordinary
memory and other repo-specific context hooks. The graph should live outside both
working copies, with only the treatment process receiving its path. Disabling
automatic injection alone does not stop an allowed file-reading tool from finding
a graph left in the repository. Evaluate unsafe attempts, gate interventions,
remaining findings, analysis failures, and functional completion separately.
