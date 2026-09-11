//! Repository security knowledge, stored separately from conversational memory.
//!
//! The MVP supplies the whole small graph as advisory context. It never promotes
//! proposed controls to observed facts or updates source hashes automatically.

mod context;
pub use context::{ContextOptions, SecurityContext, load_context};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::path::{Component, Path};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_GRAPH_BYTES: usize = 128 * 1024;
pub const MAX_CONTEXT_BYTES: usize = 16 * 1024;
pub const DEFAULT_GRAPH_PATH: &str = ".jcode/security-graph.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityGraph {
    pub schema_version: u32,
    pub id: String,
    pub description: String,
    /// SHA-256 of reviewed source files, relative to the repository root.
    #[serde(default)]
    pub source_files: BTreeMap<String, String>,
    pub nodes: Vec<SecurityNode>,
    pub edges: Vec<SecurityEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityNode {
    pub id: String,
    pub kind: NodeKind,
    pub description: String,
    pub status: ClaimStatus,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Component,
    Dependency,
    Asset,
    TrustBoundary,
    Assumption,
    Threat,
    Control,
    Finding,
    Evidence,
}

/// Observation describes implementation or a tool result, not proof of safety.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Observed,
    Inferred,
    Proposed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecurityEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub status: ClaimStatus,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Calls,
    DependsOn,
    FlowsTo,
    Inside,
    Crosses,
    DependsOnAssumption,
    Threatens,
    Violates,
    Mitigates,
    Protects,
    SupportedBy,
}

pub fn content_hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn validate_relative_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.contains(['\\', ':'])
            && Path::new(path)
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "source path must be repository-relative without parent traversal: {path:?}"
    );
    Ok(())
}

impl SecurityGraph {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_GRAPH_BYTES,
            "security graph exceeds size limit"
        );
        let graph: Self = serde_json::from_slice(bytes).context("invalid security graph JSON")?;
        graph.validate()?;
        Ok(graph)
    }

    pub fn load(path: &Path) -> Result<Self> {
        ensure!(
            std::fs::metadata(path)?.is_file(),
            "security graph must be a regular file"
        );
        let file = std::fs::File::open(path)
            .with_context(|| format!("reading security graph {}", path.display()))?;
        ensure!(
            file.metadata()?.is_file(),
            "security graph must be a regular file"
        );
        let mut bytes = Vec::new();
        file.take((MAX_GRAPH_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::from_json(&bytes).with_context(|| format!("loading {}", path.display()))
    }

    /// Validate before atomically replacing a graph. The caller owns review.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)?;
        ensure!(
            bytes.len() <= MAX_GRAPH_BYTES,
            "security graph exceeds size limit"
        );
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist(path)
            .with_context(|| format!("saving {}", path.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported security graph schema version {}",
            self.schema_version
        );
        ensure!(!self.id.trim().is_empty(), "security graph ID is empty");
        ensure!(
            !self.description.trim().is_empty(),
            "security graph description is empty"
        );
        ensure!(
            !self.nodes.is_empty() && self.nodes.len() <= 100,
            "security graph must contain 1..100 nodes"
        );
        ensure!(self.edges.len() <= 300, "security graph exceeds 300 edges");
        ensure!(
            self.source_files.len() <= 100,
            "security graph exceeds 100 source files"
        );
        let mut ids = HashSet::new();
        for node in &self.nodes {
            ensure!(!node.id.trim().is_empty(), "security node ID is empty");
            ensure!(
                ids.insert(node.id.as_str()),
                "duplicate security node ID: {}",
                node.id
            );
            ensure!(
                !node.description.trim().is_empty(),
                "security node {} has no description",
                node.id
            );
        }
        let mut edges = HashSet::new();
        for edge in &self.edges {
            ensure!(
                ids.contains(edge.from.as_str()) && ids.contains(edge.to.as_str()),
                "dangling security edge: {} -> {}",
                edge.from,
                edge.to
            );
            ensure!(
                edges.insert((&edge.from, &edge.to, &edge.kind)),
                "duplicate security edge: {} -> {}",
                edge.from,
                edge.to
            );
        }
        for (path, hash) in &self.source_files {
            validate_relative_path(path)?;
            ensure!(
                hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()),
                "invalid SHA-256 for {path}"
            );
        }
        for evidence in self
            .nodes
            .iter()
            .flat_map(|n| &n.evidence)
            .chain(self.edges.iter().flat_map(|e| &e.evidence))
        {
            validate_relative_path(&evidence.path)?;
            ensure!(evidence.line != Some(0), "evidence lines are 1-based");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
