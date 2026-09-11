//! Preview exactly the context that would be appended to a model request.
use anyhow::{Result, bail};
use jcode_security_graph::{ContextOptions, load_context};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        bail!("usage: inspect <security-graph.json> <repository-directory>");
    }
    let graph_path = PathBuf::from(&args[0]).canonicalize()?;
    let options = ContextOptions {
        enabled: true,
        graph_path: Some(graph_path),
    };
    if let Some(context) = load_context(&PathBuf::from(&args[1]), &options)? {
        println!("{}", context.prompt);
    }
    Ok(())
}
