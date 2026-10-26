use anyhow::Result;

fn main() -> Result<()> {
    let server = rembrane_mcp::RembraneMcp::from_environment()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    // Keep final provider ownership outside the async executor, including shutdown.
    runtime.block_on(rembrane_mcp::serve_stdio(server.clone()))
}
