use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    rembrane_mcp::run_stdio().await
}
