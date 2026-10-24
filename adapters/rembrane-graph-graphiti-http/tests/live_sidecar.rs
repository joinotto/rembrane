use rembrane_graph_graphiti::GraphitiProvider;
use rembrane_graph_graphiti_http::HttpGraphitiTransport;
use rembrane_provider_sdk::verify_knowledge_graph_provider;

#[test]
fn live_http_sidecar_passes_graph_provider_conformance() {
    if std::env::var("REMBRANE_RUN_GRAPHITI_SIDECAR_TESTS").as_deref() != Ok("1") {
        return;
    }
    let base_url = std::env::var("REMBRANE_GRAPHITI_TEST_BASE_URL")
        .expect("live sidecar test requires a base URL");
    let token = std::env::var("REMBRANE_GRAPHITI_TEST_TOKEN")
        .expect("live sidecar test requires a bearer token");
    let transport =
        HttpGraphitiTransport::new(&base_url, token).expect("HTTP transport should initialize");
    let mut provider = GraphitiProvider::connect(transport, "graphiti-live-test", true)
        .expect("provider should negotiate the live sidecar");
    verify_knowledge_graph_provider(&mut provider, "live-http")
        .expect("live Graphiti sidecar should conform");
}
