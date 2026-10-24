use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use rembrane_memory_provider_http::HttpMemoryProviderClient;
use rembrane_provider_sdk::{
    CURRENT_MEMORY_PROVIDER_PROTOCOL, ExplainMemoryPayload, MemoryProviderCapability,
    MemoryProviderConnection, MemoryProviderContextSelector, MemoryProviderIdempotencyKey,
    MemoryProviderLimits, MemoryProviderManifest, MemoryProviderPolicy, MemoryProviderPrivacyMode,
    MemoryProviderResponseBody, MemoryProviderTransport, ProposeMemoryPayload,
};

fn limits() -> MemoryProviderLimits {
    MemoryProviderLimits {
        maximum_context_items: 10,
        maximum_context_bytes: 1_048_576,
        maximum_event_batch_items: 10,
        maximum_sync_batch_items: 10,
    }
}

fn connection(capability: MemoryProviderCapability) -> MemoryProviderConnection {
    let manifest = MemoryProviderManifest::new(
        "rembrane.memory.wire-test".to_owned(),
        "test".to_owned(),
        CURRENT_MEMORY_PROVIDER_PROTOCOL,
        vec![MemoryProviderTransport::Https],
        vec![capability],
        MemoryProviderPrivacyMode::EndToEndEncrypted,
        Vec::new(),
        limits(),
    )
    .expect("manifest");
    let policy = MemoryProviderPolicy::new(
        CURRENT_MEMORY_PROVIDER_PROTOCOL,
        MemoryProviderTransport::Https,
        vec![capability],
        vec![MemoryProviderPrivacyMode::EndToEndEncrypted],
        limits(),
    )
    .expect("policy");
    MemoryProviderConnection::connect(manifest, &policy, "wire-test").expect("connection")
}

fn read_request(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let count = stream.read(&mut chunk).expect("request read");
        assert!(count > 0, "request ended before headers");
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let headers_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header boundary")
        + 4;
    let headers = String::from_utf8(bytes[..headers_end].to_vec()).expect("ASCII headers");
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("content length"))
        })
        .unwrap_or(0);
    while bytes.len() < headers_end + content_length {
        let count = stream.read(&mut chunk).expect("request body read");
        assert!(count > 0, "request body ended early");
        bytes.extend_from_slice(&chunk[..count]);
    }
    String::from_utf8(bytes).expect("UTF-8 request")
}

fn header(request: &str, name: &str) -> String {
    request
        .lines()
        .find_map(|line| {
            let (candidate, value) = line.split_once(':')?;
            candidate
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
        .expect("required request header")
}

fn respond(stream: &mut TcpStream, request_id: &str, body: &str) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Rembrane-Request-Id: {request_id}\r\nX-Rembrane-Protocol-Version: 0.1\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("response write");
}

#[test]
fn proposal_uses_direct_body_and_transport_correlation_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("connection");
        let request = read_request(&mut stream);
        assert!(request.starts_with("POST /v1/memory/proposals HTTP/1.1\r\n"));
        assert_eq!(header(&request, "authorization"), "Bearer wire-token");
        assert_eq!(header(&request, "x-rembrane-protocol-version"), "0.1");
        let body = request.split_once("\r\n\r\n").expect("body").1;
        let json: serde_json::Value = serde_json::from_str(body).expect("JSON body");
        assert_eq!(json["content"], "Call the user Hippo.");
        assert!(json.get("payload").is_none());
        assert!(json.get("requestId").is_none());
        let request_id = header(&request, "x-rembrane-request-id");
        respond(
            &mut stream,
            &request_id,
            r#"{"memoryId":"memory_01","version":1}"#,
        );
    });

    let client =
        HttpMemoryProviderClient::new(&format!("http://{address}"), "wire-token".to_owned())
            .expect("client");
    let request = connection(MemoryProviderCapability::ProposeMemory)
        .request(
            ProposeMemoryPayload::new(
                MemoryProviderIdempotencyKey::new("proposal_0123456789abcdef").expect("key"),
                MemoryProviderContextSelector::global(),
                rembrane_domain::MemoryKind::Preference,
                "Call the user Hippo.",
                rembrane_domain::EvidenceSource::UserStatement,
                None,
                1,
                1,
            )
            .expect("payload"),
        )
        .expect("request");
    let response = client.propose_memory(&request).expect("response");
    let MemoryProviderResponseBody::Success(result) = response.body() else {
        panic!("expected successful proposal");
    };
    assert_eq!(result.memory_id().as_str(), "memory_01");
    server.join().expect("server");
}

#[test]
fn explanation_uses_encoded_path_and_query_without_get_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("connection");
        let request = read_request(&mut stream);
        assert!(request.starts_with(
            "GET /v1/memories/memory%2F01/explain?version=7&purpose=why+remember+this HTTP/1.1\r\n"
        ));
        assert_eq!(request.split_once("\r\n\r\n").expect("body").1, "");
        let request_id = header(&request, "x-rembrane-request-id");
        respond(
            &mut stream,
            &request_id,
            r#"{"memoryId":"memory/01","version":7,"explanation":"The user stated it.","evidence":[{"evidenceId":"evidence_01","source":"user_statement"}]}"#,
        );
    });

    let client =
        HttpMemoryProviderClient::new(&format!("http://{address}"), "wire-token".to_owned())
            .expect("client");
    let request = connection(MemoryProviderCapability::ExplainMemory)
        .request(
            ExplainMemoryPayload::new(
                rembrane_domain::MemoryId::new("memory/01"),
                7,
                "why remember this",
            )
            .expect("payload"),
        )
        .expect("request");
    let response = client.explain_memory(&request).expect("response");
    let MemoryProviderResponseBody::Success(result) = response.body() else {
        panic!("expected successful explanation");
    };
    assert_eq!(result.version(), 7);
    server.join().expect("server");
}
