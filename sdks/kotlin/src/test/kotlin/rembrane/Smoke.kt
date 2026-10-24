package rembrane

import java.net.URI
import java.nio.charset.StandardCharsets

fun main() {
    var capturedUri: URI? = null
    var capturedAuthorization: String? = null
    val transport = RembraneTransport { _, uri, headers, _, _ ->
        capturedUri = uri
        capturedAuthorization = headers["Authorization"]
        RembraneResponse(
            status = 200,
            headers = mapOf("content-type" to listOf("application/json")),
            body = """{"events":[]}""".toByteArray(StandardCharsets.UTF_8),
        )
    }
    val client = RembraneClient(
        baseUrl = "http://127.0.0.1:8787/v1",
        token = "test-token",
        transport = transport,
    )
    check(
        client.listAdministrativeAudit("team", 10, 20) == """{"events":[]}"""
    )
    check(
        capturedUri.toString() ==
            "http://127.0.0.1:8787/v1/administrative-audit?workspaceId=team&afterEpochSeconds=10&limit=20"
    )
    check(capturedAuthorization == "Bearer test-token")
    check(
        runCatching {
            RembraneClient(
                baseUrl = "http://memory.example.test/v1",
                token = "token",
                transport = transport,
            )
        }.isFailure
    )
}
