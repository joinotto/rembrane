package rembrane

import java.net.URI
import java.nio.charset.StandardCharsets

fun main() {
    data class CapturedRequest(
        val method: String,
        val uri: URI,
        val headers: Map<String, String>,
        val body: ByteArray?,
    )

    val captured = mutableListOf<CapturedRequest>()
    val transport = RembraneTransport { method, uri, headers, body, _ ->
        captured.add(CapturedRequest(method, uri, headers, body))
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
        captured[0].uri.toString() ==
            "http://127.0.0.1:8787/v1/administrative-audit?workspaceId=team&afterEpochSeconds=10&limit=20"
    )
    check(captured[0].headers["Authorization"] == "Bearer test-token")

    val createBody =
        """{"workspaceId":"team","invitationId":"invite-1","invitedPrincipalId":"principal-2","role":"member","ttlSeconds":3600,"requestId":"request-1"}"""
    val transitionBody =
        """{"workspaceId":"team","invitationId":"invite-1","requestId":"request-2"}"""
    client.createWorkspaceInvitation(createBody)
    client.acceptWorkspaceInvitation(transitionBody)
    client.revokeWorkspaceInvitation(
        """{"workspaceId":"team","invitationId":"invite-1","requestId":"request-3"}"""
    )
    client.listWorkspaceInvitations("team/name", "accepted", 20)
    val invitationPaths = listOf(
        "/workspaces/invitations",
        "/workspaces/invitations/accept",
        "/workspaces/invitations/revoke",
    )
    val invitationBodies = listOf(
        createBody,
        transitionBody,
        """{"workspaceId":"team","invitationId":"invite-1","requestId":"request-3"}""",
    )
    captured.drop(1).zip(invitationPaths.zip(invitationBodies)).forEach { (request, expected) ->
        check(request.method == "POST")
        check(request.uri.toString() == "http://127.0.0.1:8787/v1${expected.first}")
        check(request.headers["Authorization"] == "Bearer test-token")
        check(request.headers["Content-Type"] == "application/json")
        check(request.body?.toString(StandardCharsets.UTF_8) == expected.second)
    }
    val listing = captured[4]
    check(listing.method == "GET")
    check(
        listing.uri.toString() ==
            "http://127.0.0.1:8787/v1/workspaces/invitations?workspaceId=team%2Fname&status=accepted&limit=20"
    )
    check(listing.headers["Authorization"] == "Bearer test-token")
    check(listing.body == null)

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
