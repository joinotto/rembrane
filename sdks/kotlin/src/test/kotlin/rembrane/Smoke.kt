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
        when (uri.path) {
            "/v1/exports" -> RembraneResponse(
                status = 200,
                headers = mapOf(
                    "content-type" to listOf("application/x-ndjson"),
                    "content-disposition" to listOf(
                        """attachment; filename="rembrane-memories.jsonl"""",
                    ),
                    "cache-control" to listOf("no-store"),
                    "x-content-type-options" to listOf("nosniff"),
                ),
                body = """{"format":"rembrane-memory-jsonl"}"""
                    .toByteArray(StandardCharsets.UTF_8),
            )
            "/v1/imports" -> RembraneResponse(
                status = 201,
                headers = mapOf("content-type" to listOf("application/json")),
                body = """{"imported":1,"status":"proposed"}"""
                    .toByteArray(StandardCharsets.UTF_8),
            )
            else -> RembraneResponse(
                status = 200,
                headers = mapOf("content-type" to listOf("application/json")),
                body = """{"events":[]}""".toByteArray(StandardCharsets.UTF_8),
            )
        }
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

    val graphBody =
        """{"workspaceId":"team","subjectId":"principal-1","nodeId":"project-1","direction":"outgoing","validAtEpochSeconds":1700000000,"maximumCandidates":20,"purpose":"continue-project","entityId":"project-1"}"""
    client.resolveGraphContext(graphBody)
    val graph = captured[5]
    check(graph.method == "POST")
    check(
        graph.uri.toString() ==
            "http://127.0.0.1:8787/v1/graph/context/resolve"
    )
    check(graph.headers["Authorization"] == "Bearer test-token")
    check(graph.headers["Content-Type"] == "application/json")
    check(graph.body?.toString(StandardCharsets.UTF_8) == graphBody)

    val exported = client.exportPortableData(
        "team:name",
        "principal-1",
        PortableExportFormat.JSONL,
    )
    check(exported.filename == "rembrane-memories.jsonl")
    check(
        exported.body.toString(StandardCharsets.UTF_8) ==
            """{"format":"rembrane-memory-jsonl"}"""
    )
    val exportRequest = captured[6]
    check(exportRequest.method == "POST")
    check(
        exportRequest.uri.toString() ==
            "http://127.0.0.1:8787/v1/exports?workspaceId=team%3Aname&subjectId=principal-1&format=jsonl"
    )
    check(exportRequest.headers["Accept"] == "application/x-ndjson")
    check(exportRequest.headers["Authorization"] == "Bearer test-token")
    check(exportRequest.body == null)

    val importArchive = """{"format":"rembrane-memory-jsonl"}"""
        .toByteArray(StandardCharsets.UTF_8)
    val imported = client.importPortableMemories(
        "team:name",
        "principal-1",
        42,
        importArchive,
    )
    check(imported == PortableImportResult(1, "proposed"))
    val importRequest = captured[7]
    check(importRequest.method == "POST")
    check(
        importRequest.uri.toString() ==
            "http://127.0.0.1:8787/v1/imports?workspaceId=team%3Aname&subjectId=principal-1&expectedPreviousSequence=42"
    )
    check(importRequest.headers["Accept"] == "application/json")
    check(importRequest.headers["Authorization"] == "Bearer test-token")
    check(importRequest.headers["Content-Type"] == "application/x-ndjson")
    check(importRequest.body.contentEquals(importArchive))

    val callsBeforeInvalidPortability = captured.size
    check(
        runCatching {
            client.exportPortableData(
                "unsafe/workspace",
                "principal-1",
                PortableExportFormat.JSONL,
            )
        }.isFailure,
    )
    check(
        runCatching {
            client.importPortableMemories("team", "principal-1", -1, importArchive)
        }.isFailure,
    )
    check(captured.size == callsBeforeInvalidPortability)

    val invalidExportClient = RembraneClient(
        baseUrl = "https://memory.example.test/v1",
        token = "token",
        transport = RembraneTransport { _, _, _, _, _ ->
            RembraneResponse(
                200,
                mapOf("content-type" to listOf("application/x-ndjson")),
                byteArrayOf(1),
            )
        },
    )
    val invalidExport = runCatching {
        invalidExportClient.exportPortableData(
            "team",
            "principal-1",
            PortableExportFormat.JSONL,
        )
    }.exceptionOrNull()
    check(
        invalidExport is RembraneApiException &&
            invalidExport.code == "invalid_response",
    )

    val conflictingImportClient = RembraneClient(
        baseUrl = "https://memory.example.test/v1",
        token = "token",
        transport = RembraneTransport { _, _, _, _, _ ->
            RembraneResponse(
                409,
                mapOf("content-type" to listOf("application/json")),
                """{"code":"sequence_conflict","message":"Sequence changed"}"""
                    .toByteArray(StandardCharsets.UTF_8),
            )
        },
    )
    val conflict = runCatching {
        conflictingImportClient.importPortableMemories(
            "team",
            "principal-1",
            0,
            importArchive,
        )
    }.exceptionOrNull()
    check(
        conflict is RembraneApiException &&
            conflict.status == 409 &&
            conflict.code == "sequence_conflict",
    )

    val continuityBody =
        """{"workspaceId":"team","subjectId":"principal-1","content":"Call me Hippo"}"""
    val continuityStart = captured.size
    client.rememberPreference(continuityBody)
    client.recordWorkTrace(continuityBody)
    client.correctMemory("memory:preference-1", continuityBody)
    client.deleteMemory("memory:preference-1", continuityBody)
    client.checkpointActivity("activity:project-1", continuityBody)
    client.resumeActivity(
        "activity:project-1",
        "team",
        "principal-1",
        "continue development",
        "git:abc/123",
    )
    check(
        captured.drop(continuityStart).map { it.uri.toString() } == listOf(
            "http://127.0.0.1:8787/v1/memories/preferences",
            "http://127.0.0.1:8787/v1/memories/work-traces",
            "http://127.0.0.1:8787/v1/memories/memory:preference-1/correction",
            "http://127.0.0.1:8787/v1/memories/memory:preference-1/deletion",
            "http://127.0.0.1:8787/v1/activities/activity:project-1/checkpoint",
            "http://127.0.0.1:8787/v1/activities/activity:project-1/resume" +
                "?workspaceId=team&subjectId=principal-1" +
                "&purpose=continue%20development&stateFingerprint=git%3Aabc%2F123",
        ),
    )
    check(captured.last().method == "GET")
    check(captured.last().body == null)
    val callsBeforeInvalidMemory = captured.size
    check(
        runCatching {
            client.correctMemory("../memory", continuityBody)
        }.isFailure,
    )
    check(captured.size == callsBeforeInvalidMemory)

    val travelBody =
        """{"workspaceId":"team","subjectId":"principal-1","tripId":"trip-1"}"""
    val travelStart = captured.size
    client.createTrip(travelBody)
    client.addTripParticipant(travelBody)
    client.addTripConstraint(travelBody)
    client.recordTripDecision(travelBody)
    client.captureBookingResearch(travelBody)
    client.resolveTravelContext(travelBody)
    check(
        captured.drop(travelStart).map { it.uri.path } == listOf(
            "/v1/travel/trips",
            "/v1/travel/trip-participants",
            "/v1/travel/trip-constraints",
            "/v1/travel/trip-decisions",
            "/v1/travel/booking-research",
            "/v1/travel/context/resolve",
        ),
    )
    check(captured.drop(travelStart).all { it.method == "POST" })
    check(
        captured.drop(travelStart).all {
            it.headers["Authorization"] == "Bearer test-token" &&
                it.body?.toString(StandardCharsets.UTF_8) == travelBody
        },
    )

    check(
        runCatching {
            RembraneClient(
                baseUrl = "http://memory.example.test/v1",
                token = "token",
                transport = transport,
            )
        }.isFailure
    )

    val channelMessage = ChannelProcessorMessage(
        protocolVersion = "0.1",
        channel = "whatsapp-business",
        eventId = "wamid.opaque-example-event",
        workspaceId = "workspace_example",
        principalId = "principal_example",
        clientId = "client_whatsapp_example",
        text = "Continue my flight research",
        receivedAtEpochSeconds = 1_792_890_000,
    )
    check(
        channelMessage.toJson() ==
            """{"protocolVersion":"0.1","channel":"whatsapp-business","eventId":"wamid.opaque-example-event","workspaceId":"workspace_example","principalId":"principal_example","clientId":"client_whatsapp_example","text":"Continue my flight research","receivedAtEpochSeconds":1792890000}"""
    )
    check(
        ChannelProcessorAcknowledgement(
            channelMessage.eventId,
            ChannelProcessorStatus.PROCESSED,
        ).toJson() ==
            """{"protocolVersion":"0.1","eventId":"wamid.opaque-example-event","status":"processed"}"""
    )
    for (invalid in listOf<() -> Unit>(
        {
            ChannelProcessorMessage(
                "0.2",
                channelMessage.channel,
                channelMessage.eventId,
                channelMessage.workspaceId,
                channelMessage.principalId,
                channelMessage.clientId,
                channelMessage.text,
                channelMessage.receivedAtEpochSeconds,
            )
        },
        {
            channelMessage.copy(eventId = "unsafe event")
        },
        {
            channelMessage.copy(workspaceId = "x".repeat(256))
        },
        {
            channelMessage.copy(text = " \n\t")
        },
        {
            channelMessage.copy(text = "😀".repeat(4_097))
        },
        {
            channelMessage.copy(receivedAtEpochSeconds = 0)
        },
    )) {
        check(runCatching(invalid).isFailure)
    }
}
