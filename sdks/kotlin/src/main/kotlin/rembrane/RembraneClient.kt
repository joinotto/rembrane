package rembrane

import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration

private const val CHANNEL_PROCESSOR_PROTOCOL_VERSION = "0.1"
private const val MAXIMUM_PORTABLE_IMPORT_BYTES = 67_108_864
private val CHANNEL_PROCESSOR_CHANNELS = setOf(
    "whatsapp-business",
    "imessage-extension",
    "mobile-share",
)

data class RembraneResponse(
    val status: Int,
    val headers: Map<String, List<String>>,
    val body: ByteArray,
)

fun interface RembraneTransport {
    fun send(
        method: String,
        uri: URI,
        headers: Map<String, String>,
        body: ByteArray?,
        maximumResponseBytes: Int,
    ): RembraneResponse
}

class JdkRembraneTransport(
    private val timeout: Duration = Duration.ofSeconds(30),
) : RembraneTransport {
    private val client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(timeout)
        .build()

    override fun send(
        method: String,
        uri: URI,
        headers: Map<String, String>,
        body: ByteArray?,
        maximumResponseBytes: Int,
    ): RembraneResponse {
        val publisher = body?.let(HttpRequest.BodyPublishers::ofByteArray)
            ?: HttpRequest.BodyPublishers.noBody()
        val builder = HttpRequest.newBuilder(uri)
            .timeout(timeout)
            .method(method, publisher)
        headers.forEach(builder::header)
        val response = client.send(
            builder.build(),
            HttpResponse.BodyHandlers.ofByteArray(),
        )
        require(response.body().size <= maximumResponseBytes) {
            "Rembrane response exceeded configured byte limit"
        }
        return RembraneResponse(
            status = response.statusCode(),
            headers = response.headers().map(),
            body = response.body(),
        )
    }
}

class RembraneApiException(
    val status: Int,
    val code: String,
    override val message: String,
) : RuntimeException(message)

enum class PortableExportFormat(
    val wireValue: String,
    val contentType: String,
    val filename: String,
) {
    JSONL("jsonl", "application/x-ndjson", "rembrane-memories.jsonl"),
    MARKDOWN("markdown", "text/markdown; charset=utf-8", "rembrane-memories.md"),
    GRAPH_JSON(
        "graph-json",
        "application/vnd.rembrane.knowledge-graph+json",
        "rembrane-knowledge-graph.json",
    ),
}

data class PortableExport(
    val format: PortableExportFormat,
    val contentType: String,
    val filename: String,
    val body: ByteArray,
)

data class PortableImportResult(val imported: Int, val status: String)

class RembraneClient(
    baseUrl: String,
    private val token: String,
    private val transport: RembraneTransport = JdkRembraneTransport(),
    private val maximumResponseBytes: Int = 1_048_576,
) {
    private val baseUri: URI

    init {
        val uri = URI(baseUrl)
        val loopback = uri.host in setOf("localhost", "127.0.0.1", "::1")
        require(uri.scheme == "https" || (uri.scheme == "http" && loopback)) {
            "Rembrane requires HTTPS or an explicit loopback URL"
        }
        require(uri.userInfo == null && uri.query == null && uri.fragment == null) {
            "Rembrane base URL must not contain credentials, query, or fragment"
        }
        require(token.isNotEmpty()) { "Rembrane bearer token is required" }
        require(maximumResponseBytes > 0) { "maximumResponseBytes must be positive" }
        baseUri = URI(baseUrl.trimEnd('/'))
    }

    fun resolveContext(jsonBody: String): String =
        request("POST", "/context/resolve", jsonBody)

    fun resolveGraphContext(jsonBody: String): String =
        request("POST", "/graph/context/resolve", jsonBody)

    fun rotateWorkspaceKey(jsonBody: String): String =
        request("POST", "/workspaces/key-rotation", jsonBody)

    fun createWorkspaceInvitation(jsonBody: String): String =
        request("POST", "/workspaces/invitations", jsonBody)

    fun acceptWorkspaceInvitation(jsonBody: String): String =
        request("POST", "/workspaces/invitations/accept", jsonBody)

    fun revokeWorkspaceInvitation(jsonBody: String): String =
        request("POST", "/workspaces/invitations/revoke", jsonBody)

    fun listWorkspaceInvitations(
        workspaceId: String,
        status: String? = null,
        limit: Int? = null,
    ): String {
        val query = buildList {
            add("workspaceId=${encode(workspaceId)}")
            status?.let { add("status=${encode(it)}") }
            limit?.let { add("limit=$it") }
        }.joinToString("&")
        return request("GET", "/workspaces/invitations?$query", null)
    }

    fun setRetentionPolicy(jsonBody: String): String =
        request("POST", "/retention/policy", jsonBody)

    fun placeLegalHold(jsonBody: String): String =
        request("POST", "/retention/legal-holds", jsonBody)

    fun releaseLegalHold(jsonBody: String): String =
        request("POST", "/retention/legal-holds/release", jsonBody)

    fun executeRetentionPurge(jsonBody: String): String =
        request("POST", "/retention/purge", jsonBody)

    fun listAdministrativeAudit(
        workspaceId: String,
        afterEpochSeconds: Long? = null,
        limit: Int? = null,
    ): String {
        val query = buildList {
            add("workspaceId=${encode(workspaceId)}")
            afterEpochSeconds?.let { add("afterEpochSeconds=$it") }
            limit?.let { add("limit=$it") }
        }.joinToString("&")
        return request("GET", "/administrative-audit?$query", null)
    }

    fun exportPortableData(
        workspaceId: String,
        subjectId: String,
        format: PortableExportFormat,
    ): PortableExport {
        requireOpaqueId(workspaceId, "workspaceId")
        requireOpaqueId(subjectId, "subjectId")
        val query = "workspaceId=${encode(workspaceId)}" +
            "&subjectId=${encode(subjectId)}&format=${format.wireValue}"
        val response = transport.send(
            "POST",
            URI("$baseUri/exports?$query"),
            mapOf(
                "Accept" to format.contentType,
                "Authorization" to "Bearer $token",
            ),
            null,
            maximumResponseBytes,
        )
        enforceResponseLimit(response)
        if (response.status !in 200..299) throwProblem(response)
        val contentType = response.header("content-type")
        if (
            !contentType.equals(format.contentType, ignoreCase = true) ||
            response.header("content-disposition") !=
            """attachment; filename="${format.filename}"""" ||
            !response.header("cache-control").equals("no-store", ignoreCase = true) ||
            !response.header("x-content-type-options").equals("nosniff", ignoreCase = true)
        ) {
            throw RembraneApiException(
                response.status,
                "invalid_response",
                "Portable export metadata was invalid",
            )
        }
        return PortableExport(format, contentType, format.filename, response.body)
    }

    fun importPortableMemories(
        workspaceId: String,
        subjectId: String,
        expectedPreviousSequence: Long,
        jsonl: ByteArray,
    ): PortableImportResult {
        requireOpaqueId(workspaceId, "workspaceId")
        requireOpaqueId(subjectId, "subjectId")
        require(expectedPreviousSequence >= 0) {
            "expectedPreviousSequence must be non-negative"
        }
        require(jsonl.isNotEmpty() && jsonl.size <= MAXIMUM_PORTABLE_IMPORT_BYTES) {
            "Portable import archive size is invalid"
        }
        val query = "workspaceId=${encode(workspaceId)}" +
            "&subjectId=${encode(subjectId)}" +
            "&expectedPreviousSequence=$expectedPreviousSequence"
        val response = transport.send(
            "POST",
            URI("$baseUri/imports?$query"),
            mapOf(
                "Accept" to "application/json",
                "Authorization" to "Bearer $token",
                "Content-Type" to "application/x-ndjson",
            ),
            jsonl,
            maximumResponseBytes,
        )
        enforceResponseLimit(response)
        if (response.status !in 200..299) throwProblem(response)
        if (!response.header("content-type").startsWith("application/json", true)) {
            throw RembraneApiException(
                response.status,
                "invalid_response",
                "Expected JSON response",
            )
        }
        val text = response.body.toString(StandardCharsets.UTF_8)
        val match = Regex(
            """^\s*\{\s*"imported"\s*:\s*([0-9]+)\s*,\s*"status"\s*:\s*"proposed"\s*}\s*$""",
        ).matchEntire(text)
        val imported = match?.groupValues?.get(1)?.toIntOrNull()
        if (imported == null || imported !in 1..10_000) {
            throw RembraneApiException(
                response.status,
                "invalid_response",
                "Portable import response was invalid",
            )
        }
        return PortableImportResult(imported, "proposed")
    }

    private fun request(method: String, path: String, jsonBody: String?): String {
        val body = jsonBody?.toByteArray(StandardCharsets.UTF_8)
        val headers = buildMap {
            put("Accept", "application/json")
            put("Authorization", "Bearer $token")
            if (body != null) put("Content-Type", "application/json")
        }
        val response = transport.send(
            method,
            URI(baseUri.toString() + path),
            headers,
            body,
            maximumResponseBytes,
        )
        enforceResponseLimit(response)
        val contentType = response.header("content-type")
        if (!contentType.startsWith("application/json", ignoreCase = true)) {
            throw RembraneApiException(
                response.status,
                "invalid_response",
                "Expected JSON response",
            )
        }
        val text = response.body.toString(StandardCharsets.UTF_8)
        if (response.status !in 200..299) {
            throw RembraneApiException(
                response.status,
                jsonString(text, "code") ?: "request_failed",
                jsonString(text, "message") ?: "Rembrane request failed",
            )
        }
        return text
    }

    private fun enforceResponseLimit(response: RembraneResponse) {
        if (response.body.size > maximumResponseBytes) {
            throw RembraneApiException(
                response.status,
                "response_too_large",
                "Response exceeded limit",
            )
        }
    }

    private fun throwProblem(response: RembraneResponse): Nothing {
        if (!response.header("content-type").startsWith("application/json", true)) {
            throw RembraneApiException(
                response.status,
                "invalid_response",
                "Expected JSON problem response",
            )
        }
        val text = response.body.toString(StandardCharsets.UTF_8)
        throw RembraneApiException(
            response.status,
            jsonString(text, "code") ?: "request_failed",
            jsonString(text, "message") ?: "Rembrane request failed",
        )
    }

    private fun encode(value: String): String =
        URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

    private fun jsonString(json: String, field: String): String? {
        val pattern = Regex("\"${Regex.escape(field)}\"\\s*:\\s*\"([^\"\\\\]*)\"")
        return pattern.find(json)?.groupValues?.get(1)
    }
}

private fun RembraneResponse.header(name: String): String =
    headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }
        ?.value?.firstOrNull().orEmpty()

private fun requireOpaqueId(value: String, field: String) {
    require(
        value.isNotEmpty() &&
            value.toByteArray(StandardCharsets.UTF_8).size <= 255 &&
            value.first().isLetterOrDigit() &&
            value.all { it.isLetterOrDigit() && it.code < 128 || it in "._:-" },
    ) {
        "$field must be a bounded opaque identifier"
    }
}

data class ChannelProcessorMessage(
    val protocolVersion: String,
    val channel: String,
    val eventId: String,
    val workspaceId: String,
    val principalId: String,
    val clientId: String,
    val text: String,
    val receivedAtEpochSeconds: Long,
) {
    init {
        require(protocolVersion == CHANNEL_PROCESSOR_PROTOCOL_VERSION) {
            "Invalid Rembrane channel processor protocol version"
        }
        require(channel in CHANNEL_PROCESSOR_CHANNELS) {
            "Invalid Rembrane channel processor channel"
        }
        requireBoundedToken(eventId, 256, "eventId")
        requireBoundedToken(workspaceId, 255, "workspaceId")
        requireBoundedToken(principalId, 255, "principalId")
        requireBoundedToken(clientId, 255, "clientId")
        require(text.isNotBlank() && text.toByteArray(StandardCharsets.UTF_8).size <= 16_384) {
            "Invalid Rembrane channel processor text"
        }
        require(receivedAtEpochSeconds > 0) {
            "Invalid Rembrane channel processor receipt time"
        }
    }

    fun toJson(): String =
        """{"protocolVersion":${jsonQuote(protocolVersion)},"channel":${jsonQuote(channel)},"eventId":${jsonQuote(eventId)},"workspaceId":${jsonQuote(workspaceId)},"principalId":${jsonQuote(principalId)},"clientId":${jsonQuote(clientId)},"text":${jsonQuote(text)},"receivedAtEpochSeconds":$receivedAtEpochSeconds}"""
}

enum class ChannelProcessorStatus(val wireValue: String) {
    PROCESSED("processed"),
    DUPLICATE("duplicate"),
}

data class ChannelProcessorAcknowledgement(
    val eventId: String,
    val status: ChannelProcessorStatus,
) {
    init {
        requireBoundedToken(eventId, 256, "eventId")
    }

    val protocolVersion: String = CHANNEL_PROCESSOR_PROTOCOL_VERSION

    fun toJson(): String =
        """{"protocolVersion":${jsonQuote(protocolVersion)},"eventId":${jsonQuote(eventId)},"status":${jsonQuote(status.wireValue)}}"""
}

private fun requireBoundedToken(value: String, maximumBytes: Int, field: String) {
    require(
        value.isNotEmpty() &&
            value.toByteArray(StandardCharsets.UTF_8).size <= maximumBytes &&
            value.none { it.isWhitespace() || it.code < 32 || it.code == 127 },
    ) {
        "Invalid Rembrane channel processor $field"
    }
}

private fun jsonQuote(value: String): String = buildString {
    append('"')
    value.forEach { character ->
        when (character) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\b' -> append("\\b")
            '\u000c' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else ->
                if (character.code < 32) {
                    append("\\u")
                    append(character.code.toString(16).padStart(4, '0'))
                } else {
                    append(character)
                }
        }
    }
    append('"')
}
