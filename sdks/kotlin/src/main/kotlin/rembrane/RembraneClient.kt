package rembrane

import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.time.Duration

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

    fun rotateWorkspaceKey(jsonBody: String): String =
        request("POST", "/workspaces/key-rotation", jsonBody)

    fun createWorkspaceInvitation(jsonBody: String): String =
        request("POST", "/workspaces/invitations", jsonBody)

    fun acceptWorkspaceInvitation(jsonBody: String): String =
        request("POST", "/workspaces/invitations/accept", jsonBody)

    fun revokeWorkspaceInvitation(jsonBody: String): String =
        request("POST", "/workspaces/invitations/revoke", jsonBody)

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
        if (response.body.size > maximumResponseBytes) {
            throw RembraneApiException(
                response.status,
                "response_too_large",
                "Response exceeded limit",
            )
        }
        val contentType = response.headers.entries
            .firstOrNull { it.key.equals("content-type", ignoreCase = true) }
            ?.value
            ?.firstOrNull()
            .orEmpty()
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

    private fun encode(value: String): String =
        URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

    private fun jsonString(json: String, field: String): String? {
        val pattern = Regex("\"${Regex.escape(field)}\"\\s*:\\s*\"([^\"\\\\]*)\"")
        return pattern.find(json)?.groupValues?.get(1)
    }
}
