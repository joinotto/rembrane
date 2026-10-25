"""Zero-dependency authenticated client for the Rembrane REST API."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

DEFAULT_MAXIMUM_RESPONSE_BYTES = 1024 * 1024
CHANNEL_PROCESSOR_PROTOCOL_VERSION = "0.1"
CHANNEL_PROCESSOR_CHANNELS = {
    "whatsapp-business",
    "imessage-extension",
    "mobile-share",
}
CHANNEL_PROCESSOR_STATUSES = {"processed", "duplicate"}
CHANNEL_PROCESSOR_MESSAGE_KEYS = {
    "protocolVersion",
    "channel",
    "eventId",
    "workspaceId",
    "principalId",
    "clientId",
    "text",
    "receivedAtEpochSeconds",
}
Transport = Callable[
    [str, str, Mapping[str, str], bytes | None, int],
    tuple[int, Mapping[str, str], bytes],
]


@dataclass(frozen=True)
class RembraneError(Exception):
    status: int
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise RembraneError(code, "redirect_rejected", "Redirects are not allowed")


def _default_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    maximum_response_bytes: int,
) -> tuple[int, Mapping[str, str], bytes]:
    request = Request(url, data=body, headers=dict(headers), method=method)
    opener = build_opener(_RejectRedirects)
    try:
        with opener.open(request, timeout=30) as response:
            payload = response.read(maximum_response_bytes + 1)
            return response.status, dict(response.headers.items()), payload
    except HTTPError as error:
        payload = error.read(maximum_response_bytes + 1)
        return error.code, dict(error.headers.items()), payload


class RembraneClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        transport: Transport = _default_transport,
        maximum_response_bytes: int = DEFAULT_MAXIMUM_RESPONSE_BYTES,
    ) -> None:
        parsed = urlsplit(base_url)
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise ValueError("Rembrane requires HTTPS or an explicit loopback URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(
                "Rembrane base URL must not contain credentials, query, or fragment"
            )
        if not token:
            raise ValueError("Rembrane bearer token is required")
        if maximum_response_bytes < 1:
            raise ValueError("maximum_response_bytes must be positive")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._transport = transport
        self._maximum_response_bytes = maximum_response_bytes

    def resolve_context(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/context/resolve", request)

    def resolve_graph_context(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/graph/context/resolve", request)

    def rotate_workspace_key(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/workspaces/key-rotation", request)

    def create_workspace_invitation(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/workspaces/invitations", request)

    def accept_workspace_invitation(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/workspaces/invitations/accept", request)

    def revoke_workspace_invitation(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/workspaces/invitations/revoke", request)

    def list_workspace_invitations(
        self,
        workspace_id: str,
        *,
        status: str | None = None,
        limit: int | None = None,
    ) -> Any:
        query: dict[str, str | int] = {"workspaceId": workspace_id}
        if status is not None:
            query["status"] = status
        if limit is not None:
            query["limit"] = limit
        return self._request("GET", f"/workspaces/invitations?{urlencode(query)}", None)

    def list_administrative_audit(
        self,
        workspace_id: str,
        *,
        after_epoch_seconds: int | None = None,
        limit: int | None = None,
    ) -> Any:
        query: dict[str, str | int] = {"workspaceId": workspace_id}
        if after_epoch_seconds is not None:
            query["afterEpochSeconds"] = after_epoch_seconds
        if limit is not None:
            query["limit"] = limit
        return self._request("GET", f"/administrative-audit?{urlencode(query)}", None)

    def set_retention_policy(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/retention/policy", request)

    def place_legal_hold(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/retention/legal-holds", request)

    def release_legal_hold(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/retention/legal-holds/release", request)

    def execute_retention_purge(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/retention/purge", request)

    def _request(self, method: str, path: str, body: Mapping[str, Any] | None) -> Any:
        encoded = (
            None
            if body is None
            else json.dumps(body, separators=(",", ":")).encode("utf-8")
        )
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token}",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        status, response_headers, payload = self._transport(
            method,
            f"{self._base_url}{path}",
            headers,
            encoded,
            self._maximum_response_bytes,
        )
        if len(payload) > self._maximum_response_bytes:
            raise RembraneError(status, "response_too_large", "Response exceeded limit")
        content_type = next(
            (
                value
                for key, value in response_headers.items()
                if key.lower() == "content-type"
            ),
            "",
        )
        if not content_type.lower().startswith("application/json"):
            raise RembraneError(status, "invalid_response", "Expected JSON response")
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RembraneError(
                status, "invalid_response", "Response was not valid JSON"
            ) from error
        if not 200 <= status < 300:
            code = (
                value.get("code", "request_failed")
                if isinstance(value, dict)
                else "request_failed"
            )
            message = (
                value.get("message", "Rembrane request failed")
                if isinstance(value, dict)
                else "Rembrane request failed"
            )
            raise RembraneError(status, str(code), str(message))
        return value


def parse_channel_processor_message(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != CHANNEL_PROCESSOR_MESSAGE_KEYS:
        raise ValueError("Invalid Rembrane channel processor message")
    if (
        value["protocolVersion"] != CHANNEL_PROCESSOR_PROTOCOL_VERSION
        or value["channel"] not in CHANNEL_PROCESSOR_CHANNELS
        or not _is_bounded_token(value["eventId"], 256)
        or not _is_bounded_token(value["workspaceId"], 255)
        or not _is_bounded_token(value["principalId"], 255)
        or not _is_bounded_token(value["clientId"], 255)
        or type(value["text"]) is not str
        or not value["text"].strip()
        or len(value["text"].encode("utf-8")) > 16_384
        or type(value["receivedAtEpochSeconds"]) is not int
        or value["receivedAtEpochSeconds"] < 1
    ):
        raise ValueError("Invalid Rembrane channel processor message")
    return dict(value)


def create_channel_processor_acknowledgement(
    event_id: str, status: str
) -> dict[str, str]:
    if not _is_bounded_token(event_id, 256) or status not in CHANNEL_PROCESSOR_STATUSES:
        raise ValueError("Invalid Rembrane channel processor acknowledgement")
    return {
        "protocolVersion": CHANNEL_PROCESSOR_PROTOCOL_VERSION,
        "eventId": event_id,
        "status": status,
    }


def _is_bounded_token(value: Any, maximum_bytes: int) -> bool:
    return (
        type(value) is str
        and bool(value)
        and len(value.encode("utf-8")) <= maximum_bytes
        and not any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in value
        )
    )
