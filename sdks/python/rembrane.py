"""Zero-dependency authenticated client for the Rembrane REST API."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Literal, Mapping, NotRequired, TypedDict
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

DEFAULT_MAXIMUM_RESPONSE_BYTES = 1024 * 1024
CHANNEL_PROCESSOR_PROTOCOL_VERSION = "0.1"
CHANNEL_PROCESSOR_CHANNELS = {
    "whatsapp-business",
    "imessage-extension",
    "mobile-share",
}
CHANNEL_PROCESSOR_STATUSES = {"processed", "duplicate"}
DISCOVERY_PROCESSING_MODES = {"hosted", "customer-gateway", "local-only"}
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

EvidenceSource = Literal[
    "user-statement",
    "agent-observation",
    "tool-result",
    "imported-record",
    "workspace-decision",
]
TripConstraintKind = Literal[
    "accessibility",
    "accommodation",
    "budget",
    "dietary",
    "documentation",
    "schedule",
    "transport",
    "other",
]
TripDecisionStatus = Literal["proposed", "selected", "rejected"]
BookingResearchKind = Literal[
    "flight",
    "lodging",
    "ground-transport",
    "activity",
    "other",
]


class TravelRequest(TypedDict):
    workspaceId: str
    subjectId: str


class CreateTripRequest(TravelRequest):
    title: str
    origin: str
    destinations: list[str]
    departNotBefore: str
    returnNotAfter: str
    expectedPreviousSequence: int


class TripRevisionRequest(TravelRequest):
    tripId: str
    expectedTripVersion: int
    expectedPreviousSequence: int


class AddTripParticipantRequest(TripRevisionRequest):
    label: str


class AddTripConstraintRequest(TripRevisionRequest):
    participantId: NotRequired[str | None]
    kind: TripConstraintKind
    statement: str
    evidenceSource: EvidenceSource


class RecordTripDecisionRequest(TripRevisionRequest):
    status: TripDecisionStatus
    summary: str
    rationale: NotRequired[str | None]
    evidenceSource: EvidenceSource


class CaptureBookingResearchRequest(TravelRequest):
    tripId: str
    kind: BookingResearchKind
    provider: str
    summary: str
    sourceReference: str
    evidenceSource: EvidenceSource
    observedAt: str
    expiresAt: str
    expectedPreviousSequence: int


class ResolveTravelContextRequest(TravelRequest):
    tripId: str
    purpose: str
    asOf: str
    includeSourceReferences: NotRequired[bool]
    includeSensitiveProfile: NotRequired[bool]


class Trip(TypedDict):
    tripId: str
    workspaceId: str
    ownerSubjectId: str
    version: int


class TripParticipant(TypedDict):
    tripId: str
    participantId: str
    label: str
    tripVersion: int


class TripRevision(TypedDict):
    tripId: str
    recordId: str
    tripVersion: int


class BookingResearch(TypedDict):
    id: str
    workspaceId: str
    tripId: str
    observedBy: str
    version: int
    expiresAt: str


class TravelParticipant(TypedDict):
    participantId: str
    label: str


class TravelConstraint(TypedDict):
    constraintId: str
    participantId: NotRequired[str | None]
    kind: TripConstraintKind
    statement: str
    evidenceId: str


class TravelDecision(TypedDict):
    decisionId: str
    status: TripDecisionStatus
    summary: str
    rationale: NotRequired[str | None]
    decidedBy: str
    evidenceId: str


class TravelSensitiveProfile(TypedDict):
    participants: list[TravelParticipant]
    constraints: list[TravelConstraint]
    decisions: list[TravelDecision]


class TravelTrip(TypedDict):
    tripId: str
    title: str
    origin: str
    destinations: list[str]
    departNotBefore: str
    returnNotAfter: str
    version: int
    sensitiveProfile: NotRequired[TravelSensitiveProfile]


class TravelResearch(TypedDict):
    researchId: str
    kind: BookingResearchKind
    provider: str
    summary: str
    evidenceId: str
    observedAt: str
    expiresAt: str
    version: int
    sourceReference: NotRequired[str]


class TravelContext(TypedDict):
    disclosureId: str
    trip: TravelTrip
    freshResearch: list[TravelResearch]
    expiredResearch: list[TravelResearch]


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

    def discover(self) -> Any:
        parsed = urlsplit(self._base_url)
        url = f"{parsed.scheme}://{parsed.netloc}/.well-known/ai-memory"
        value = self._request_url("GET", url, None, authenticated=False)
        return _validate_memory_discovery(value, self._base_url)

    def resolve_graph_context(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/graph/context/resolve", request)

    def remember_preference(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/memories/preferences", request)

    def record_work_trace(self, request: Mapping[str, Any]) -> Any:
        return self._request("POST", "/memories/work-traces", request)

    def correct_memory(
        self, memory_id: str, request: Mapping[str, Any]
    ) -> Any:
        path_id = _opaque_path_id(memory_id, "memory_id")
        return self._request("POST", f"/memories/{path_id}/correction", request)

    def delete_memory(self, memory_id: str, request: Mapping[str, Any]) -> Any:
        path_id = _opaque_path_id(memory_id, "memory_id")
        return self._request("POST", f"/memories/{path_id}/deletion", request)

    def checkpoint_activity(
        self, activity_id: str, request: Mapping[str, Any]
    ) -> Any:
        path_id = _activity_path_id(activity_id)
        return self._request("POST", f"/activities/{path_id}/checkpoint", request)

    def resume_activity(
        self,
        activity_id: str,
        workspace_id: str,
        subject_id: str,
        *,
        purpose: str | None = None,
        state_fingerprint: str | None = None,
    ) -> Any:
        path_id = _activity_path_id(activity_id)
        query = {"workspaceId": workspace_id, "subjectId": subject_id}
        if purpose is not None:
            query["purpose"] = purpose
        if state_fingerprint is not None:
            query["stateFingerprint"] = state_fingerprint
        return self._request(
            "GET", f"/activities/{path_id}/resume?{urlencode(query)}", None
        )

    def create_trip(self, request: CreateTripRequest) -> Trip:
        _validate_travel_request_identity(request)
        return self._request("POST", "/travel/trips", request)

    def add_trip_participant(
        self, request: AddTripParticipantRequest
    ) -> TripParticipant:
        _validate_travel_request_identity(request, require_trip_id=True)
        return self._request("POST", "/travel/trip-participants", request)

    def add_trip_constraint(
        self, request: AddTripConstraintRequest
    ) -> TripRevision:
        _validate_travel_request_identity(
            request, require_trip_id=True, allow_participant_id=True
        )
        return self._request("POST", "/travel/trip-constraints", request)

    def record_trip_decision(
        self, request: RecordTripDecisionRequest
    ) -> TripRevision:
        _validate_travel_request_identity(request, require_trip_id=True)
        return self._request("POST", "/travel/trip-decisions", request)

    def capture_booking_research(
        self, request: CaptureBookingResearchRequest
    ) -> BookingResearch:
        _validate_travel_request_identity(request, require_trip_id=True)
        return self._request("POST", "/travel/booking-research", request)

    def resolve_travel_context(
        self, request: ResolveTravelContextRequest
    ) -> TravelContext:
        _validate_travel_request_identity(request, require_trip_id=True)
        return self._request("POST", "/travel/context/resolve", request)

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
        return self._request_url(
            method,
            f"{self._base_url}{path}",
            body,
            authenticated=True,
        )

    def _request_url(
        self,
        method: str,
        url: str,
        body: Mapping[str, Any] | None,
        *,
        authenticated: bool,
    ) -> Any:
        encoded = (
            None
            if body is None
            else json.dumps(body, separators=(",", ":")).encode("utf-8")
        )
        headers = {
            "Accept": "application/json",
        }
        if authenticated:
            headers["Authorization"] = f"Bearer {self._token}"
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        status, response_headers, payload = self._transport(
            method,
            url,
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


def _activity_path_id(value: Any) -> str:
    return _opaque_path_id(value, "activity_id")


def _opaque_path_id(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or len(value.encode("utf-8")) > 255
        or not value
        or not value[0].isalnum()
        or not all(
            character.isascii()
            and (character.isalnum() or character in {".", "_", ":", "-"})
            for character in value
        )
    ):
        raise ValueError(f"{label} must be a bounded opaque identifier")
    return quote(value, safe="")


def _validate_travel_request_identity(
    request: Mapping[str, Any],
    *,
    require_trip_id: bool = False,
    allow_participant_id: bool = False,
) -> None:
    if not isinstance(request, Mapping):
        raise ValueError("travel request must be a mapping")
    _opaque_path_id(request.get("workspaceId"), "workspaceId")
    _opaque_path_id(request.get("subjectId"), "subjectId")
    if require_trip_id:
        _opaque_path_id(request.get("tripId"), "tripId")
    participant_id = request.get("participantId")
    if allow_participant_id and participant_id is not None:
        _opaque_path_id(participant_id, "participantId")


def _validate_memory_discovery(value: Any, expected_api: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise _invalid_discovery()
    provider = value.get("provider")
    versions = value.get("protocolVersions")
    endpoints = value.get("endpoints")
    capabilities = value.get("capabilities")
    privacy = value.get("privacy")
    required_capabilities = {
        "contextResolution",
        "memoryProposal",
        "activityCheckpoint",
        "disclosureReceipt",
        "deletionPropagation",
    }
    if (
        type(provider) is not dict
        or not _is_bounded_text(provider.get("id"), 255)
        or not _is_bounded_text(provider.get("name"), 255)
        or type(versions) is not list
        or not versions
        or len(set(versions)) != len(versions)
        or not all(
            type(version) is str
            and len(version.split(".")) == 2
            and all(part.isdigit() and part for part in version.split("."))
            for version in versions
        )
        or type(endpoints) is not dict
        or _normalize_api_root(endpoints.get("api")) != expected_api
        or type(capabilities) is not dict
        or not all(
            type(capabilities.get(name)) is bool for name in required_capabilities
        )
        or type(privacy) is not dict
        or privacy.get("disclosureReceipts") is not True
        or type(privacy.get("processingModes")) is not list
        or not privacy["processingModes"]
        or len(set(privacy["processingModes"])) != len(privacy["processingModes"])
        or not all(
            mode in DISCOVERY_PROCESSING_MODES for mode in privacy["processingModes"]
        )
    ):
        raise _invalid_discovery()
    return dict(value)


def _normalize_api_root(value: Any) -> str | None:
    if type(value) is not str:
        return None
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.netloc
        or not parsed.path.endswith("/v1")
    ):
        return None
    return value.rstrip("/")


def _is_bounded_text(value: Any, maximum_bytes: int) -> bool:
    return (
        type(value) is str
        and bool(value.strip())
        and len(value.encode("utf-8")) <= maximum_bytes
    )


def _invalid_discovery() -> RembraneError:
    return RembraneError(
        200,
        "invalid_discovery",
        "Provider discovery was invalid or did not match the configured API",
    )
