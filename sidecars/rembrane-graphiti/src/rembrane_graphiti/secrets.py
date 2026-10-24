"""Protected local secret resolution for the Graphiti sidecar."""

from __future__ import annotations

import os
import stat

MAXIMUM_SECRET_BYTES = 65_536
MAXIMUM_ENVIRONMENT_NAME_BYTES = 128
MAXIMUM_FILE_REFERENCE_BYTES = 4_096
_OPAQUE_ERROR = "Graphiti credential unavailable"


def resolve_secret(reference_environment: str, default_environment: str) -> str:
    """Resolve an env/file locator without accepting inline credential values."""

    locator = os.environ.get(reference_environment, "")
    if not locator:
        return _resolve_environment_secret(default_environment)
    source, separator, target = locator.partition(":")
    if not separator or not target:
        raise RuntimeError(_OPAQUE_ERROR)
    if source == "env":
        return _resolve_environment_secret(target)
    if source == "file":
        return _resolve_file_secret(target)
    raise RuntimeError(_OPAQUE_ERROR)


def _resolve_environment_secret(variable: str) -> str:
    if (
        len(variable) > MAXIMUM_ENVIRONMENT_NAME_BYTES
        or not variable
        or (not variable[0].isalpha() and variable[0] != "_")
        or any(
            not character.isascii()
            or not (character.isalnum() or character == "_")
            for character in variable
        )
    ):
        raise RuntimeError(_OPAQUE_ERROR)
    try:
        value = os.environ[variable]
    except (KeyError, UnicodeError) as error:
        raise RuntimeError(_OPAQUE_ERROR) from error
    return _validate_resolved_secret(value)


def _resolve_file_secret(path: str) -> str:
    if (
        len(path.encode()) > MAXIMUM_FILE_REFERENCE_BYTES
        or path.strip() != path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise RuntimeError(_OPAQUE_ERROR)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAXIMUM_SECRET_BYTES
            or metadata.st_mode & 0o077
        ):
            raise RuntimeError(_OPAQUE_ERROR)
        value = bytearray()
        while len(value) <= MAXIMUM_SECRET_BYTES:
            chunk = os.read(
                descriptor,
                min(8_192, MAXIMUM_SECRET_BYTES + 1 - len(value)),
            )
            if not chunk:
                break
            value.extend(chunk)
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError(_OPAQUE_ERROR) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value) > MAXIMUM_SECRET_BYTES:
        raise RuntimeError(_OPAQUE_ERROR)
    if value.endswith(b"\n"):
        value.pop()
        if value.endswith(b"\r"):
            value.pop()
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError(_OPAQUE_ERROR) from error
    finally:
        value[:] = b"\0" * len(value)
    return _validate_resolved_secret(decoded)


def _validate_resolved_secret(value: str) -> str:
    if not value or len(value.encode()) > MAXIMUM_SECRET_BYTES or "\0" in value:
        raise RuntimeError(_OPAQUE_ERROR)
    return value
