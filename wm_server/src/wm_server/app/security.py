from __future__ import annotations

"""
Simple HMAC-signed token utilities for secure direct-upload handoff.

Overview
- Tokens are compact, URL-safe strings that encode a JSON payload (workspace_id, destination_path, expiry)
  and an HMAC-SHA256 signature.
- Intended for short-lived authorization of direct uploads to a specific destination path within a workspace.
- This is NOT a general JWT implementation; it's a minimal, purpose-built scheme.

Token format (string)
    v1.<base64url(payload_json)><.><base64url(signature_bytes)>

Where:
- payload_json is a canonical JSON encoding of:
    {
      "v": 1,                     # version
      "ws": "<workspace_id>",     # workspace id
      "dst": "<destination_path>",# absolute path inside container
      "iat": <issued_at_epoch>,   # seconds since epoch
      "exp": <expires_epoch>      # seconds since epoch
    }
- signature_bytes = HMAC_SHA256(secret, payload_json_bytes)
- base64url encoding omits padding for compactness.

Security properties
- Signature: Prevents tampering with payload fields.
- Short TTL: Minimizes risk if a token is leaked.
- Scoped: Token is bound to a single workspace_id and destination path.

Usage
    # Issue a token
    token = generate_upload_token(
        secret="super-secret",
        workspace_id="ws-123",
        destination_path="/tmp/workspace/upload.bin",
        ttl_seconds=900,
    )

    # Verify and parse on request
    payload = parse_and_verify_upload_token(
        secret="super-secret",
        token=token,
    )
    # Optional checks to bind to the actual request:
    assert_token_matches_request(payload, workspace_id, destination_path)

Integration guidance
- The server should expose a token-issuing endpoint that requires the normal API key.
- The upload endpoint should require this short-lived token (header or query param),
  verify it, and ensure the workspace_id and destination_path match the request.
"""

import base64
import hashlib
import hmac
import json
import time
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional


# -----------------------
# Exceptions
# -----------------------

class InvalidTokenError(ValueError):
    """Raised when a token is malformed or fails signature validation."""


class TokenExpiredError(ValueError):
    """Raised when a token is validly signed but expired."""


# -----------------------
# Data structures
# -----------------------

@dataclass(frozen=True)
class UploadTokenPayload:
    """
    Structured, validated form of a parsed token payload.
    """
    version: int
    workspace_id: str
    destination_path: str
    issued_at: int
    expires_at: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "v": self.version,
            "ws": self.workspace_id,
            "dst": self.destination_path,
            "iat": self.issued_at,
            "exp": self.expires_at,
        }


# -----------------------
# Internal helpers
# -----------------------

_TOKEN_VERSION = 1
_TOKEN_PREFIX = "v1"


def _b64u_encode(data: bytes) -> str:
    """
    Base64 URL-safe encoding without padding.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data_str: str) -> bytes:
    """
    Base64 URL-safe decoding that tolerates missing padding.
    """
    s = data_str.strip()
    # Restore padding
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    """
    Produce a canonical JSON byte representation for signing.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(secret: str, payload_bytes: bytes) -> bytes:
    """
    HMAC-SHA256 signature over the payload bytes using the provided secret.
    """
    key = secret.encode("utf-8")
    return hmac.new(key, payload_bytes, hashlib.sha256).digest()


def _now_s() -> int:
    return int(time.time())


def _validate_destination_path(path: str) -> None:
    """
    Ensure the destination path is an absolute Unix-like path.
    """
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("destination_path must be an absolute path starting with '/'.")


# -----------------------
# Public API: Token issue/verify
# -----------------------

def generate_upload_token(
    *,
    secret: str,
    workspace_id: str,
    destination_path: str,
    ttl_seconds: int = 900,
    issued_at: Optional[int] = None,
) -> str:
    """
    Generate a short-lived, HMAC-signed token granting permission to upload a file
    to a specific destination path for a given workspace.

    Args:
        secret: Server-side secret used to sign tokens.
        workspace_id: Target workspace identifier.
        destination_path: Absolute path inside the container where the upload will land.
        ttl_seconds: Token time-to-live in seconds (default: 900 = 15 minutes).
        issued_at: Optional override for token issuance time (epoch seconds).

    Returns:
        A compact token string suitable for header or query param transport.

    Raises:
        ValueError: For invalid arguments (e.g., non-absolute destination_path).
    """
    if not secret:
        raise ValueError("A non-empty secret is required to issue tokens.")
    if not workspace_id or not isinstance(workspace_id, str):
        raise ValueError("workspace_id must be a non-empty string.")
    _validate_destination_path(destination_path)
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer.")

    iat = int(issued_at if issued_at is not None else _now_s())
    exp = iat + int(ttl_seconds)

    payload_obj = {
        "v": _TOKEN_VERSION,
        "ws": workspace_id,
        "dst": destination_path,
        "iat": iat,
        "exp": exp,
    }
    payload_bytes = _canonical_json_bytes(payload_obj)
    sig = _sign(secret, payload_bytes)

    token = f"{_TOKEN_PREFIX}.{_b64u_encode(payload_bytes)}.{_b64u_encode(sig)}"
    return token


def parse_and_verify_upload_token(
    *,
    secret: str,
    token: str,
    now_s: Optional[int] = None,
) -> UploadTokenPayload:
    """
    Verify an upload token and return its validated payload.

    Steps:
    - Parse token format: v1.<b64payload>.<b64sig>
    - Verify HMAC-SHA256 signature over payload bytes
    - Verify expiry (exp >= now)
    - Validate essential fields and types

    Args:
        secret: Server-side secret used to sign tokens.
        token: Token string to validate.
        now_s: Optional override for current time (epoch seconds).

    Returns:
        UploadTokenPayload with validated fields.

    Raises:
        InvalidTokenError: For malformed tokens or signature mismatch.
        TokenExpiredError: For valid tokens that have expired.
    """
    if not isinstance(token, str) or "." not in token:
        raise InvalidTokenError("Malformed token.")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _TOKEN_PREFIX:
        raise InvalidTokenError("Unsupported token format or version.")

    b64_payload, b64_sig = parts[1], parts[2]
    try:
        payload_bytes = _b64u_decode(b64_payload)
        sig_bytes = _b64u_decode(b64_sig)
    except Exception as e:
        raise InvalidTokenError(f"Invalid token encoding: {e}")

    # Verify signature
    expected_sig = _sign(secret, payload_bytes)
    if not hmac.compare_digest(expected_sig, sig_bytes):
        raise InvalidTokenError("Signature verification failed.")

    # Parse and validate payload
    try:
        obj = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise InvalidTokenError("Payload is not valid JSON.")

    if not isinstance(obj, dict):
        raise InvalidTokenError("Payload structure is invalid.")

    version = int(obj.get("v", 0))
    if version != _TOKEN_VERSION:
        raise InvalidTokenError("Unsupported token version.")

    ws = obj.get("ws")
    dst = obj.get("dst")
    iat = obj.get("iat")
    exp = obj.get("exp")

    if not isinstance(ws, str) or not ws:
        raise InvalidTokenError("Payload is missing a valid 'ws'.")
    if not isinstance(dst, str) or not dst.startswith("/"):
        raise InvalidTokenError("Payload is missing a valid absolute 'dst' path.")
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise InvalidTokenError("Payload is missing valid 'iat'/'exp' timestamps.")

    now = int(now_s if now_s is not None else _now_s())
    if exp < now:
        raise TokenExpiredError("Token has expired.")

    return UploadTokenPayload(
        version=version,
        workspace_id=ws,
        destination_path=dst,
        issued_at=iat,
        expires_at=exp,
    )


def assert_token_matches_request(
    payload: UploadTokenPayload,
    *,
    workspace_id: str,
    destination_path: str,
) -> None:
    """
    Ensure the token payload matches the workspace_id and destination_path requested.

    Raises:
        InvalidTokenError if there is a mismatch.
    """
    if payload.workspace_id != workspace_id:
        raise InvalidTokenError("Token workspace_id does not match request.")
    # Normalize destination path check: must exactly match what was authorized
    if payload.destination_path != destination_path:
        raise InvalidTokenError("Token destination_path does not match request.")


# -----------------------
# Convenience wrappers (optional)
# -----------------------

def generate_upload_token_from_settings(
    settings: Any,
    *,
    workspace_id: str,
    destination_path: str,
    ttl_seconds: Optional[int] = None,
) -> str:
    """
    Convenience wrapper to issue a token from a settings object
    expected to provide:
      - upload_token_secret: Optional[str]
      - upload_token_ttl_seconds: int

    Raises:
        RuntimeError if upload_token_secret is not configured.
    """
    # If the settings object exposes token_secret_effective(), treat it as authoritative:
    # - Use its return value and do NOT fall back to env or other attributes when it is present.
    # - If it returns falsy, consider the secret unset and raise.
    if hasattr(settings, "token_secret_effective"):
        secret = settings.token_secret_effective()
        if not secret:
            raise RuntimeError("Direct upload token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).")
    else:
        # Legacy fallback when token_secret_effective() is not provided by settings
        secret = getattr(settings, "upload_token_secret", None) or os.getenv("WORKSPACE_UPLOAD_TOKEN_SECRET")
        if not secret:
            raise RuntimeError("Direct upload token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).")

    ttl_cfg = int(ttl_seconds) if ttl_seconds is not None else int(
        getattr(settings, "upload_token_ttl_seconds", os.getenv("WORKSPACE_UPLOAD_TOKEN_TTL_SECONDS", "900"))
    )
    return generate_upload_token(
        secret=str(secret),
        workspace_id=workspace_id,
        destination_path=destination_path,
        ttl_seconds=ttl_cfg,
    )


def parse_and_verify_upload_token_from_settings(
    settings: Any,
    *,
    token: str,
    now_s: Optional[int] = None,
) -> UploadTokenPayload:
    """
    Convenience wrapper to verify a token using a settings object
    expected to provide:
      - upload_token_secret: Optional[str]
    """
    # If the settings object exposes token_secret_effective(), treat it as authoritative:
    # - Use its return value and do NOT fall back to env or other attributes when it is present.
    # - If it returns falsy, consider the secret unset and raise.
    if hasattr(settings, "token_secret_effective"):
        secret = settings.token_secret_effective()
        if not secret:
            raise RuntimeError("Direct upload token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).")
    else:
        # Legacy fallback when token_secret_effective() is not provided by settings
        secret = getattr(settings, "upload_token_secret", None) or os.getenv("WORKSPACE_UPLOAD_TOKEN_SECRET")
        if not secret:
            raise RuntimeError("Direct upload token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).")
    return parse_and_verify_upload_token(secret=str(secret), token=token, now_s=now_s)


__all__ = [
    "UploadTokenPayload",
    "InvalidTokenError",
    "TokenExpiredError",
    "generate_upload_token",
    "parse_and_verify_upload_token",
    "assert_token_matches_request",
    "generate_upload_token_from_settings",
    "parse_and_verify_upload_token_from_settings",
    "DownloadTokenPayload",
    "generate_download_token",
    "parse_and_verify_download_token",
    "assert_download_token_matches_request",
    "generate_download_token_from_settings",
    "parse_and_verify_download_token_from_settings",
]


# -----------------------
# Download token support (copy-from hardening)
# -----------------------

@dataclass(frozen=True)
class DownloadTokenPayload:
    """
    Structured, validated form of a parsed download token payload.
    """
    version: int
    workspace_id: str
    source_path: str
    issued_at: int
    expires_at: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "v": self.version,
            "ws": self.workspace_id,
            "src": self.source_path,
            "iat": self.issued_at,
            "exp": self.expires_at,
        }


def generate_download_token(
    *,
    secret: str,
    workspace_id: str,
    source_path: str,
    ttl_seconds: int = 900,
    issued_at: Optional[int] = None,
) -> str:
    """
    Generate a short-lived, HMAC-signed token granting permission to download a file
    from a specific source path for a given workspace.

    Args:
        secret: Server-side secret used to sign tokens.
        workspace_id: Target workspace identifier.
        source_path: Absolute path inside the container that will be downloaded.
        ttl_seconds: Token time-to-live in seconds (default: 900 = 15 minutes).
        issued_at: Optional override for token issuance time (epoch seconds).

    Returns:
        A compact token string suitable for header or query param transport.
    """
    if not secret:
        raise ValueError("A non-empty secret is required to issue tokens.")
    if not workspace_id or not isinstance(workspace_id, str):
        raise ValueError("workspace_id must be a non-empty string.")
    # Reuse path validator (requires absolute path)
    _validate_destination_path(source_path)
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer.")

    iat = int(issued_at if issued_at is not None else _now_s())
    exp = iat + int(ttl_seconds)

    payload_obj = {
        "v": _TOKEN_VERSION,
        "ws": workspace_id,
        "src": source_path,
        "iat": iat,
        "exp": exp,
    }
    payload_bytes = _canonical_json_bytes(payload_obj)
    sig = _sign(secret, payload_bytes)

    token = f"{_TOKEN_PREFIX}.{_b64u_encode(payload_bytes)}.{_b64u_encode(sig)}"
    return token


def parse_and_verify_download_token(
    *,
    secret: str,
    token: str,
    now_s: Optional[int] = None,
) -> DownloadTokenPayload:
    """
    Verify a download token and return its validated payload.

    Steps:
    - Parse token format: v1.<b64payload>.<b64sig>
    - Verify HMAC-SHA256 signature over payload bytes
    - Verify expiry (exp >= now)
    - Validate essential fields and types
    """
    if not isinstance(token, str) or "." not in token:
        raise InvalidTokenError("Malformed token.")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != _TOKEN_PREFIX:
        raise InvalidTokenError("Unsupported token format or version.")

    b64_payload, b64_sig = parts[1], parts[2]
    try:
        payload_bytes = _b64u_decode(b64_payload)
        sig_bytes = _b64u_decode(b64_sig)
    except Exception as e:
        raise InvalidTokenError(f"Invalid token encoding: {e}")

    expected_sig = _sign(secret, payload_bytes)
    if not hmac.compare_digest(expected_sig, sig_bytes):
        raise InvalidTokenError("Signature verification failed.")

    try:
        obj = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise InvalidTokenError("Payload is not valid JSON.")

    if not isinstance(obj, dict):
        raise InvalidTokenError("Payload structure is invalid.")

    version = int(obj.get("v", 0))
    if version != _TOKEN_VERSION:
        raise InvalidTokenError("Unsupported token version.")

    ws = obj.get("ws")
    src = obj.get("src")
    iat = obj.get("iat")
    exp = obj.get("exp")

    if not isinstance(ws, str) or not ws:
        raise InvalidTokenError("Payload is missing a valid 'ws'.")
    if not isinstance(src, str) or not src.startswith("/"):
        raise InvalidTokenError("Payload is missing a valid absolute 'src' path.")
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise InvalidTokenError("Payload is missing valid 'iat'/'exp' timestamps.")

    now = int(now_s if now_s is not None else _now_s())
    if exp < now:
        raise TokenExpiredError("Token has expired.")

    return DownloadTokenPayload(
        version=version,
        workspace_id=ws,
        source_path=src,
        issued_at=iat,
        expires_at=exp,
    )


def assert_download_token_matches_request(
    payload: DownloadTokenPayload,
    *,
    workspace_id: str,
    source_path: str,
) -> None:
    """
    Ensure the token payload matches the workspace_id and source_path requested.
    """
    if payload.workspace_id != workspace_id:
        raise InvalidTokenError("Token workspace_id does not match request.")
    if payload.source_path != source_path:
        raise InvalidTokenError("Token source_path does not match request.")


def generate_download_token_from_settings(
    settings: Any,
    *,
    workspace_id: str,
    source_path: str,
    ttl_seconds: Optional[int] = None,
) -> str:
    """
    Convenience wrapper to issue a download token from a settings object
    expected to provide:
      - upload_token_secret: Optional[str]
      - upload_token_ttl_seconds: int
    """
    secret = getattr(settings, "upload_token_secret", None) or os.getenv("WORKSPACE_UPLOAD_TOKEN_SECRET")
    if not secret:
        raise RuntimeError("Direct upload token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).")
    ttl_cfg = int(ttl_seconds) if ttl_seconds is not None else int(
        getattr(settings, "upload_token_ttl_seconds", os.getenv("WORKSPACE_UPLOAD_TOKEN_TTL_SECONDS", "900"))
    )
    return generate_download_token(
        secret=str(secret),
        workspace_id=workspace_id,
        source_path=source_path,
        ttl_seconds=ttl_cfg,
    )


def parse_and_verify_download_token_from_settings(
    settings: Any,
    *,
    token: str,
    now_s: Optional[int] = None,
) -> DownloadTokenPayload:
    """
    Convenience wrapper to verify a download token using a settings object
    expected to provide:
      - upload_token_secret: Optional[str]
    """
    secret = getattr(settings, "upload_token_secret", None) or os.getenv("WORKSPACE_UPLOAD_TOKEN_SECRET")
    if not secret:
        raise RuntimeError("Direct upload token secret is not configured (WORKSPACE_UPLOAD_TOKEN_SECRET).")
    return parse_and_verify_download_token(secret=str(secret), token=token, now_s=now_s)