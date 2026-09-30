"""Dependency-free Driver RuStore boundary. Mutations are never retried here."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from threading import Lock
from typing import Protocol, Sequence, cast
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


PACKAGE = "ru.altparking.driver"
BASE = "https://public-api.rustore.ru"


class RustoreApiError(RuntimeError):
    """A sanitized boundary error; response text must never be included."""


class RustoreMutationUnresolved(RustoreApiError):
    """A POST may have taken effect; reconcile before any further mutation."""

    def __init__(self, operation: str, version_id: int | None = None) -> None:
        self.operation = operation if operation in {"create", "upload", "commit", "publish"} else "mutation"
        self.version_id = version_id if type(version_id) is int and version_id > 0 else None
        super().__init__(f"RuStore {self.operation}: unresolved outcome; reconcile server state")


@dataclass(frozen=True)
class RustoreVersion:
    version_id: int
    package_name: str
    version_name: str
    version_code: int
    status: str
    publish_type: str
    partial_value: int


class RequestTransport(Protocol):
    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]: ...


class UploadTransport(Protocol):
    def __call__(self, url: str, token: str, apk_path: Path) -> tuple[int, bytes]: ...


class SignatureProvider(Protocol):
    def __call__(self, message: bytes, der_key: bytes) -> bytes: ...


class Clock(Protocol):
    def __call__(self) -> datetime: ...


@dataclass(frozen=True)
class _Credentials:
    key_id: str = field(repr=False)
    der_key: bytes = field(repr=False)


@dataclass(frozen=True)
class _Token:
    value: str = field(repr=False)
    acquired_at: datetime
    lifetime: int


class _NoRedirect(HTTPRedirectHandler):
    # A redirect must not forward a token or implicitly repeat a POST.
    def redirect_request(self, req: Request, fp: object, code: int, msg: str,
                         headers: object, newurl: str) -> None:
        return None


def http_request(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with build_opener(_NoRedirect()).open(request, timeout=120) as response:
            return response.status, response.read()
    except HTTPError as error:
        with error:
            return error.code, error.read()


def curl_upload(url: str, token: str, apk_path: Path) -> tuple[int, bytes]:
    """Use RuStore's documented curl multipart form without redirects or retries."""
    try:
        result = subprocess.run(
            [
                "curl", "--silent", "--show-error", "--request", "POST",
                "--proto", "=https", "--max-redirs", "0",
                "--connect-timeout", "30", "--max-time", "600",
                "--url", url,
                "--header", f"Public-Token: {token}",
                "--form", f"file=@{apk_path}",
                "--write-out", "\n%{http_code}",
            ],
            input=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=630,
        )
        if result.returncode != 0:
            raise OSError
        raw, separator, status = result.stdout.rpartition(b"\n")
        if separator != b"\n" or re.fullmatch(rb"[1-5][0-9]{2}", status) is None:
            raise OSError
        return int(status), raw
    except Exception:
        raise RustoreApiError("RuStore upload: transport failed") from None


def openssl_sign(message: bytes, der_key: bytes) -> bytes:
    """Sign SHA512withRSA/PKCS#1 v1.5; never expose key or subprocess output."""
    key_path: str | None = None
    try:
        descriptor, key_path = tempfile.mkstemp(prefix="rustore-", suffix=".der")
        with os.fdopen(descriptor, "wb") as stream:
            os.chmod(key_path, 0o600)
            stream.write(der_key)
        signed = subprocess.run(
            ["openssl", "dgst", "-sha512", "-keyform", "DER", "-sign", key_path,
             "-sigopt", "rsa_padding_mode:pkcs1"],
            input=message, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=True, timeout=30,
        )
        if not signed.stdout:
            raise RustoreApiError("RuStore auth: signing failed")
        return signed.stdout
    except Exception:
        raise RustoreApiError("RuStore auth: signing failed") from None
    finally:
        if key_path is not None:
            try:
                os.unlink(key_path)
            except OSError:
                raise RustoreApiError("RuStore auth: temporary key cleanup failed") from None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _integer(value: object, minimum: int = 1) -> int:
    if type(value) is not int or cast(int, value) < minimum:
        raise RustoreApiError("RuStore: invalid integer field")
    return cast(int, value)


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise RustoreApiError("RuStore: invalid text field")
    return value


def _enum_text(value: object) -> str:
    text = _text(value)
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", text) is None:
        raise RustoreApiError("RuStore: invalid status field")
    return text


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RustoreApiError("RuStore: invalid object")
    return cast(dict[str, object], value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RustoreApiError("RuStore: duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise RustoreApiError("RuStore: invalid JSON number")


def _envelope(raw: bytes) -> dict[str, object]:
    try:
        envelope = _mapping(json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant))
        _text(envelope.get("code"))
        return envelope
    except Exception:
        raise RustoreApiError("RuStore: invalid or unsuccessful response") from None


def _version(value: object, package_name: str) -> RustoreVersion:
    item = _mapping(value)
    if item.get("packageName", package_name) != package_name:
        raise RustoreApiError("RuStore: contradictory package identity")
    status = _enum_text(item.get("versionStatus"))
    if item.get("status", status) != status:
        raise RustoreApiError("RuStore: contradictory status")
    partial_value = _integer(item.get("partialValue"), 0)
    if partial_value > 100:
        raise RustoreApiError("RuStore: invalid rollout percentage")
    return RustoreVersion(
        version_id=_integer(item.get("versionId")), package_name=package_name,
        version_name=_text(item.get("versionName")), version_code=_integer(item.get("versionCode")),
        status=status, publish_type=_enum_text(item.get("publishType")), partial_value=partial_value,
    )


@dataclass(frozen=True)
class _Page:
    items: tuple[RustoreVersion, ...]
    number: int
    size: int
    total: int
    pages: int


def _page(value: object, package_name: str) -> _Page:
    body = _mapping(value)
    content = body.get("content")
    if not isinstance(content, list):
        raise RustoreApiError("RuStore: invalid page content")
    page = _Page(
        items=tuple(_version(item, package_name) for item in content),
        number=_integer(body.get("pageNumber"), 0), size=_integer(body.get("pageSize")),
        total=_integer(body.get("totalElements"), 0), pages=_integer(body.get("totalPages"), 0),
    )
    if page.total == 0:
        valid = page.number == 0 and page.pages in (0, 1) and not page.items
    else:
        valid = (page.pages == (page.total + page.size - 1) // page.size
                 and page.number < page.pages
                 and len(page.items) == min(page.size, page.total - page.number * page.size))
    if not valid:
        raise RustoreApiError("RuStore: contradictory pagination")
    return page


class RustoreApiClient:
    def __init__(self, *, key_id: str, private_key_pkcs8_base64: str,
                 request: RequestTransport = http_request, sign: SignatureProvider = openssl_sign,
                 now: Clock = _utc_now, upload: UploadTransport = curl_upload) -> None:
        try:
            key_id = _text(key_id)
            der_key = base64.b64decode(private_key_pkcs8_base64, validate=True)
            if not der_key:
                raise ValueError
        except Exception:
            raise RustoreApiError("RuStore auth: invalid credentials") from None
        self._credentials = _Credentials(key_id, der_key)
        self._request = request
        self._upload = upload
        self._sign = sign
        self._now = now
        self._token: _Token | None = None
        self._auth_lock = Lock()

    def _time(self) -> datetime:
        try:
            value = self._now()
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError
            return value.astimezone(timezone.utc)
        except Exception:
            raise RustoreApiError("RuStore auth: invalid clock") from None

    def _exchange(self, method: str, url: str, headers: dict[str, str], body: bytes | None,
                  *, operation: str, mutating: bool = False, version_id: int | None = None,
                  acknowledgement: bool = False, request: RequestTransport | None = None) -> object:
        try:
            status, raw = (request or self._request)(method, url, headers, body)
        except Exception:
            if mutating:
                raise RustoreMutationUnresolved(operation, version_id) from None
            raise RustoreApiError(f"RuStore {operation}: transport failed") from None
        # Malformed status/JSON is ambiguous; a definitive rejection is not.
        try:
            if type(status) is not int or not 100 <= status <= 599:
                raise RustoreApiError("RuStore: invalid HTTP status")
        except Exception:
            if mutating:
                raise RustoreMutationUnresolved(operation, version_id) from None
            raise RustoreApiError(f"RuStore {operation}: invalid or unsuccessful response") from None
        if not 200 <= status < 300:
            raise RustoreApiError(f"RuStore {operation}: HTTP failure")
        try:
            envelope = _envelope(raw)
        except Exception:
            if mutating:
                raise RustoreMutationUnresolved(operation, version_id) from None
            raise RustoreApiError(f"RuStore {operation}: invalid or unsuccessful response") from None
        if envelope["code"] != "OK":
            raise RustoreApiError(f"RuStore {operation}: unsuccessful response")
        result = envelope.get("body")
        if (acknowledgement and result is not None) or (not acknowledgement and result is None):
            if mutating:
                raise RustoreMutationUnresolved(operation, version_id)
            raise RustoreApiError(f"RuStore {operation}: invalid response body")
        return result

    def _authenticate(self) -> str:
        with self._auth_lock:
            current = self._time()
            if self._token is not None:
                age = (current - self._token.acquired_at).total_seconds()
                if 0 <= age < self._token.lifetime:
                    return self._token.value
            self._token = None
            timestamp = current.isoformat(timespec="milliseconds")
            try:
                signature = self._sign((self._credentials.key_id + timestamp).encode("utf-8"), self._credentials.der_key)
                if not isinstance(signature, bytes) or not signature:
                    raise ValueError
                body = json.dumps({"keyId": self._credentials.key_id, "timestamp": timestamp,
                                   "signature": base64.b64encode(signature).decode("ascii")}).encode("utf-8")
            except Exception:
                raise RustoreApiError("RuStore auth: signing failed") from None
            result = _mapping(self._exchange("POST", BASE + "/public/auth/", {"Content-Type": "application/json"}, body, operation="auth"))
            value = _text(result.get("jwe"))
            # Tokens are opaque ASCII header values, never alternate token fields.
            if not value.isascii() or any(char.isspace() for char in value):
                raise RustoreApiError("RuStore auth: invalid token")
            ttl = _integer(result.get("ttl"))
            self._token = _Token(value, current, min(840, max(0, ttl - 60)))
            return value

    def _path(self, package_name: str, version_id: int | None = None) -> str:
        if package_name != PACKAGE:
            raise RustoreApiError("RuStore: invalid package")
        path = f"{BASE}/public/v1/application/{PACKAGE}/version"
        if version_id is not None:
            path += f"/{_integer(version_id)}"
        return path

    def _get(self, url: str) -> object:
        return self._exchange("GET", url, {"Public-Token": self._authenticate()}, None, operation="query")

    def _post(self, url: str, *, operation: str, version_id: int | None = None,
              body: bytes | None = None, content_type: str = "application/json",
              acknowledgement: bool = False) -> object:
        return self._exchange("POST", url, {"Public-Token": self._authenticate(), "Content-Type": content_type},
                              body, operation=operation, mutating=True, version_id=version_id,
                              acknowledgement=acknowledgement)

    def list_versions(self, package_name: str, *, statuses: Sequence[str] = ()) -> tuple[RustoreVersion, ...]:
        path = self._path(package_name)
        if isinstance(statuses, (str, bytes)):
            raise RustoreApiError("RuStore: invalid status filter")
        filters = tuple(_enum_text(status) for status in statuses)
        result: list[RustoreVersion] = []
        seen: set[int] = set()
        expected: tuple[int, int, int] | None = None
        number = 0
        while True:
            query: dict[str, str | int] = {"page": number, "size": expected[0] if expected else 100}
            if filters:
                query["versionStatuses"] = ",".join(filters)
            page = _page(self._get(path + "?" + urlencode(query)), package_name)
            metadata = (page.size, page.total, page.pages)
            if page.number != number or (expected is not None and metadata != expected):
                raise RustoreApiError("RuStore: inconsistent pagination")
            expected = metadata
            for item in page.items:
                if item.version_id in seen or (filters and item.status not in filters):
                    raise RustoreApiError("RuStore: duplicate identity or contradictory status")
                seen.add(item.version_id)
                result.append(item)
            number += 1
            if number >= page.pages:
                if len(result) != page.total:
                    raise RustoreApiError("RuStore: incomplete pagination")
                return tuple(result)

    def get_version(self, package_name: str, version_id: int) -> RustoreVersion:
        path = self._path(package_name)
        identity = _integer(version_id)
        page = _page(self._get(path + "?" + urlencode({"ids": identity})), package_name)
        if page.number != 0 or page.pages != 1 or page.total != 1 or len(page.items) != 1 or page.items[0].version_id != identity:
            raise RustoreApiError("RuStore: exact version identity not found")
        return page.items[0]

    def create_manual_draft(self, package_name: str) -> int:
        path = self._path(package_name)
        result = self._post(path, operation="create", body=b'{"publishType":"MANUAL","partialValue":100}')
        try:
            return _integer(result)
        except RustoreApiError:
            raise RustoreMutationUnresolved("create") from None

    def upload_main_apk(self, package_name: str, version_id: int, apk_path: Path) -> None:
        _integer(version_id)
        path = self._path(package_name, version_id)
        try:
            if apk_path.suffix.lower() != ".apk" or not apk_path.is_file() or apk_path.stat().st_size <= 0:
                raise ValueError
        except Exception:
            raise RustoreApiError("RuStore upload: APK unreadable or invalid") from None
        url = path + "/apk?isMainApk=true&servicesType=Unknown"
        token = self._authenticate()

        def upload(method: str, requested_url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
            if method != "POST" or requested_url != url or body is not None or headers != {"Public-Token": token}:
                raise RustoreApiError("RuStore upload: invalid request")
            return self._upload(requested_url, token, apk_path)

        self._exchange("POST", url, {"Public-Token": token}, None, operation="upload", mutating=True,
                       version_id=version_id, acknowledgement=True, request=upload)

    def commit_for_moderation(self, package_name: str, version_id: int) -> None:
        _integer(version_id)
        path = self._path(package_name, version_id)
        self._post(path + "/commit?priorityUpdate=0", operation="commit", version_id=version_id, acknowledgement=True)

    def publish_manual(self, package_name: str, version_id: int) -> None:
        _integer(version_id)
        path = self._path(package_name, version_id)
        self._post(path + "/publish", operation="publish", version_id=version_id, acknowledgement=True)
