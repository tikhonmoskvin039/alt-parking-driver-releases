from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import subprocess
import traceback
from typing import Callable
import unittest
from unittest.mock import patch

from tool.rustore_api import RustoreApiClient, RustoreApiError, RustoreMutationUnresolved, openssl_sign


PACKAGE = "ru.altparking.driver"
BASE = "https://public-api.rustore.ru"
NOW = datetime(2026, 9, 23, 10, 11, 12, tzinfo=timezone.utc)


def version(version_id: int, status: str = "ACTIVE") -> dict[str, object]:
    return {
        "versionId": version_id,
        "appName": "ALT:PARKING",
        "appType": "MAIN",
        "versionName": "0.1.10",
        "versionCode": 17,
        "versionStatus": status,
        "publishType": "MANUAL",
        "testingType": None,
        "publishDateTime": None,
        "sendDateForModer": None,
        "partialValue": 100,
        "whatsNew": "Исправления",
        "priceValue": 0,
        "paid": False,
    }


def response(body: object, *, code: str = "OK") -> bytes:
    return json.dumps({"code": code, "message": None, "body": body, "timestamp": "2026-09-23T10:11:12.000+00:00"}).encode("utf-8")


def page(items: list[dict[str, object]], *, number: int = 0, total_pages: int = 1, total_elements: int | None = None) -> bytes:
    return response({
        "content": items,
        "pageNumber": number,
        "pageSize": 1,
        "totalElements": len(items) if total_elements is None else total_elements,
        "totalPages": total_pages,
    })


class RecordingTransport:
    def __init__(self, *responses: tuple[int, bytes]) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> tuple[int, bytes]:
        self.requests.append((method, url, headers.copy(), body))
        if not self.responses:
            raise AssertionError(f"Unexpected HTTP {method} {url}")
        return self.responses.pop(0)


def client(
    transport: RecordingTransport,
    signatures: list[tuple[bytes, bytes]],
    *,
    now: Callable[[], datetime] = lambda: NOW,
) -> RustoreApiClient:
    def sign(message: bytes, der_key: bytes) -> bytes:
        signatures.append((message, der_key))
        return b"test-signature"

    def upload(url: str, token: str, apk_path: Path) -> tuple[int, bytes]:
        return transport("POST", url, {"Public-Token": token}, apk_path.read_bytes())

    return RustoreApiClient(
        key_id="driver-submit-key",
        private_key_pkcs8_base64="ZGVyLWtleQ==",
        request=transport,
        sign=sign,
        now=now,
        upload=upload,
    )


AUTH = (200, response({"jwe": "test-jwe", "ttl": 900}))


class RustoreApiContractTest(unittest.TestCase):
    def test_invalid_ids_are_rejected_before_authentication(self) -> None:
        for bad in (0, -1, True, "42", 42.0):
            transport = RecordingTransport()
            with self.subTest(value=bad), self.assertRaises(RustoreApiError):
                client(transport, []).get_version(PACKAGE, bad)
            self.assertEqual(transport.requests, [])

    def test_strict_envelopes_and_version_fields_fail_closed(self) -> None:
        bodies = [b'[]', b'{"code":"OK","code":"OK","body":{}}',
                  b'{"code":"OK","body":NaN}', response({}, code="ERROR")]
        for field, value in (("versionId", True), ("versionCode", "17"),
                             ("versionName", ""), ("versionStatus", ""),
                             ("publishType", None), ("partialValue", True),
                             ("partialValue", 101), ("packageName", "ru.altparking.guard")):
            item = version(31)
            item[field] = value
            bodies.append(page([item]))
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(RustoreApiError):
                client(RecordingTransport(AUTH, (200, body)), []).list_versions(PACKAGE)

    def test_inconsistent_pagination_and_filter_mismatch_are_rejected(self) -> None:
        for body in (page([version(31)], number=1),
                     page([version(31)], total_pages=2, total_elements=1),
                     page([], total_elements=1)):
            with self.subTest(body=body), self.assertRaises(RustoreApiError):
                client(RecordingTransport(AUTH, (200, body)), []).list_versions(PACKAGE)
        with self.assertRaises(RustoreApiError):
            client(RecordingTransport(AUTH, (200, page([version(31)]))), []).list_versions(PACKAGE, statuses=("DRAFT",))

    def test_mutation_timeout_or_unusable_response_is_typed_and_never_retried(self) -> None:
        for outcome in (TimeoutError("test-jwe server-secret"),
                        (200, b"not-json"), (200, response("wrong-id")),
                        (True, response(42)), (99, response(42)), (600, response(42)),
                        ("200", response(42)), (200, b'{"code":null,"body":42}'),
                        (200, b'{"code":"","body":42}')):
            calls: list[str] = []

            def request(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
                calls.append(url)
                if len(calls) == 1:
                    return AUTH
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome

            api = RustoreApiClient(key_id="driver-submit-key", private_key_pkcs8_base64="ZGVyLWtleQ==", request=request, sign=lambda message, key: b"test-signature", now=lambda: NOW)
            with self.subTest(outcome=outcome), self.assertRaises(RustoreMutationUnresolved) as raised:
                api.create_manual_draft(PACKAGE)
            self.assertEqual(len(calls), 2)
            self.assertEqual(raised.exception.operation, "create")
            self.assertIsNone(raised.exception.version_id)
            for secret in ("driver-submit-key", "test-jwe", "test-signature", "server-secret", "der-key"):
                self.assertNotIn(secret, repr(api) + str(raised.exception) + repr(raised.exception))

    def test_auth_rejects_invalid_ttl_or_header_injection(self) -> None:
        for body in ({"jwe": "test-jwe", "ttl": True}, {"jwe": "test-jwe", "ttl": 0},
                     {"jwe": "test-jwe\r\nsecret", "ttl": 900}):
            transport = RecordingTransport((200, response(body)))
            with self.subTest(body=body), self.assertRaises(RustoreApiError):
                client(transport, []).list_versions(PACKAGE)
            self.assertEqual(len(transport.requests), 1)

    def test_openssl_key_is_private_and_removed_even_after_failure(self) -> None:
        for fail in (False, True):
            key_paths: list[Path] = []

            def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                key_path = Path(args[args.index("-sign") + 1])
                key_paths.append(key_path)
                self.assertEqual(key_path.read_bytes(), b"der-key")
                self.assertEqual(kwargs["input"], b"signed-message")
                self.assertIn("-sha512", args)
                self.assertIn("rsa_padding_mode:pkcs1", args)
                self.assertNotIn("der-key", " ".join(args))
                if fail:
                    raise subprocess.CalledProcessError(1, args, stderr=b"der-key")
                return subprocess.CompletedProcess(args, 0, stdout=b"signature", stderr=b"")

            with patch("tool.rustore_api.subprocess.run", side_effect=run), patch("tool.rustore_api.os.chmod") as chmod:
                if fail:
                    with self.assertRaises(RustoreApiError) as raised:
                        openssl_sign(b"signed-message", b"der-key")
                    self.assertNotIn("der-key", str(raised.exception))
                else:
                    self.assertEqual(openssl_sign(b"signed-message", b"der-key"), b"signature")
                self.assertEqual(chmod.call_args.args[1], 0o600)
            self.assertEqual(len(key_paths), 1)
            self.assertFalse(key_paths[0].exists())

    def test_auth_signs_key_and_timestamp_and_sends_jwe_only_as_public_token(self) -> None:
        transport = RecordingTransport(AUTH, (200, page([version(31)])))
        signatures: list[tuple[bytes, bytes]] = []

        result = client(transport, signatures).list_versions(PACKAGE)

        self.assertEqual([item.version_id for item in result], [31])
        self.assertEqual(signatures, [(b"driver-submit-key2026-09-23T10:11:12.000+00:00", b"der-key")])
        auth, listing = transport.requests
        self.assertEqual((auth[0], auth[1]), ("POST", f"{BASE}/public/auth/"))
        self.assertEqual(json.loads(auth[3] or b"{}"), {"keyId": "driver-submit-key", "timestamp": "2026-09-23T10:11:12.000+00:00", "signature": "dGVzdC1zaWduYXR1cmU="})
        self.assertEqual(listing[2]["Public-Token"], "test-jwe")
        self.assertNotIn("Public-Token", auth[2])

    def test_list_versions_collects_every_page_and_rejects_duplicate_ids(self) -> None:
        pages = (
            (200, page([version(31)], number=0, total_pages=2, total_elements=2)),
            (200, page([version(32, "READY_FOR_PUBLICATION")], number=1, total_pages=2, total_elements=2)),
        )
        transport = RecordingTransport(AUTH, *pages)
        result = client(transport, []).list_versions(PACKAGE)
        self.assertEqual([(item.version_id, item.status) for item in result], [(31, "ACTIVE"), (32, "READY_FOR_PUBLICATION")])
        listing_urls = [request[1] for request in transport.requests[1:]]
        self.assertEqual(len(listing_urls), 2)
        self.assertNotEqual(listing_urls[0], listing_urls[1])
        self.assertIn("page=1", listing_urls[1])

        duplicate = RecordingTransport(AUTH, pages[0], (200, page([version(31)], number=1, total_pages=2, total_elements=2)))
        with self.assertRaises(RustoreApiError):
            client(duplicate, []).list_versions(PACKAGE)

    def test_cached_auth_is_reused_and_status_filter_is_sent(self) -> None:
        transport = RecordingTransport(
            AUTH,
            (200, page([version(31)])),
            (200, page([version(32, "READY_FOR_PUBLICATION")])),
        )
        api = client(transport, [])
        self.assertEqual(api.list_versions(PACKAGE)[0].version_id, 31)
        self.assertEqual(api.list_versions(PACKAGE, statuses=("READY_FOR_PUBLICATION",))[0].version_id, 32)
        self.assertEqual(len(transport.requests), 3)
        self.assertIn("versionStatuses=READY_FOR_PUBLICATION", transport.requests[2][1])

    def test_auth_refreshes_at_safe_expiry_before_900_second_ttl(self) -> None:
        current = [NOW]
        transport = RecordingTransport(
            AUTH,
            (200, page([version(31)])),
            (200, page([version(31)])),
            (200, response({"jwe": "refreshed-jwe", "ttl": 900})),
            (200, page([version(31)])),
        )
        signatures: list[tuple[bytes, bytes]] = []
        api = client(transport, signatures, now=lambda: current[0])

        api.list_versions(PACKAGE)
        current[0] = NOW + timedelta(seconds=839)
        api.list_versions(PACKAGE)
        current[0] = NOW + timedelta(seconds=840)
        api.list_versions(PACKAGE)

        self.assertEqual([request[1] for request in transport.requests if request[0] == "POST"], [f"{BASE}/public/auth/", f"{BASE}/public/auth/"])
        self.assertEqual(transport.requests[-1][2]["Public-Token"], "refreshed-jwe")
        self.assertEqual(signatures, [
            (b"driver-submit-key2026-09-23T10:11:12.000+00:00", b"der-key"),
            (b"driver-submit-key2026-09-23T10:25:12.000+00:00", b"der-key"),
        ])

    def test_invalid_package_rejected_before_network(self) -> None:
        transport = RecordingTransport()
        with self.assertRaises(RustoreApiError):
            client(transport, []).create_manual_draft("ru.altparking.guard")
        self.assertEqual(transport.requests, [])

    def test_exact_id_lookup_rejects_wrong_or_missing_identity(self) -> None:
        wrong = version(88)
        transport = RecordingTransport(AUTH, (200, page([wrong])))
        with self.assertRaises(RustoreApiError):
            client(transport, []).get_version(PACKAGE, 31)
        self.assertIn("ids=31", transport.requests[1][1])
        self.assertNotIn("page=", transport.requests[1][1])
        self.assertNotIn("size=", transport.requests[1][1])

        missing_status = version(31)
        del missing_status["versionStatus"]
        malformed = RecordingTransport(AUTH, (200, page([missing_status])))
        with self.assertRaises(RustoreApiError):
            client(malformed, []).get_version(PACKAGE, 31)

    def test_draft_creation_sends_explicit_manual_full_rollout_and_accepts_integer_id_only(self) -> None:
        transport = RecordingTransport(AUTH, (200, response(42)))
        draft_id = client(transport, []).create_manual_draft(PACKAGE)
        self.assertEqual(draft_id, 42)
        method, url, _, body = transport.requests[1]
        self.assertEqual((method, url), ("POST", f"{BASE}/public/v1/application/{PACKAGE}/version"))
        self.assertEqual(json.loads(body or b"{}"), {"publishType": "MANUAL", "partialValue": 100})

        for unsafe in (0, -1, True, "42", {"versionId": 42}, version(42, "DRAFT")):
            with self.subTest(body=unsafe):
                malformed = RecordingTransport(AUTH, (200, response(unsafe)))
                with self.assertRaises(RustoreApiError):
                    client(malformed, []).create_manual_draft(PACKAGE)

    def test_upload_commit_and_manual_publish_use_exact_endpoints(self) -> None:
        transport = RecordingTransport(AUTH, (200, b'{"code":"OK"}'), (200, response(None)), (200, b'{"code":"OK"}'))
        api = client(transport, [])
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"PK\x03\x04fixture-apk")
            api.upload_main_apk(PACKAGE, 42, apk)
        api.commit_for_moderation(PACKAGE, 42)
        api.publish_manual(PACKAGE, 42)
        requests = transport.requests[1:]
        self.assertEqual([item[0] for item in requests], ["POST", "POST", "POST"])
        self.assertEqual(requests[0][1], f"{BASE}/public/v1/application/{PACKAGE}/version/42/apk?isMainApk=true&servicesType=Unknown")
        self.assertEqual(requests[0][2], {"Public-Token": "test-jwe"})
        self.assertEqual(requests[0][3], b"PK\x03\x04fixture-apk")
        self.assertEqual(requests[1][1], f"{BASE}/public/v1/application/{PACKAGE}/version/42/commit?priorityUpdate=0")
        self.assertEqual(requests[2][1], f"{BASE}/public/v1/application/{PACKAGE}/version/42/publish")

    def test_default_upload_uses_documented_curl_form_without_materializing_multipart(self) -> None:
        transport = RecordingTransport(AUTH, (200, b'{"code":"OK"}'))
        executed: list[tuple[list[str], dict[str, object]]] = []

        def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            executed.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, stdout=b'{"code":"OK"}\n200', stderr=b"")

        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver release.apk"
            apk.write_bytes(b"PK\x03\x04fixture-apk")
            api = RustoreApiClient(
                key_id="driver-submit-key", private_key_pkcs8_base64="ZGVyLWtleQ==",
                request=transport, sign=lambda message, key: b"test-signature", now=lambda: NOW,
            )
            with patch("tool.rustore_api.subprocess.run", side_effect=run), \
                    patch("pathlib.Path.read_bytes", side_effect=AssertionError("APK must be streamed by curl")):
                api.upload_main_apk(PACKAGE, 42, apk)

        self.assertEqual(len(executed), 1)
        command, options = executed[0]
        self.assertEqual(command[0], "curl")
        self.assertIn("--form", command)
        self.assertIn(f"file=@{apk}", command)
        self.assertIn(f"{BASE}/public/v1/application/{PACKAGE}/version/42/apk?isMainApk=true&servicesType=Unknown", command)
        self.assertIn("Public-Token: test-jwe", command)
        self.assertNotIn("Content-Type: application/vnd.android.package-archive", command)
        self.assertEqual(options["input"], None)
        self.assertEqual(transport.requests[1:], [])

    def test_acknowledgement_endpoints_accept_only_absent_or_null_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"abc")
            for operation in ("upload", "commit", "publish"):
                for raw in (b'{"code":"OK"}', response(None)):
                    with self.subTest(operation=operation, raw=raw):
                        transport = RecordingTransport(AUTH, (200, raw))
                        api = client(transport, [])
                        self.mutate(api, operation, apk)
                        self.assertEqual(len(transport.requests), 2)
                for raw in (*(response(value) for value in ({}, [], 42, False, "unexpected")),
                            b'{"code":"OK","body":null,"body":null}'):
                    with self.subTest(operation=operation, invalid=raw):
                        transport = RecordingTransport(AUTH, (200, raw))
                        with self.assertRaises(RustoreMutationUnresolved) as raised:
                            self.mutate(client(transport, []), operation, apk)
                        self.assertEqual((raised.exception.operation, raised.exception.version_id), (operation, 42))
                        self.assertEqual(len(transport.requests), 2)

    @staticmethod
    def mutate(api: RustoreApiClient, operation: str, apk: Path) -> None:
        if operation == "create":
            api.create_manual_draft(PACKAGE)
        elif operation == "upload":
            api.upload_main_apk(PACKAGE, 42, apk)
        elif operation == "commit":
            api.commit_for_moderation(PACKAGE, 42)
        else:
            api.publish_manual(PACKAGE, 42)

    def test_definitive_mutation_rejections_are_not_unresolved_or_retried(self) -> None:
        secret = "server-secret test-jwe driver-submit-key der-key"
        outcomes = [(status, secret.encode()) for status in (400, 409, 502, 503)]
        outcomes.append((200, response(secret, code="ERROR")))
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"abc")
            for operation in ("create", "upload", "commit", "publish"):
                for outcome in outcomes:
                    with self.subTest(operation=operation, status=outcome[0]):
                        transport = RecordingTransport(AUTH, outcome)
                        rendered = ""
                        with self.assertRaises(RustoreApiError) as raised:
                            try:
                                self.mutate(client(transport, []), operation, apk)
                            except RustoreApiError:
                                rendered = traceback.format_exc()
                                raise
                        self.assertIs(type(raised.exception), RustoreApiError)
                        self.assertEqual(len(transport.requests), 2)
                        for value in secret.split():
                            self.assertNotIn(value, rendered)

    def test_data_endpoints_reject_absent_and_null_bodies(self) -> None:
        for raw in (b'{"code":"OK"}', response(None)):
            for operation in ("auth", "list", "get", "create"):
                with self.subTest(operation=operation, raw=raw):
                    transport = RecordingTransport(*(() if operation == "auth" else (AUTH,)), (200, raw))
                    api = client(transport, [])
                    expected = RustoreMutationUnresolved if operation == "create" else RustoreApiError
                    with self.assertRaises(expected) as raised:
                        if operation == "get":
                            api.get_version(PACKAGE, 42)
                        elif operation == "create":
                            api.create_manual_draft(PACKAGE)
                        else:
                            api.list_versions(PACKAGE)
                    self.assertIs(type(raised.exception), expected)
                    self.assertEqual(len(transport.requests), 1 if operation == "auth" else 2)

    def test_malformed_response_and_http_error_never_disclose_secrets(self) -> None:
        leaked = b"test-jwe der-key test-signature server-secret"
        transport = RecordingTransport(AUTH, (500, leaked))
        with self.assertRaises(RustoreApiError) as raised:
            client(transport, []).list_versions(PACKAGE)
        for secret in ("test-jwe", "der-key", "test-signature", "server-secret"):
            self.assertNotIn(secret, str(raised.exception))

        malformed = RecordingTransport((200, response({"token": "wrong-place"})))
        with self.assertRaises(RustoreApiError):
            client(malformed, []).list_versions(PACKAGE)


if __name__ == "__main__":
    unittest.main()
