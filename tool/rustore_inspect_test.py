from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import re
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from tool import rustore_inspect
from tool.rustore_api import BASE, RustoreApiClient


VERSION_ID = 2064928626
DETAIL_URL = (
    BASE + "/public/v2/application/"
    f"ru.altparking.driver/version/{VERSION_ID}"
)
WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/rustore-inspect.yml"


class RustoreInspectTest(unittest.TestCase):
    def test_manual_workflow_has_production_gate_and_only_read_permissions(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("environment: production", text)
        self.assertIn("if: ${{ github.ref == 'refs/heads/main' }}", text)
        self.assertIn("contents: read", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("actions: write", text)
        self.assertIn("persist-credentials: false", text)
        self.assertEqual(text.count("secrets.RUSTORE_SUBMIT_KEY_ID"), 1)
        self.assertEqual(text.count("secrets.RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64"), 1)
        self.assertNotIn("secrets.RUSTORE_PUBLISH", text)
        self.assertIn("python -m tool.rustore_inspect --version-id", text)
        self.assertIn("--status-v1", text)
        self.assertEqual(re.findall(r"uses: ([^\s]+)", text), [
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        ])

    def test_exact_read_only_requests_and_sanitized_summary(self) -> None:
        calls: list[tuple[str, str, dict[str, str], bytes | None]] = []
        detail = {
            "code": "OK",
            "body": {
                "versionId": VERSION_ID,
                "versionStatus": "DRAFT",
                "publishType": "MANUAL",
                "versionCode": 29,
                "versionName": "0.1.22",
                "packages": [{
                    "apkUid": "do-not-print-this-uid",
                    "fileName": "do-not-print-this-file-name.apk",
                    "isMainApk": True,
                    "verCode": 29,
                    "verName": "0.1.22",
                    "size": 160000000,
                    "servicesType": "Unknown",
                }],
                "fullDescription": "do-not-print-this-description",
            },
        }

        def request(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
            calls.append((method, url, headers, body))
            if url == BASE + "/public/auth/":
                return 200, b'{"code":"OK","body":{"jwe":"private-token","ttl":900}}'
            if url == DETAIL_URL:
                return 200, json.dumps(detail).encode()
            self.fail("Unexpected network request")

        client = RustoreApiClient(
            key_id="private-key-id",
            private_key_pkcs8_base64=base64.b64encode(b"private-key").decode(),
            request=request,
            sign=lambda message, key: b"signature",
        )
        summary = rustore_inspect.inspect_version(client, VERSION_ID)

        self.assertEqual([(method, url) for method, url, _, _ in calls], [
            ("POST", BASE + "/public/auth/"), ("GET", DETAIL_URL),
        ])
        self.assertEqual(calls[1][2], {"Public-Token": "private-token"})
        self.assertIsNone(calls[1][3])
        self.assertEqual(summary, {
            "versionId": VERSION_ID,
            "status": "DRAFT",
            "publishType": "MANUAL",
            "versionCode": 29,
            "versionName": "0.1.22",
            "packageCount": 1,
            "mainApk": {
                "versionCode": 29,
                "versionName": "0.1.22",
                "sizeBytes": 160000000,
                "servicesType": "Unknown",
            },
        })
        rendered = json.dumps(summary)
        self.assertNotIn("do-not-print", rendered)
        self.assertNotIn("private-token", rendered)

    def test_wrong_id_is_rejected_before_credentials_or_network(self) -> None:
        with patch.object(rustore_inspect, "RustoreApiClient") as client, redirect_stdout(io.StringIO()) as output:
            result = rustore_inspect.main(["--version-id", "2064928627"])
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), "")
        client.assert_not_called()

    def test_v1_status_reads_only_exact_id_and_redacts_response(self) -> None:
        secret = "never-log-private-fields-or-token"
        calls: list[tuple[str, str]] = []
        status_url = f"{BASE}/public/v1/application/ru.altparking.driver/version?ids={VERSION_ID}"

        def request(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
            calls.append((method, url))
            if method == "POST" and url == BASE + "/public/auth/":
                return 200, json.dumps({"code": "OK", "body": {"jwe": secret, "ttl": 900}}).encode()
            self.assertEqual((method, url), ("GET", status_url))
            self.assertEqual(headers, {"Public-Token": secret})
            self.assertIsNone(body)
            return 200, json.dumps({"code": "OK", "body": {
                "content": [{"versionId": VERSION_ID, "versionStatus": "DRAFT",
                             "versionName": None, "versionCode": None, "partialValue": -1,
                             "privateField": secret}],
                "pageNumber": 0, "pageSize": 20, "totalElements": 1, "totalPages": 1,
                "privatePageField": secret,
            }}).encode()

        def client_factory(**kwargs: object) -> RustoreApiClient:
            return RustoreApiClient(**kwargs, sign=lambda message, key: b"signature")

        with patch.object(rustore_inspect, "http_request", side_effect=request), \
                patch.object(rustore_inspect, "RustoreApiClient", side_effect=client_factory), \
                patch.dict(os.environ, {
                    "RUSTORE_SUBMIT_KEY_ID": "private-key-id",
                    "RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64": base64.b64encode(b"private-key").decode(),
                }), redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
            result = rustore_inspect.main(["--version-id", str(VERSION_ID), "--status-v1"])
        self.assertEqual(result, 0)
        self.assertEqual(calls, [("POST", BASE + "/public/auth/"), ("GET", status_url)])
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(json.loads(output.getvalue()), {
            "versionId": VERSION_ID, "versionStatus": "DRAFT", "versionName": None,
            "versionCode": None, "partialValue": -1,
            "page": {"pageNumber": 0, "pageSize": 20, "totalElements": 1, "totalPages": 1},
        })
        self.assertNotIn(secret, output.getvalue())

    def test_v1_status_rejects_other_identity_without_leaking_body(self) -> None:
        with patch.object(rustore_inspect, "RustoreApiClient") as factory, \
                redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
            factory.return_value._get.return_value = {
                "content": [{"versionId": VERSION_ID + 1, "versionStatus": "DRAFT",
                             "versionName": None, "versionCode": None, "partialValue": 100,
                             "private": "never-log-this"}],
                "pageNumber": 0, "pageSize": 20, "totalElements": 1, "totalPages": 1,
            }
            result = rustore_inspect.main(["--version-id", str(VERSION_ID), "--status-v1"])
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "RUSTORE_INSPECT_V1_IDENTITY_MISMATCH\n")
        self.assertNotIn("never-log-this", errors.getvalue())

    def test_v1_status_shape_categories_hide_untrusted_fields(self) -> None:
        row = {"versionId": VERSION_ID, "versionStatus": "DRAFT",
               "versionName": None, "versionCode": None, "partialValue": 100,
               "private": "never-log-this"}
        page = {"content": [row], "pageNumber": 0, "pageSize": 20,
                "totalElements": 1, "totalPages": 1, "private": "never-log-this"}
        cases: list[tuple[object, str]] = [
            ([], "PAGE_OBJECT_INVALID"),
            ({key: value for key, value in page.items() if key != "content"}, "CONTENT_MISSING"),
            ({**page, "content": "never-log-this"}, "CONTENT_NOT_LIST"),
            ({**page, "content": []}, "ROW_COUNT_INVALID"),
            ({**page, "content": ["never-log-this"]}, "ROW_OBJECT_INVALID"),
            ({**page, "pageSize": 0}, "PAGE_METADATA_INVALID"),
            ({**page, "content": [{**row, "versionStatus": "never-log-this"}]}, "VERSION_STATUS_INVALID"),
            ({**page, "content": [{**row, "versionName": "never-log-this\n"}]}, "VERSION_NAME_INVALID"),
            ({**page, "content": [{**row, "versionCode": "never-log-this"}]}, "VERSION_CODE_INVALID"),
            ({**page, "content": [{**row, "partialValue": "never-log-this"}]}, "PARTIAL_VALUE_INVALID"),
        ]
        for response, category in cases:
            with self.subTest(category=category), patch.object(rustore_inspect, "RustoreApiClient") as factory, \
                    redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
                factory.return_value._get.return_value = response
                result = rustore_inspect.main(["--version-id", str(VERSION_ID), "--status-v1"])
                self.assertEqual(result, 1)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(errors.getvalue(), f"RUSTORE_INSPECT_V1_{category}\n")
                self.assertNotIn("never-log-this", errors.getvalue())

    def test_v1_status_http_failure_hides_response_and_token(self) -> None:
        secret = "never-log-http-body-or-token"
        status_url = f"{BASE}/public/v1/application/ru.altparking.driver/version?ids={VERSION_ID}"

        def request(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
            if method == "POST" and url == BASE + "/public/auth/":
                return 200, json.dumps({"code": "OK", "body": {"jwe": secret, "ttl": 900}}).encode()
            self.assertEqual((method, url), ("GET", status_url))
            return 403, json.dumps({"code": "error", "message": secret}).encode()

        def client_factory(**kwargs: object) -> RustoreApiClient:
            return RustoreApiClient(**kwargs, sign=lambda message, key: b"signature")

        with patch.object(rustore_inspect, "http_request", side_effect=request), \
                patch.object(rustore_inspect, "RustoreApiClient", side_effect=client_factory), \
                patch.dict(os.environ, {
                    "RUSTORE_SUBMIT_KEY_ID": "private-key-id",
                    "RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64": base64.b64encode(b"private-key").decode(),
                }), redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
            result = rustore_inspect.main(["--version-id", str(VERSION_ID), "--status-v1"])
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "RUSTORE_INSPECT_STATUS_HTTP_403\n")
        self.assertNotIn(secret, errors.getvalue())

    def test_invalid_response_fails_without_printing_raw_fields(self) -> None:
        response = {"versionId": VERSION_ID + 1, "versionStatus": "DRAFT", "private": "do-not-print"}
        with patch.object(rustore_inspect, "RustoreApiClient") as factory, \
                patch.dict(os.environ, {"RUSTORE_SUBMIT_KEY_ID": "key", "RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64": "private"}), \
                redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
            factory.return_value._get.return_value = response
            result = rustore_inspect.main(["--version-id", str(VERSION_ID)])
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("do-not-print", errors.getvalue())
        self.assertNotIn("private", errors.getvalue())

    def test_detail_http_status_is_reported_without_response_or_token(self) -> None:
        secret = "response-and-token-must-stay-private"

        def request(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
            if method == "POST" and url == BASE + "/public/auth/":
                return 200, json.dumps({"code": "OK", "body": {"jwe": secret, "ttl": 900}}).encode()
            self.assertEqual((method, url), ("GET", DETAIL_URL))
            return 403, json.dumps({"code": "error", "message": secret}).encode()

        def client_factory(**kwargs: object) -> RustoreApiClient:
            return RustoreApiClient(**kwargs, sign=lambda message, key: b"signature")

        with patch.object(rustore_inspect, "http_request", side_effect=request), \
                patch.object(rustore_inspect, "RustoreApiClient", side_effect=client_factory), \
                patch.dict(os.environ, {
                    "RUSTORE_SUBMIT_KEY_ID": "private-key-id",
                    "RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64": base64.b64encode(b"private-key").decode(),
                }), redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
            result = rustore_inspect.main(["--version-id", str(VERSION_ID)])
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "RUSTORE_INSPECT_DETAIL_HTTP_403\n")
        self.assertNotIn(secret, errors.getvalue())


if __name__ == "__main__":
    unittest.main()
