"""Read-only inspection of one RuStore Driver draft after an unresolved upload."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import cast

from tool.rustore_api import BASE, PACKAGE, RustoreApiClient, RustoreApiError, http_request


VERSION_ID = 2064928626
DETAIL_URL = (
    BASE + "/public/v2/application/"
    f"{PACKAGE}/version/{VERSION_ID}"
)


class _ReadOnlyTransport:
    """Allow only the existing auth exchange and one fixed detail GET."""

    def __init__(self) -> None:
        self.detail_http_status: int | None = None

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
        if method == "POST" and url == BASE + "/public/auth/" and set(headers) == {"Content-Type"}:
            return http_request(method, url, headers, body)
        if method == "GET" and url == DETAIL_URL and set(headers) == {"Public-Token"} and body is None:
            status, raw = http_request(method, url, headers, body)
            if type(status) is int and 100 <= status <= 599:
                self.detail_http_status = status
            return status, raw
        raise RustoreApiError("Unexpected RuStore inspection request")


def _error_category(error: RustoreApiError, transport: _ReadOnlyTransport) -> str:
    """Map audited client errors to fixed log markers; never print API text."""
    message = str(error)
    if message.startswith("RuStore auth:"):
        return "RUSTORE_INSPECT_AUTH_FAILURE"
    if message == "RuStore query: HTTP failure" and transport.detail_http_status is not None:
        return f"RUSTORE_INSPECT_DETAIL_HTTP_{transport.detail_http_status}"
    if message == "RuStore query: transport failed":
        return "RUSTORE_INSPECT_DETAIL_TRANSPORT_FAILURE"
    if message == "RuStore query: unsuccessful response":
        return "RUSTORE_INSPECT_DETAIL_API_REJECTED"
    if message in {"RuStore query: invalid or unsuccessful response", "RuStore query: invalid response body"}:
        return "RUSTORE_INSPECT_DETAIL_RESPONSE_INVALID"
    return "RUSTORE_INSPECT_API_FAILURE"


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("Invalid version detail")
    return cast(dict[str, object], value)


def _positive_integer(value: object, *, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if type(value) is not int or value <= 0:
        raise ValueError("Invalid version detail")
    return value


def _safe_text(value: object, pattern: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(pattern, value, re.ASCII) is None:
        raise ValueError("Invalid version detail")
    return value


def inspect_version(client: RustoreApiClient, version_id: int) -> dict[str, object]:
    """GET the official v2 detail endpoint and return only approved fields."""
    if type(version_id) is not int or version_id != VERSION_ID:
        raise ValueError("Unexpected RuStore version ID")
    detail = _mapping(client._get(DETAIL_URL))
    if detail.get("versionId") != version_id or type(detail["versionId"]) is not int:
        raise ValueError("Invalid version identity")
    packages = detail.get("packages")
    if packages is None:
        packages = []
    if not isinstance(packages, list) or len(packages) > 10:
        raise ValueError("Invalid package list")
    package_rows = [_mapping(package) for package in packages]
    main_packages = [package for package in package_rows if package.get("isMainApk") is True]
    if len(main_packages) > 1:
        raise ValueError("Ambiguous main APK")
    main_apk: dict[str, object] | None = None
    if main_packages:
        package = main_packages[0]
        main_apk = {
            "versionCode": _positive_integer(package.get("verCode"), optional=True),
            "versionName": _safe_text(package.get("verName"), r"[A-Za-z0-9._+-]{1,64}", optional=True),
            "sizeBytes": _positive_integer(package.get("size"), optional=True),
            "servicesType": _safe_text(package.get("servicesType"), r"[A-Za-z][A-Za-z0-9_-]{0,23}", optional=True),
        }
    return {
        "versionId": version_id,
        "status": _safe_text(detail.get("versionStatus"), r"[A-Z][A-Z0-9_]{0,40}"),
        "publishType": _safe_text(detail.get("publishType"), r"[A-Z][A-Z0-9_]{0,40}"),
        "versionCode": _positive_integer(detail.get("versionCode"), optional=True),
        "versionName": _safe_text(detail.get("versionName"), r"[A-Za-z0-9._+-]{1,64}", optional=True),
        "packageCount": len(package_rows),
        "mainApk": main_apk,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect one RuStore Driver draft without mutating it")
    parser.add_argument("--version-id", required=True)
    arguments = parser.parse_args(argv)
    if arguments.version_id != str(VERSION_ID):
        print("Unexpected RuStore version ID", file=sys.stderr)
        return 2
    transport = _ReadOnlyTransport()
    try:
        client = RustoreApiClient(
            key_id=os.environ.get("RUSTORE_SUBMIT_KEY_ID", ""),
            private_key_pkcs8_base64=os.environ.get("RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64", ""),
            request=transport,
        )
        summary = inspect_version(client, VERSION_ID)
    except RustoreApiError as error:
        print(_error_category(error, transport), file=sys.stderr)
        return 1
    except Exception:
        print("RuStore inspection failed", file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
