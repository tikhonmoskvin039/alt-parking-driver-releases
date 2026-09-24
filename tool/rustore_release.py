"""Driver-only RuStore release gates. No destructive operations or POST retries.

Run with ``python -m tool.rustore_release``. The controller must independently
verify APK package/version/signature and supply the resulting trusted manifest.
The version API does not expose an APK digest or signing certificate.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Protocol, Sequence, cast

from tool.rustore_api import (
    Clock, PACKAGE, RustoreApiClient, RustoreApiError,
    RustoreMutationUnresolved, RustoreVersion,
)


SIGNER_SHA256 = "E0BEBA119BAA0F69D988495744D3BE2F531AC729656B1B4A05560B2EEB0CE414"
PENDING = frozenset({"TAKEN_FOR_MODERATION", "MODERATION", "AUTO_CHECK"})
SUBMITTED = PENDING | {"READY_FOR_PUBLICATION"}
HISTORICAL = frozenset({"PREVIOUS_ACTIVE", "ARCHIVED", "DELETED_DRAFT"})
REJECTED = frozenset({"REJECTED_BY_MODERATOR", "REJECTED_BY_SECURITY", "AUTO_CHECK_FAILED"})
KNOWN_STATUSES = SUBMITTED | HISTORICAL | REJECTED | {"DRAFT", "ACTIVE", "PARTIAL_ACTIVE"}
MANIFEST_FIELDS = {
    "application": "application", "packageName": "package_name",
    "versionName": "version_name", "versionCode": "version_code",
    "sourceCommit": "source_commit", "sourceTag": "source_tag",
    "apkSha256": "apk_sha256", "signingCertificateSha256": "signing_certificate_sha256",
}
RECEIPT_FIELDS = {
    **MANIFEST_FIELDS, "rustoreVersionId": "rustore_version_id",
    "publishType": "publish_type", "partialValue": "partial_value",
    "status": "status", "observedAt": "observed_at",
}


class RustoreReleaseError(RuntimeError):
    """A safe, nonsecret operator-facing release failure."""


class ReleaseApi(Protocol):
    def list_versions(self, package_name: str, *, statuses: Sequence[str] = ()) -> tuple[RustoreVersion, ...]: ...
    def get_version(self, package_name: str, version_id: int) -> RustoreVersion: ...
    def create_manual_draft(self, package_name: str) -> int: ...
    def upload_main_apk(self, package_name: str, version_id: int, apk_path: Path) -> None: ...
    def commit_for_moderation(self, package_name: str, version_id: int) -> None: ...
    def publish_manual(self, package_name: str, version_id: int) -> None: ...


class StageObserver(Protocol):
    def __call__(self, stage: str, version_id: int | None) -> None: ...


class _Journal:
    """Persist mutation intent before a POST, retaining even interrupted writes.

    Existing journals require operator reconciliation, never automatic cleanup.
    The controller must retain this file across retries of the same release.
    """

    def __init__(self, path: Path, manifest: ReleaseManifest) -> None:
        self.path = path
        self.manifest = manifest
        self.started = False

    def __call__(self, stage: str, version_id: int | None) -> None:
        fields = {key: getattr(self.manifest, name) for key, name in MANIFEST_FIELDS.items()}
        fields.update(stage=stage, rustoreVersionId=version_id)
        data = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if not self.started:
            with self.path.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            _sync_directory(self.path.parent)
            self.started = True
        else:
            _atomic_write(self.path, data)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RustoreReleaseError(message)


def _positive_integer(value: object) -> bool:
    return type(value) is int and cast(int, value) > 0


def _matches(pattern: str, value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value, flags=re.ASCII) is not None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(now: Clock) -> str:
    value = now()
    _require(isinstance(value, datetime) and value.utcoffset() is not None, "Invalid release clock")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class ReleaseManifest:
    application: str
    package_name: str
    version_name: str
    version_code: int
    source_commit: str
    source_tag: str
    apk_sha256: str
    signing_certificate_sha256: str

    def validate(self) -> None:
        _require(self.application == "driver" and self.package_name == PACKAGE, "Invalid Driver release identity")
        _require(_matches(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", self.version_name)
                 and self.source_tag == "v" + self.version_name, "Release tag and version disagree")
        _require(_positive_integer(self.version_code), "Invalid release version code")
        _require(_matches(r"[0-9a-f]{40}", self.source_commit), "Invalid source commit")
        _require(_matches(r"[0-9a-f]{64}", self.apk_sha256), "Invalid APK checksum")
        _require(self.signing_certificate_sha256 == SIGNER_SHA256, "Unexpected Driver signing certificate")

    @classmethod
    def from_path(cls, path: Path) -> ReleaseManifest:
        fields = _read_json(path.read_bytes())
        _require(set(fields) == set(MANIFEST_FIELDS), "Invalid release manifest fields")
        result = cls(**{name: fields[key] for key, name in MANIFEST_FIELDS.items()})
        result.validate()
        return result


@dataclass(frozen=True)
class RustoreReceipt(ReleaseManifest):
    rustore_version_id: int
    publish_type: str
    partial_value: int
    status: str
    observed_at: str

    def validate(self) -> None:
        super().validate()
        _require(_positive_integer(self.rustore_version_id), "Invalid receipt version ID")
        _require(self.publish_type == "MANUAL" and type(self.partial_value) is int and self.partial_value == 100,
                 "Receipt must require MANUAL publication at 100 percent")
        _require(isinstance(self.status, str) and self.status in SUBMITTED | {"ACTIVE"}, "Receipt status requires operator attention")
        _require(_matches(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", self.observed_at), "Invalid receipt UTC timestamp")
        try:
            datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except ValueError:
            raise RustoreReleaseError("Invalid receipt UTC timestamp") from None

    def to_bytes(self) -> bytes:
        self.validate()
        return json.dumps({key: getattr(self, name) for key, name in RECEIPT_FIELDS.items()},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")

    def write(self, path: Path) -> str:
        """Persist exact canonical bytes atomically; return their SHA-256."""
        data = self.to_bytes()
        _atomic_write(path, data)
        return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".rustore-", dir=path.parent)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        _sync_directory(path.parent)
    finally:
        if temporary is not None:
            os.unlink(temporary)


def _sync_directory(directory: Path) -> None:
    """Persist created/replaced entries on POSIX; Windows has no directory fsync."""
    if os.name != "posix":
        return
    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise RustoreReleaseError("Release directory sync failed; operator attention required") from None


def _read_json(data: bytes) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            _require(key not in result, "Duplicate release JSON field")
            result[key] = value
        return result

    def constant(value: str) -> object:
        raise RustoreReleaseError("Invalid release JSON constant")

    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        raise RustoreReleaseError("Invalid release JSON") from None
    _require(isinstance(result, dict), "Invalid release JSON object")
    return cast(dict[str, object], result)


def load_receipt(path: Path, checksum: str, manifest: ReleaseManifest) -> RustoreReceipt:
    manifest.validate()
    _require(_matches(r"[0-9a-f]{64}", checksum), "Invalid receipt checksum")
    data = path.read_bytes()
    _require(hmac.compare_digest(hashlib.sha256(data).hexdigest(), checksum), "Receipt checksum mismatch")
    fields = _read_json(data)
    _require(set(fields) == set(RECEIPT_FIELDS), "Invalid receipt fields")
    result = RustoreReceipt(**{name: fields[key] for key, name in RECEIPT_FIELDS.items()})
    result.validate()
    _require(result.to_bytes() == data, "Receipt is not canonical JSON")
    _require(all(getattr(result, name) == getattr(manifest, name) for name in MANIFEST_FIELDS.values()),
             "Receipt does not match release manifest")
    return result


def verify_apk(manifest: ReleaseManifest, apk_path: Path) -> None:
    manifest.validate()
    _require(apk_path.suffix.lower() == ".apk", "Expected an APK artifact")
    with apk_path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    _require(hmac.compare_digest(digest, manifest.apk_sha256), "APK checksum mismatch")


def _same_release(version: RustoreVersion, manifest: ReleaseManifest) -> bool:
    return (version.package_name == manifest.package_name and version.version_name == manifest.version_name
            and type(version.version_code) is int and version.version_code == manifest.version_code)


def _check_version(version: RustoreVersion, manifest: ReleaseManifest, version_id: int, *, metadata: bool = True) -> None:
    _require(_positive_integer(version.version_id) and version.version_id == version_id
             and version.package_name == PACKAGE, "RuStore exact version identity mismatch")
    _require(version.publish_type == "MANUAL" and type(version.partial_value) is int and version.partial_value == 100,
             f"RuStore version {version_id}: expected MANUAL publication at 100 percent")
    _require(version.status in KNOWN_STATUSES, f"RuStore version {version_id}: unknown status; operator attention required")
    if metadata:
        _require(_same_release(version, manifest), f"RuStore version {version_id}: release metadata mismatch")


def _receipt(manifest: ReleaseManifest, version: RustoreVersion, now: Clock) -> RustoreReceipt:
    return RustoreReceipt(**{name: getattr(manifest, name) for name in MANIFEST_FIELDS.values()},
                          rustore_version_id=version.version_id, publish_type=version.publish_type,
                          partial_value=version.partial_value, status=version.status, observed_at=_timestamp(now))


def _candidate(versions: tuple[RustoreVersion, ...], manifest: ReleaseManifest) -> RustoreVersion | None:
    seen: set[int] = set()
    current: list[RustoreVersion] = []
    for version in versions:
        _require(_positive_integer(version.version_id) and version.version_id not in seen
                 and version.package_name == PACKAGE, "RuStore listing identity conflict")
        seen.add(version.version_id)
        _require(version.status in KNOWN_STATUSES, "RuStore listing has unknown status; operator attention required")
        if version.status in HISTORICAL or version.status == "ACTIVE":
            _require(not _same_release(version, manifest), "Release already live or historical; operator attention required")
            continue
        _require(version.status not in REJECTED | {"PARTIAL_ACTIVE"}, "RuStore listing requires operator attention")
        current.append(version)
    _require(len(current) <= 1, "Multiple RuStore drafts or submissions; operator attention required")
    if not current:
        return None
    selected = current[0]
    _check_version(selected, manifest, selected.version_id)
    return selected


def _poll_submission(client: ReleaseApi, manifest: ReleaseManifest, version_id: int, now: Clock, poll_limit: int) -> RustoreReceipt:
    for _ in range(poll_limit):
        version = client.get_version(PACKAGE, version_id)
        _check_version(version, manifest, version_id)
        _require(version.status in SUBMITTED | {"DRAFT"}, f"RuStore version {version_id}: submission requires operator attention")
        if version.status == "READY_FOR_PUBLICATION":
            return _receipt(manifest, version, now)
    _require(version.status in PENDING, f"RuStore version {version_id}: submission unresolved; inspect before retrying")
    return _receipt(manifest, version, now)


def _validate_poll_limit(poll_limit: int) -> None:
    _require(type(poll_limit) is int and 1 <= poll_limit <= 10, "Poll limit must be between 1 and 10")


def _validate_publication(saved: RustoreReceipt, confirmation: str) -> None:
    _require(saved.status in SUBMITTED, "Receipt is not a pending manual submission")
    _require(confirmation == f"PUBLISH {PACKAGE} {saved.rustore_version_id}", "Exact publication confirmation required")


def submit_release(client: ReleaseApi, manifest: ReleaseManifest, apk_path: Path, *,
                   now: Clock = _utc_now, poll_limit: int = 1,
                   on_stage: StageObserver | None = None) -> RustoreReceipt:
    verify_apk(manifest, apk_path)
    _validate_poll_limit(poll_limit)
    _timestamp(now)
    # Unfiltered, exhaustive pagination is performed by the reviewed API client.
    versions = client.list_versions(PACKAGE)
    _require(any(v.package_name == PACKAGE and v.status == "ACTIVE" for v in versions),
             "An ACTIVE Driver version is required before API delivery")
    selected = _candidate(versions, manifest)
    _require(selected is None,
             "Existing draft or submission has no verified artifact provenance; operator attention required")
    if on_stage is not None:
        on_stage("create_requested", None)
    try:
        version_id = client.create_manual_draft(PACKAGE)
    except (RustoreMutationUnresolved, TimeoutError):
        # A matching list delta can belong to another operator, not this request.
        raise RustoreReleaseError("Draft creation unresolved; operator reconciliation required") from None
    _require(_positive_integer(version_id), "Draft creation returned invalid ID")
    _require(all(version.version_id != version_id for version in versions), "Draft creation reused an existing ID")
    if on_stage is not None:
        on_stage("version_selected", version_id)
    draft = client.get_version(PACKAGE, version_id)
    # A newly created draft can inherit the previous version's metadata until upload.
    _check_version(draft, manifest, version_id, metadata=draft.status != "DRAFT")
    # No receipt can bind this manifest to a binary we have not uploaded here.
    _require(draft.status == "DRAFT", f"RuStore version {version_id}: not an editable draft")
    if on_stage is not None:
        on_stage("upload_requested", version_id)
    try:
        client.upload_main_apk(PACKAGE, version_id, apk_path)
    except (RustoreMutationUnresolved, TimeoutError):
        # Matching version metadata cannot prove which binary the server received.
        observed = client.get_version(PACKAGE, version_id)
        _check_version(observed, manifest, version_id, metadata=False)
        raise RustoreReleaseError(f"RuStore version {version_id}: upload unresolved; operator attention required") from None
    if on_stage is not None:
        on_stage("commit_requested", version_id)
    try:
        client.commit_for_moderation(PACKAGE, version_id)
    except (RustoreMutationUnresolved, TimeoutError):
        pass  # Only read the saved ID below; never repeat the POST.
    return _poll_submission(client, manifest, version_id, now, poll_limit)


def status_release(client: ReleaseApi, manifest: ReleaseManifest, receipt_path: Path, receipt_sha256: str, *,
                   now: Clock = _utc_now) -> RustoreReceipt:
    saved = load_receipt(receipt_path, receipt_sha256, manifest)
    version = client.get_version(PACKAGE, saved.rustore_version_id)
    _check_version(version, manifest, saved.rustore_version_id)
    _require(version.status in SUBMITTED | {"ACTIVE"}, f"RuStore version {saved.rustore_version_id}: operator attention required")
    return _receipt(manifest, version, now)


def publish_release(client: ReleaseApi, manifest: ReleaseManifest, receipt_path: Path, receipt_sha256: str,
                    confirmation: str, *, now: Clock = _utc_now,
                    on_stage: StageObserver | None = None) -> RustoreReceipt:
    saved = load_receipt(receipt_path, receipt_sha256, manifest)
    version_id = saved.rustore_version_id
    _validate_publication(saved, confirmation)
    _timestamp(now)
    ready = client.get_version(PACKAGE, version_id)
    _check_version(ready, manifest, version_id)
    _require(ready.status == "READY_FOR_PUBLICATION", f"RuStore version {version_id}: not READY_FOR_PUBLICATION")
    if on_stage is not None:
        on_stage("publish_requested", version_id)
    try:
        client.publish_manual(PACKAGE, version_id)
    except (RustoreMutationUnresolved, TimeoutError):
        pass  # Reconcile once, read-only, even if the publish response was lost.
    active = client.get_version(PACKAGE, version_id)
    _check_version(active, manifest, version_id)
    _require(active.status == "ACTIVE", f"RuStore version {version_id}: publication not confirmed ACTIVE; operator attention required")
    return _receipt(manifest, active, now)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Driver RuStore release gates")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("submit", "status", "publish"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        if name in {"submit", "publish"}:
            command.add_argument("--apk", type=Path, required=True)
        if name == "submit":
            command.add_argument("--poll-limit", type=int, default=1)
        else:
            command.add_argument("--receipt", type=Path, required=True)
            command.add_argument("--receipt-sha256", required=True)
        if name == "publish":
            command.add_argument("--confirmation", required=True)
    args = parser.parse_args(argv)
    try:
        journal_path = args.output.with_name(args.output.name + ".journal.json")
        _require(not args.output.exists(), "Output receipt already exists; use status with a new output path")
        _require(not journal_path.exists(), "Mutation journal already exists; operator reconciliation required before retrying")
        _require(args.output.parent.is_dir(), "Output directory does not exist")
        manifest = ReleaseManifest.from_path(args.manifest)
        if args.command in {"submit", "publish"}:
            verify_apk(manifest, args.apk)
        if args.command == "submit":
            _validate_poll_limit(args.poll_limit)
        else:
            saved = load_receipt(args.receipt, args.receipt_sha256, manifest)
            if args.command == "publish":
                _validate_publication(saved, args.confirmation)
        prefix = "RUSTORE_PUBLISH" if args.command == "publish" else "RUSTORE_SUBMIT"
        client = RustoreApiClient(key_id=os.environ.get(prefix + "_KEY_ID", ""),
                                 private_key_pkcs8_base64=os.environ.get(prefix + "_PRIVATE_KEY_PKCS8_BASE64", ""))
        if args.command == "submit":
            result = submit_release(client, manifest, args.apk, poll_limit=args.poll_limit,
                                    on_stage=_Journal(journal_path, manifest))
        elif args.command == "status":
            result = status_release(client, manifest, args.receipt, args.receipt_sha256)
        else:
            result = publish_release(client, manifest, args.receipt, args.receipt_sha256, args.confirmation,
                                     on_stage=_Journal(journal_path, manifest))
        checksum = result.write(args.output)
        print(f"RuStore version {result.rustore_version_id}: {result.status}; receipt SHA256 {checksum}")
        return 0
    except RustoreReleaseError as error:
        # These messages are generated here from constants and validated IDs.
        print(str(error), file=sys.stderr)
        return 1
    except (RustoreApiError, OSError, ValueError, TypeError):
        # Do not echo arbitrary API, filesystem or environment exception values.
        print("RuStore release failed; inspect the saved version and validated inputs before retrying", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
