from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tool.rustore_api import RustoreVersion, RustoreMutationUnresolved, RustoreApiError
from tool.rustore_api_test import AUTH, BASE, RecordingTransport, client, page, response, version as api_version
from tool import rustore_release
from tool.rustore_release import (
    ReleaseManifest,
    RustoreReleaseError,
    RustoreReceipt,
    publish_release,
    submit_release,
    load_receipt,
    main,
    status_release,
)


PACKAGE = "ru.altparking.driver"
SOURCE_SHA = "a" * 40
APK_SHA = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
SIGNER_SHA = "E0BEBA119BAA0F69D988495744D3BE2F531AC729656B1B4A05560B2EEB0CE414"
NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


def manifest() -> ReleaseManifest:
    return ReleaseManifest(
        application="driver",
        package_name=PACKAGE,
        version_name="0.1.11",
        version_code=18,
        source_commit=SOURCE_SHA,
        source_tag="v0.1.11",
        apk_sha256=APK_SHA,
        signing_certificate_sha256=SIGNER_SHA,
    )


def version(version_id: int, status: str, version_name: str = "0.1.11", version_code: int = 18) -> RustoreVersion:
    return RustoreVersion(
        version_id=version_id,
        package_name=PACKAGE,
        version_name=version_name,
        version_code=version_code,
        status=status,
        publish_type="MANUAL",
        partial_value=100,
    )


class FakeApi:
    def __init__(
        self,
        listings: list[tuple[RustoreVersion, ...]],
        lookups: list[RustoreVersion] | None = None,
    ) -> None:
        self.listings = list(listings)
        self.lookups = list(lookups or [])
        self.events: list[tuple[object, ...]] = []
        self.create_failure: BaseException | None = None
        self.upload_failure: BaseException | None = None
        self.commit_failure: BaseException | None = None
        self.publish_failure: BaseException | None = None

    def list_versions(self, package_name: str, *, statuses: tuple[str, ...] = ()) -> tuple[RustoreVersion, ...]:
        self.events.append(("list", package_name, statuses))
        if self.listings:
            return self.listings.pop(0)
        return ()

    def get_version(self, package_name: str, version_id: int) -> RustoreVersion:
        self.events.append(("get", package_name, version_id))
        if not self.lookups:
            raise AssertionError("Unexpected exact-version lookup")
        return self.lookups.pop(0)

    def create_manual_draft(self, package_name: str) -> int:
        self.events.append(("create", package_name))
        if self.create_failure is not None:
            raise self.create_failure
        return 42

    def upload_main_apk(self, package_name: str, version_id: int, apk_path: Path) -> None:
        self.events.append(("upload", package_name, version_id, apk_path.name))
        if self.upload_failure is not None:
            raise self.upload_failure

    def commit_for_moderation(self, package_name: str, version_id: int) -> None:
        self.events.append(("commit", package_name, version_id))
        if self.commit_failure is not None:
            raise self.commit_failure

    def publish_manual(self, package_name: str, version_id: int) -> None:
        self.events.append(("publish", package_name, version_id))
        if self.publish_failure is not None:
            raise self.publish_failure


def receipt_bytes(*, status: str = "READY_FOR_PUBLICATION", apk_sha: str = APK_SHA) -> bytes:
    fields: dict[str, object] = {
        "application": "driver",
        "packageName": PACKAGE,
        "versionName": "0.1.11",
        "versionCode": 18,
        "sourceCommit": SOURCE_SHA,
        "sourceTag": "v0.1.11",
        "apkSha256": apk_sha,
        "signingCertificateSha256": SIGNER_SHA,
        "rustoreVersionId": 42,
        "publishType": "MANUAL",
        "partialValue": 100,
        "status": status,
        "observedAt": "2026-09-23T12:00:00Z",
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


class RustoreReleaseContractTest(unittest.TestCase):
    def test_submission_requires_first_active_version_before_creating_draft(self) -> None:
        api = FakeApi([()])
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"abc")
            with self.assertRaises(RustoreReleaseError):
                submit_release(api, manifest(), apk, now=lambda: NOW, poll_limit=1)
        self.assertEqual([event[0] for event in api.events], ["list"])

    def test_submission_creates_uploads_and_commits_without_publishing(self) -> None:
        api = FakeApi(
            [(version(17, "ACTIVE", "0.1.10", 17),)],
            [version(42, "DRAFT", "0.1.10", 17), version(42, "TAKEN_FOR_MODERATION")],
        )
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"abc")
            receipt = submit_release(api, manifest(), apk, now=lambda: NOW, poll_limit=1)
        self.assertEqual(receipt.rustore_version_id, 42)
        self.assertEqual((receipt.publish_type, receipt.partial_value), ("MANUAL", 100))
        self.assertEqual(receipt.status, "TAKEN_FOR_MODERATION")
        self.assertEqual([event[0] for event in api.events], ["list", "create", "get", "upload", "commit", "get"])
        self.assertNotIn("publish", [event[0] for event in api.events])

    def test_existing_unrelated_draft_blocks_mutation(self) -> None:
        api = FakeApi([(version(17, "ACTIVE", "0.1.10", 17), version(99, "DRAFT", "0.1.12", 19))])
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"abc")
            with self.assertRaises(RustoreReleaseError):
                submit_release(api, manifest(), apk, now=lambda: NOW, poll_limit=1)
        self.assertEqual([event[0] for event in api.events], ["list"])

    def test_created_draft_is_checked_for_manual_full_rollout_before_upload(self) -> None:
        unsafe_draft = replace(version(42, "DRAFT", "0.1.10", 17), publish_type="INSTANTLY")
        api = FakeApi([(version(17, "ACTIVE", "0.1.10", 17),)], [unsafe_draft])
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"abc")
            with self.assertRaises(RustoreReleaseError):
                submit_release(api, manifest(), apk, now=lambda: NOW, poll_limit=1)
        self.assertEqual([event[0] for event in api.events], ["list", "create", "get"])

    def test_ambiguous_draft_creation_stops_even_with_one_matching_draft(self) -> None:
        active = version(17, "ACTIVE", "0.1.10", 17)
        api = FakeApi(
            [(active,), (active, version(42, "DRAFT"))],
            [version(42, "DRAFT", "0.1.10", 17), version(42, "TAKEN_FOR_MODERATION")],
        )
        api.create_failure = TimeoutError("response lost")
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"abc")
            with self.assertRaises(RustoreReleaseError):
                submit_release(api, manifest(), apk, now=lambda: NOW, poll_limit=1)
        self.assertEqual([event[0] for event in api.events], ["list", "create"])
        self.assertEqual(len(api.listings), 1)

    def test_ambiguous_commit_queries_saved_version_without_repeating_commit(self) -> None:
        api = FakeApi(
            [(version(17, "ACTIVE", "0.1.10", 17),)],
            [version(42, "DRAFT", "0.1.10", 17), version(42, "TAKEN_FOR_MODERATION")],
        )
        api.commit_failure = TimeoutError("response lost")
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"abc")
            receipt = submit_release(api, manifest(), apk, now=lambda: NOW, poll_limit=1)
        self.assertEqual(receipt.status, "TAKEN_FOR_MODERATION")
        self.assertEqual([event[0] for event in api.events].count("commit"), 1)
        self.assertEqual([event[0] for event in api.events].count("get"), 2)

    def test_ambiguous_upload_does_not_repeat_post_when_server_state_is_inconclusive(self) -> None:
        api = FakeApi(
            [(version(17, "ACTIVE", "0.1.10", 17),)],
            [version(42, "DRAFT", "0.1.10", 17), version(42, "DRAFT", "0.1.10", 17)],
        )
        api.upload_failure = TimeoutError("response lost")
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "driver.apk"
            apk.write_bytes(b"abc")
            with self.assertRaises(RustoreReleaseError):
                submit_release(api, manifest(), apk, now=lambda: NOW, poll_limit=1)
        self.assertEqual([event[0] for event in api.events].count("upload"), 1)
        self.assertNotIn("commit", [event[0] for event in api.events])
        self.assertEqual(api.events[-1], ("get", PACKAGE, 42))

    def test_rejected_or_unknown_status_blocks_receipt_success(self) -> None:
        for status in ("REJECTED_BY_MODERATOR", "SURPRISE_STATUS"):
            with self.subTest(status=status):
                api = FakeApi(
                    [(version(17, "ACTIVE", "0.1.10", 17),)],
                    [version(42, "DRAFT", "0.1.10", 17), version(42, status)],
                )
                with tempfile.TemporaryDirectory() as directory:
                    apk = Path(directory) / "driver.apk"
                    apk.write_bytes(b"abc")
                    with self.assertRaises(RustoreReleaseError):
                        submit_release(api, manifest(), apk, now=lambda: NOW, poll_limit=1)
                self.assertNotIn("publish", [event[0] for event in api.events])

    def test_publication_rejects_wrong_checksum_and_mismatched_manifest_before_api_call(self) -> None:
        api = FakeApi([], [])
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "rustore-submission.json"
            receipt_path.write_bytes(receipt_bytes())
            with self.assertRaises(RustoreReleaseError):
                publish_release(api, manifest(), receipt_path, "0" * 64, f"PUBLISH {PACKAGE} 42")
            altered = manifest()
            altered = ReleaseManifest(
                application=altered.application,
                package_name=altered.package_name,
                version_name=altered.version_name,
                version_code=altered.version_code,
                source_commit=altered.source_commit,
                source_tag=altered.source_tag,
                apk_sha256="c" * 64,
                signing_certificate_sha256=altered.signing_certificate_sha256,
            )
            checksum = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
            with self.assertRaises(RustoreReleaseError):
                publish_release(api, altered, receipt_path, checksum, f"PUBLISH {PACKAGE} 42")
        self.assertEqual(api.events, [])

    def test_publication_requires_exact_confirmation_and_ready_status(self) -> None:
        for status, confirmation in (("TAKEN_FOR_MODERATION", f"PUBLISH {PACKAGE} 42"), ("REJECTED_BY_MODERATOR", f"PUBLISH {PACKAGE} 42"), ("ACTIVE", f"PUBLISH {PACKAGE} 42"), ("UNKNOWN", f"PUBLISH {PACKAGE} 42"), ("READY_FOR_PUBLICATION", "publish anyway")):
            with self.subTest(status=status, confirmation=confirmation):
                api = FakeApi([], [version(42, status)])
                with tempfile.TemporaryDirectory() as directory:
                    receipt_path = Path(directory) / "rustore-submission.json"
                    data = receipt_bytes()
                    receipt_path.write_bytes(data)
                    checksum = hashlib.sha256(data).hexdigest()
                    with self.assertRaises(RustoreReleaseError):
                        publish_release(api, manifest(), receipt_path, checksum, confirmation)
                self.assertNotIn("publish", [event[0] for event in api.events])

    def test_publication_rejects_ready_version_with_wrong_version_code(self) -> None:
        api = FakeApi([], [version(42, "READY_FOR_PUBLICATION", version_code=19)])
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "rustore-submission.json"
            data = receipt_bytes()
            receipt_path.write_bytes(data)
            with self.assertRaises(RustoreReleaseError):
                publish_release(api, manifest(), receipt_path, hashlib.sha256(data).hexdigest(), f"PUBLISH {PACKAGE} 42")
        self.assertEqual(api.events, [("get", PACKAGE, 42)])

    def test_ready_version_publishes_once_and_requires_active_afterward(self) -> None:
        api = FakeApi([], [version(42, "READY_FOR_PUBLICATION"), version(42, "ACTIVE")])
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "rustore-submission.json"
            data = receipt_bytes()
            receipt_path.write_bytes(data)
            checksum = hashlib.sha256(data).hexdigest()
            published = publish_release(api, manifest(), receipt_path, checksum, f"PUBLISH {PACKAGE} 42")
        self.assertEqual(published.status, "ACTIVE")
        self.assertEqual(api.events, [("get", PACKAGE, 42), ("publish", PACKAGE, 42), ("get", PACKAGE, 42)])

    def test_publish_result_other_than_active_fails_without_repeating_post(self) -> None:
        api = FakeApi([], [version(42, "READY_FOR_PUBLICATION"), version(42, "MODERATION")])
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "rustore-submission.json"
            data = receipt_bytes()
            receipt_path.write_bytes(data)
            with self.assertRaises(RustoreReleaseError):
                publish_release(api, manifest(), receipt_path, hashlib.sha256(data).hexdigest(), f"PUBLISH {PACKAGE} 42")
        self.assertEqual([event[0] for event in api.events].count("publish"), 1)


class AdditionalSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.apk = self.directory / "driver.apk"
        self.apk.write_bytes(b"abc")
        self.receipt = self.directory / "rustore-submission.json"
        self.receipt.write_bytes(receipt_bytes())
        self.checksum = hashlib.sha256(receipt_bytes()).hexdigest()
        self.active = version(17, "ACTIVE", "0.1.10", 17)

    def submit(self, api: FakeApi, *, poll_limit: int = 1) -> RustoreReceipt:
        return submit_release(api, manifest(), self.apk, now=lambda: NOW, poll_limit=poll_limit)

    def test_real_client_bodyless_upload_and_commit_produce_bound_receipt(self) -> None:
        submitted = api_version(42, "TAKEN_FOR_MODERATION")
        submitted.update(versionName="0.1.11", versionCode=18)
        transport = RecordingTransport(
            AUTH, (200, page([api_version(17)])), (200, response(42)),
            (200, page([api_version(42, "DRAFT")])),
            (200, b'{"code":"OK"}'), (200, b'{"code":"OK"}'),
            (200, page([submitted])),
        )
        receipt = submit_release(client(transport, []), manifest(), self.apk, now=lambda: NOW)
        self.assertEqual((receipt.rustore_version_id, receipt.status, receipt.apk_sha256),
                         (42, "TAKEN_FOR_MODERATION", APK_SHA))
        self.assertEqual([request[0] for request in transport.requests],
                         ["POST", "GET", "POST", "GET", "POST", "POST", "GET"])
        self.assertEqual(transport.responses, [])

    def test_real_client_failed_create_never_adopts_foreign_matching_draft(self) -> None:
        foreign = api_version(42, "DRAFT")
        foreign.update(versionName="0.1.11", versionCode=18)
        for outcome, expected in (
            (TimeoutError("secret transport data"), RustoreReleaseError),
            ((200, b"malformed response"), RustoreReleaseError),
            ((400, b"secret rejection data"), RustoreApiError),
            ((409, b"secret rejection data"), RustoreApiError),
            ((200, response("secret rejection data", code="ERROR")), RustoreApiError),
        ):
            with self.subTest(outcome=outcome):
                queued = [AUTH, (200, page([api_version(17)])), outcome,
                          (200, page([api_version(17)], total_pages=2, total_elements=2)),
                          (200, page([foreign], number=1, total_pages=2, total_elements=2)),
                          (200, page([foreign]))]
                calls: list[tuple[str, str]] = []

                def request(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
                    calls.append((method, url))
                    result = queued.pop(0)
                    if isinstance(result, Exception):
                        raise result
                    return result

                api = rustore_release.RustoreApiClient(
                    key_id="fixture", private_key_pkcs8_base64="ZGVyLWtleQ==",
                    request=request, sign=lambda message, key: b"signature", now=lambda: NOW)
                output = self.directory / "new-receipt.json"
                stages: list[tuple[str, int | None]] = []
                with self.assertRaises(expected) as raised:
                    submit_release(api, manifest(), self.apk, now=lambda: NOW,
                                   on_stage=lambda stage, identity: stages.append((stage, identity))).write(output)
                self.assertIs(type(raised.exception), expected)
                self.assertEqual(calls, [
                    ("POST", BASE + "/public/auth/"),
                    ("GET", BASE + f"/public/v1/application/{PACKAGE}/version?page=0&size=100"),
                    ("POST", BASE + f"/public/v1/application/{PACKAGE}/version"),
                ])
                self.assertEqual(stages, [("create_requested", None)])
                self.assertEqual(len(queued), 3)
                self.assertFalse(output.exists())

    def test_fresh_real_client_blocks_preexisting_exact_draft_without_local_journal(self) -> None:
        draft = api_version(42, "DRAFT")
        draft.update(versionName="0.1.11", versionCode=18)
        for _ in range(2):
            transport = RecordingTransport(
                AUTH,
                (200, page([api_version(17)], total_pages=2, total_elements=2)),
                (200, page([draft], number=1, total_pages=2, total_elements=2)),
            )
            with self.assertRaises(RustoreReleaseError):
                submit_release(client(transport, []), manifest(), self.apk, now=lambda: NOW)
            self.assertEqual([call[0] for call in transport.requests], ["POST", "GET", "GET"])
            self.assertEqual(list(self.directory.glob("*.journal.json")), [])

    def test_multiple_drafts_and_unknown_or_foreign_inflight_state_stop_before_mutation(self) -> None:
        for extra in ((version(42, "DRAFT"), version(43, "DRAFT")),
                      (version(42, "SURPRISE"),),
                      (version(42, "MODERATION", "0.1.12", 19),),
                      (version(42, "PARTIAL_ACTIVE"),)):
            api = FakeApi([(self.active, *extra)])
            with self.subTest(extra=extra), self.assertRaises(RustoreReleaseError):
                self.submit(api)
            self.assertEqual([event[0] for event in api.events], ["list"])

    def test_preexisting_pending_states_cannot_mint_receipt_without_artifact_provenance(self) -> None:
        for state in ("DRAFT", "AUTO_CHECK", "TAKEN_FOR_MODERATION", "MODERATION", "READY_FOR_PUBLICATION"):
            api = FakeApi([(self.active, version(42, state))], [version(42, state), version(42, "MODERATION")])
            with self.subTest(state=state), self.assertRaises(RustoreReleaseError):
                self.submit(api)
            self.assertEqual(api.events, [("list", PACKAGE, ())])

    def test_remote_version_match_cannot_bind_a_different_local_manifest(self) -> None:
        self.apk.write_bytes(b"different binary")
        changed = replace(manifest(), source_commit="b" * 40,
                          apk_sha256=hashlib.sha256(b"different binary").hexdigest())
        api = FakeApi([(self.active, version(42, "READY_FOR_PUBLICATION"))], [version(42, "READY_FOR_PUBLICATION")])
        with self.assertRaises(RustoreReleaseError):
            submit_release(api, changed, self.apk, now=lambda: NOW)
        self.assertEqual(api.events, [("list", PACKAGE, ())])

    def test_draft_that_advances_before_our_upload_has_no_provenance(self) -> None:
        for existing in (False, True):
            api = FakeApi([(self.active, version(42, "DRAFT")) if existing else (self.active,)],
                          [version(42, "READY_FOR_PUBLICATION")])
            with self.subTest(existing=existing), self.assertRaises(RustoreReleaseError):
                self.submit(api)
            self.assertNotIn("upload", [event[0] for event in api.events])

    def test_lost_create_never_uses_a_listing_delta_to_infer_ownership(self) -> None:
        historical = version(9, "ARCHIVED", "0.1.9", 16)
        for after in ((self.active, version(9, "DRAFT")),
                      (self.active, version(42, "DRAFT")),
                      (replace(self.active, status="PREVIOUS_ACTIVE"), historical, version(42, "DRAFT")),
                      (self.active, historical, version(42, "DRAFT"), version(43, "ARCHIVED", "0.1.8", 15))):
            api = FakeApi([(self.active, historical), after], [version(42, "DRAFT"), version(42, "MODERATION")])
            api.create_failure = RustoreMutationUnresolved("create")
            with self.subTest(after=after), self.assertRaises(RustoreReleaseError):
                self.submit(api)
            self.assertEqual([event[0] for event in api.events], ["list", "create"])
            self.assertEqual(api.listings, [after])

    def test_target_historical_rejected_live_and_unknown_states_never_succeed(self) -> None:
        for state in ("REJECTED_BY_MODERATOR", "REJECTED_BY_SECURITY", "AUTO_CHECK_FAILED",
                      "PREVIOUS_ACTIVE", "ARCHIVED", "DELETED_DRAFT", "PARTIAL_ACTIVE", "ACTIVE", "UNKNOWN"):
            api = FakeApi([(self.active,)], [version(42, "DRAFT", "0.1.10", 17), version(42, state)])
            with self.subTest(state=state), self.assertRaises(RustoreReleaseError):
                self.submit(api)
            self.assertNotIn("publish", [event[0] for event in api.events])

    def test_existing_matching_draft_blocks_before_lookup_or_mutation(self) -> None:
        api = FakeApi([(self.active, version(42, "DRAFT"))], [version(42, "DRAFT"), version(42, "MODERATION")])
        with self.assertRaises(RustoreReleaseError):
            self.submit(api)
        self.assertEqual([event[0] for event in api.events], ["list"])

    def test_typed_create_ambiguity_always_stops_without_reconciliation(self) -> None:
        for drafts in ((), (version(42, "DRAFT"),),
                       (version(42, "DRAFT"), version(43, "DRAFT")),
                       (version(42, "DRAFT", "0.1.12", 19),)):
            api = FakeApi([(self.active,), (self.active, *drafts)],
                          [version(42, "DRAFT"), version(42, "MODERATION")])
            api.create_failure = RustoreMutationUnresolved("create")
            with self.subTest(drafts=drafts):
                with self.assertRaises(RustoreReleaseError):
                    self.submit(api)
                self.assertEqual([event[0] for event in api.events], ["list", "create"])
                self.assertEqual(len(api.listings), 1)

    def test_typed_upload_ambiguity_never_commits_even_when_draft_metadata_matches(self) -> None:
        api = FakeApi([(self.active,)], [version(42, "DRAFT", "0.1.10", 17), version(42, "DRAFT")])
        api.upload_failure = RustoreMutationUnresolved("upload", 42)
        with self.assertRaises(RustoreReleaseError):
            self.submit(api)
        self.assertEqual([event[0] for event in api.events], ["list", "create", "get", "upload", "get"])

    def test_typed_commit_ambiguity_is_read_only_bounded_reconciliation(self) -> None:
        api = FakeApi([(self.active,)], [version(42, "DRAFT", "0.1.10", 17),
                                      version(42, "DRAFT"), version(42, "AUTO_CHECK"), version(42, "MODERATION")])
        api.commit_failure = RustoreMutationUnresolved("commit", 42)
        self.assertEqual(self.submit(api, poll_limit=3).status, "MODERATION")
        self.assertEqual([event[0] for event in api.events].count("commit"), 1)
        self.assertEqual([event[0] for event in api.events].count("get"), 4)

    def test_unresolved_commit_draft_exhausts_bound_without_second_post(self) -> None:
        api = FakeApi([(self.active,)], [version(42, "DRAFT", "0.1.10", 17), version(42, "DRAFT"), version(42, "DRAFT")])
        api.commit_failure = RustoreMutationUnresolved("commit", 42)
        with self.assertRaises(RustoreReleaseError):
            self.submit(api, poll_limit=2)
        self.assertEqual([event[0] for event in api.events].count("commit"), 1)
        self.assertEqual([event[0] for event in api.events].count("get"), 3)

    def test_invalid_artifact_manifest_and_poll_limit_fail_before_remote_calls(self) -> None:
        for invalid in (replace(manifest(), source_tag="v0.1.12"), replace(manifest(), version_code=True),
                        replace(manifest(), package_name="ru.altparking.guard"),
                        replace(manifest(), signing_certificate_sha256="B" * 64),
                        replace(manifest(), source_commit="bad"), replace(manifest(), apk_sha256="c" * 64)):
            api = FakeApi([])
            with self.subTest(invalid=invalid), self.assertRaises(RustoreReleaseError):
                submit_release(api, invalid, self.apk, now=lambda: NOW, poll_limit=1)
            self.assertEqual(api.events, [])
        for limit in (0, -1, True, 1000):
            api = FakeApi([])
            with self.subTest(limit=limit), self.assertRaises(RustoreReleaseError):
                self.submit(api, poll_limit=limit)
            self.assertEqual(api.events, [])

    def test_receipt_bytes_are_canonical_exact_and_checksum_durable(self) -> None:
        api = FakeApi([(self.active,)], [version(42, "DRAFT", "0.1.10", 17), version(42, "READY_FOR_PUBLICATION")])
        result = self.submit(api)
        self.assertEqual(result.to_bytes(), receipt_bytes())
        checksum = result.write(self.receipt)
        self.assertEqual(checksum, self.checksum)
        self.assertEqual(self.receipt.read_bytes(), receipt_bytes())
        self.assertEqual(load_receipt(self.receipt, checksum, manifest()), result)

    def test_strict_receipt_rejects_every_identity_change_and_malformed_json_before_api(self) -> None:
        original = json.loads(receipt_bytes())
        changes = {"application": "guard", "packageName": "ru.altparking.guard", "versionName": "0.1.12",
                   "versionCode": 19, "sourceCommit": "b" * 40, "sourceTag": "v0.1.12",
                   "apkSha256": "c" * 64, "signingCertificateSha256": "B" * 64,
                   "rustoreVersionId": True, "publishType": "INSTANTLY", "partialValue": 99,
                   "status": "DISABLED", "observedAt": "2026-09-23T12:00:00", "secret": "hidden"}
        data_cases = [json.dumps({**original, key: value}, sort_keys=True, separators=(",", ":")).encode()
                      for key, value in changes.items()]
        data_cases.extend((b'[]', receipt_bytes()[:-1] + b',"status":"READY_FOR_PUBLICATION"}',
                           receipt_bytes().replace(b'"versionCode":18', b'"versionCode":NaN'),
                           receipt_bytes() + b'\n', b'\xff'))
        for data in data_cases:
            api = FakeApi([])
            self.receipt.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(RustoreReleaseError):
                publish_release(api, manifest(), self.receipt, hashlib.sha256(data).hexdigest(), f"PUBLISH {PACKAGE} 42")
            self.assertEqual(api.events, [])

    def test_publish_ambiguous_response_reconciles_saved_id_once_and_requires_full_active(self) -> None:
        for failure in (TimeoutError("secret"), RustoreMutationUnresolved("publish", 42)):
            for state in ("ACTIVE", "PARTIAL_ACTIVE", "READY_FOR_PUBLICATION", "REJECTED_BY_SECURITY", "ARCHIVED", "UNKNOWN"):
                api = FakeApi([], [version(42, "READY_FOR_PUBLICATION"), version(42, state)])
                api.publish_failure = failure
                with self.subTest(failure=failure, state=state):
                    if state == "ACTIVE":
                        self.assertEqual(publish_release(api, manifest(), self.receipt, self.checksum, f"PUBLISH {PACKAGE} 42").status, state)
                    else:
                        with self.assertRaises(RustoreReleaseError):
                            publish_release(api, manifest(), self.receipt, self.checksum, f"PUBLISH {PACKAGE} 42")
                    self.assertEqual(api.events, [("get", PACKAGE, 42), ("publish", PACKAGE, 42), ("get", PACKAGE, 42)])

    def test_exact_id_package_and_manual_rollout_checked_on_every_publish_read(self) -> None:
        for bad in (replace(version(42, "READY_FOR_PUBLICATION"), version_id=43),
                    replace(version(42, "READY_FOR_PUBLICATION"), package_name="ru.altparking.guard"),
                    replace(version(42, "READY_FOR_PUBLICATION"), publish_type="INSTANTLY"),
                    replace(version(42, "READY_FOR_PUBLICATION"), partial_value=99)):
            api = FakeApi([], [bad])
            with self.subTest(bad=bad), self.assertRaises(RustoreReleaseError):
                publish_release(api, manifest(), self.receipt, self.checksum, f"PUBLISH {PACKAGE} 42")
            self.assertEqual(api.events, [("get", PACKAGE, 42)])

    def test_status_reads_saved_id_and_emits_current_receipt_without_mutation(self) -> None:
        api = FakeApi([], [version(42, "MODERATION")])
        result = status_release(api, manifest(), self.receipt, self.checksum, now=lambda: NOW)
        self.assertEqual(result.to_bytes(), receipt_bytes(status="MODERATION"))
        self.assertEqual(api.events, [("get", PACKAGE, 42)])

    def test_cli_scopes_credentials_and_checks_apk_before_publication(self) -> None:
        manifest_path = self.directory / "release-manifest.json"
        manifest_path.write_text(json.dumps({key: value for key, value in json.loads(receipt_bytes()).items()
                                           if key not in {"rustoreVersionId", "publishType", "partialValue", "status", "observedAt"}}))
        env = {"RUSTORE_SUBMIT_KEY_ID": "submit-key", "RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64": "submit-private",
               "RUSTORE_PUBLISH_KEY_ID": "publish-key", "RUSTORE_PUBLISH_PRIVATE_KEY_PKCS8_BASE64": "publish-private"}
        for command in ("submit", "status", "publish"):
            args = [command, "--manifest", str(manifest_path), "--output", str(self.directory / f"{command}-result.json")]
            if command in {"submit", "publish"}:
                args += ["--apk", str(self.apk)]
            if command != "submit":
                args += ["--receipt", str(self.receipt), "--receipt-sha256", self.checksum]
            if command == "publish":
                args += ["--confirmation", f"PUBLISH {PACKAGE} 42"]
            api = (FakeApi([(self.active,)], [version(42, "DRAFT", "0.1.10", 17), version(42, "MODERATION")])
                   if command == "submit" else FakeApi([], [version(42, "READY_FOR_PUBLICATION"), version(42, "ACTIVE")]))
            output = io.StringIO()
            with patch.dict(os.environ, env, clear=True), patch("tool.rustore_release.RustoreApiClient", return_value=api) as factory, contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                self.assertEqual(main(args), 0)
            prefix = "PUBLISH" if command == "publish" else "SUBMIT"
            self.assertEqual(factory.call_args.kwargs, {"key_id": env[f"RUSTORE_{prefix}_KEY_ID"],
                                                       "private_key_pkcs8_base64": env[f"RUSTORE_{prefix}_PRIVATE_KEY_PKCS8_BASE64"]})
            for value in env.values():
                self.assertNotIn(value, output.getvalue())
        self.apk.write_bytes(b"wrong")
        args[args.index("--output") + 1] = str(self.directory / "wrong-apk-result.json")
        with patch.dict(os.environ, env, clear=True), patch("tool.rustore_release.RustoreApiClient") as factory, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(args), 1)
            factory.assert_not_called()

    def test_cli_journals_before_upload_and_blocks_restart_after_ambiguous_upload(self) -> None:
        manifest_path = self.directory / "manifest.json"
        manifest_path.write_text(json.dumps({key: value for key, value in json.loads(receipt_bytes()).items()
                                           if key not in {"rustoreVersionId", "publishType", "partialValue", "status", "observedAt"}}))
        output_path = self.directory / "submitted.json"
        args = ["submit", "--manifest", str(manifest_path), "--apk", str(self.apk), "--output", str(output_path)]
        api = FakeApi([(self.active,)], [version(42, "DRAFT", "0.1.10", 17), version(42, "DRAFT")])
        api.upload_failure = RustoreMutationUnresolved("upload", 42)
        original_upload = api.upload_main_apk

        def upload(package: str, identity: int, path: Path) -> None:
            saved = json.loads((self.directory / "submitted.json.journal.json").read_bytes())
            self.assertEqual(saved["stage"], "upload_requested")
            self.assertEqual(saved["rustoreVersionId"], 42)
            self.assertEqual(saved["sourceCommit"], SOURCE_SHA)
            original_upload(package, identity, path)

        api.upload_main_apk = upload
        error = io.StringIO()
        with patch("tool.rustore_release.RustoreApiClient", return_value=api), contextlib.redirect_stderr(error):
            self.assertEqual(main(args), 1)
        self.assertIn("42", error.getvalue())
        self.assertFalse(output_path.exists())
        with patch("tool.rustore_release.RustoreApiClient") as factory, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(args), 1)
            factory.assert_not_called()

    def test_publish_journal_precedes_post_and_no_active_receipt_is_written_for_partial_active(self) -> None:
        manifest_path = self.directory / "manifest.json"
        manifest_path.write_text(json.dumps({key: value for key, value in json.loads(receipt_bytes()).items()
                                           if key not in {"rustoreVersionId", "publishType", "partialValue", "status", "observedAt"}}))
        output_path = self.directory / "published.json"
        args = ["publish", "--manifest", str(manifest_path), "--apk", str(self.apk), "--output", str(output_path),
                "--receipt", str(self.receipt), "--receipt-sha256", self.checksum, "--confirmation", f"PUBLISH {PACKAGE} 42"]
        api = FakeApi([], [version(42, "READY_FOR_PUBLICATION"), version(42, "PARTIAL_ACTIVE")])
        original_publish = api.publish_manual

        def publish(package: str, identity: int) -> None:
            saved = json.loads((self.directory / "published.json.journal.json").read_bytes())
            self.assertEqual((saved["stage"], saved["rustoreVersionId"]), ("publish_requested", 42))
            original_publish(package, identity)

        api.publish_manual = publish
        with patch("tool.rustore_release.RustoreApiClient", return_value=api), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(args), 1)
        self.assertFalse(output_path.exists())
        with patch("tool.rustore_release.RustoreApiClient") as factory, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(args), 1)
            factory.assert_not_called()

    def test_cli_rejects_local_gate_failures_before_credentials_or_client(self) -> None:
        manifest_path = self.directory / "manifest.json"
        manifest_path.write_text(json.dumps({key: value for key, value in json.loads(receipt_bytes()).items()
                                           if key not in {"rustoreVersionId", "publishType", "partialValue", "status", "observedAt"}}))
        cases = [("submit", "READY_FOR_PUBLICATION", "", ["--poll-limit", "0"]),
                 ("publish", "READY_FOR_PUBLICATION", "publish anyway", [])]
        cases.extend(("publish", state, f"PUBLISH {PACKAGE} 42", []) for state in
                     ("ACTIVE", "DRAFT", "PARTIAL_ACTIVE", "REJECTED_BY_MODERATOR", "ARCHIVED", "UNKNOWN"))
        for command, state, confirmation, extra in cases:
            data = receipt_bytes(status=state)
            self.receipt.write_bytes(data)
            args = [command, "--manifest", str(manifest_path), "--apk", str(self.apk),
                    "--output", str(self.directory / "output.json"), *extra]
            if command == "publish":
                args += ["--receipt", str(self.receipt), "--receipt-sha256", hashlib.sha256(data).hexdigest(),
                         "--confirmation", confirmation]
            with self.subTest(command=command, state=state, confirmation=confirmation), \
                    patch("tool.rustore_release.os.environ.get", return_value="secret") as credentials, \
                    patch("tool.rustore_release.RustoreApiClient") as factory, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)
                self.assertEqual([call for call in credentials.call_args_list
                                  if call.args[0].startswith("RUSTORE_")], [])
                factory.assert_not_called()

    def test_pending_receipt_remains_publish_eligible_but_remote_ready_gate_is_required(self) -> None:
        manifest_path = self.directory / "manifest.json"
        manifest_path.write_text(json.dumps({key: value for key, value in json.loads(receipt_bytes()).items()
                                           if key not in {"rustoreVersionId", "publishType", "partialValue", "status", "observedAt"}}))
        for state in ("AUTO_CHECK", "TAKEN_FOR_MODERATION", "MODERATION"):
            data = receipt_bytes(status=state)
            self.receipt.write_bytes(data)
            api = FakeApi([], [version(42, state)])
            args = ["publish", "--manifest", str(manifest_path), "--apk", str(self.apk),
                    "--output", str(self.directory / "output.json"), "--receipt", str(self.receipt),
                    "--receipt-sha256", hashlib.sha256(data).hexdigest(), "--confirmation", f"PUBLISH {PACKAGE} 42"]
            with self.subTest(state=state), patch("tool.rustore_release.RustoreApiClient", return_value=api) as factory, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)
                factory.assert_called_once()
            self.assertEqual(api.events, [("get", PACKAGE, 42)])
            ready = FakeApi([], [version(42, "READY_FOR_PUBLICATION"), version(42, "ACTIVE")])
            self.assertEqual(publish_release(ready, manifest(), self.receipt, hashlib.sha256(data).hexdigest(),
                                             f"PUBLISH {PACKAGE} 42").status, "ACTIVE")
            self.assertEqual(self.receipt.read_bytes(), data)

    def test_journal_creation_and_atomic_receipt_replacement_sync_parent_directory(self) -> None:
        journal_path = self.directory / "journal.json"
        synced: list[Path] = []

        def sync(directory: Path) -> None:
            self.assertTrue(journal_path.exists())
            synced.append(directory)

        with patch("tool.rustore_release._sync_directory", create=True, side_effect=sync):
            rustore_release._Journal(journal_path, manifest())("create_requested", None)
            load_receipt(self.receipt, self.checksum, manifest()).write(self.receipt)
        self.assertEqual(synced, [self.directory, self.directory])

    def test_directory_sync_uses_posix_descriptor_and_closes_it_on_failure(self) -> None:
        for failure in (None, OSError("untrusted secret path")):
            with self.subTest(failure=failure), patch("tool.rustore_release.os.name", "posix"), \
                    patch("tool.rustore_release.os.open", return_value=71) as opened, \
                    patch("tool.rustore_release.os.fsync", side_effect=failure) as synced, \
                    patch("tool.rustore_release.os.close") as closed:
                if failure is None:
                    rustore_release._sync_directory(self.directory)
                else:
                    with self.assertRaises(RustoreReleaseError) as raised:
                        rustore_release._sync_directory(self.directory)
                    self.assertNotIn("untrusted secret", str(raised.exception))
                opened.assert_called_once_with(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                synced.assert_called_once_with(71)
                closed.assert_called_once_with(71)
        with patch("tool.rustore_release.os.name", "nt"), patch("tool.rustore_release.os.open") as opened:
            rustore_release._sync_directory(self.directory)
            opened.assert_not_called()

    def test_journal_directory_sync_failure_prevents_mutation(self) -> None:
        api = FakeApi([(self.active,)])
        journal = rustore_release._Journal(self.directory / "journal.json", manifest())
        with patch("tool.rustore_release._sync_directory", create=True, side_effect=RustoreReleaseError("Directory sync failed")):
            with self.assertRaises(RustoreReleaseError):
                submit_release(api, manifest(), self.apk, now=lambda: NOW, on_stage=journal)
        self.assertEqual(api.events, [("list", PACKAGE, ())])


if __name__ == "__main__":
    unittest.main()
