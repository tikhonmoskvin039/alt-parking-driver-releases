from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / "distribution/github/workflows/release.yml"
SHA = "a" * 40
SIGNER = "E0BEBA119BAA0F69D988495744D3BE2F531AC729656B1B4A05560B2EEB0CE414"


class ProductionReleaseWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(WORKFLOW.is_file(), "Missing protected Driver controller template")
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        code = self.workflow.split("          # BEGIN DRIVER POLICY\n", 1)[1].split(
            "          # END DRIVER POLICY", 1
        )[0]
        self.policy_code = textwrap.dedent(code)
        self.policy: dict[str, object] = {"__name__": "controller_policy_test"}
        exec(compile(self.policy_code, str(WORKFLOW), "exec"), self.policy)

    def call(self, name: str, *args: object, **kwargs: object) -> object:
        return self.policy[name](*args, **kwargs)

    def manifest(self) -> dict[str, object]:
        return dict(application="driver", packageName="ru.altparking.driver", versionName="1.2.3",
                    versionCode=18, sourceCommit=SHA, sourceTag="v1.2.3",
                    apkSha256=hashlib.sha256(b"verified-apk").hexdigest(),
                    signingCertificateSha256=SIGNER)

    def bundle(self, root: Path) -> None:
        (root / "ALT-PARKING-Driver-v1.2.3.apk").write_bytes(b"verified-apk")
        (root / "release-manifest.json").write_text(json.dumps(self.manifest()), encoding="utf-8")
        (root / "rustore-submission.json").write_bytes(self.call("disabled_receipt", self.manifest()))
        self.call("write_checksums", root, "v1.2.3")

    def test_dispatch_permissions_checkout_and_secret_boundaries(self) -> None:
        self.assertIn("environment: production", self.workflow.split("  publish:")[0])
        self.assertIn("runs-on: windows-latest", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertIn("          - build-only\n          - publish", self.workflow)
        self.assertIn("          - rustore-publish", self.workflow)
        actions = re.findall(r"uses: ([^\s]+)", self.workflow)
        self.assertTrue(actions)
        self.assertTrue(all(re.fullmatch(r"[\w/-]+@[a-f0-9]{40}", action) for action in actions))
        self.assertEqual(self.workflow.count("persist-credentials: false"), 4)
        self.assertNotIn("persist-credentials: true", self.workflow)
        self.assertIn("repository: tikhonmoskvin039/mobile-driver-frontend", self.workflow)
        self.assertIn("ref: ${{ inputs.source_sha }}", self.workflow)
        publisher = self.workflow.split("\n  publish:", 1)[1].split("\n  rustore-publish:", 1)[0]
        self.assertIn("if: ${{ inputs.mode == 'publish' }}", publisher)
        self.assertIn("needs: [immutable-policy, build]", publisher)
        self.assertNotIn("secrets.", publisher)
        self.assertIn("contents: write", publisher)
        self.assertIn("retention-days: 1", self.workflow)
        self.assertEqual(self.workflow.count("secrets.RUSTORE_SUBMIT_KEY_ID"), 1)
        self.assertEqual(self.workflow.count("secrets.RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64"), 1)
        self.assertEqual(self.workflow.count("secrets.RUSTORE_PUBLISH_KEY_ID"), 1)
        self.assertNotIn("--clobber", self.workflow)
        self.assertNotIn("flutter build", self.workflow)
        self.assertIn("pwsh -File tool/build_android_prod_release.ps1 -ConfigPath .env.driver-prod.json", self.workflow)
        self.assertGreaterEqual(self.workflow.count("if: always()"), 2)
        self.assertLess(self.workflow.index("Run canonical Python tool contracts"), self.workflow.index("secrets.ANDROID_KEYSTORE_BASE64"))
        self.assertLess(self.workflow.index("Run canonical Python tool contracts"), self.workflow.index("secrets.RUSTORE_SUBMIT_KEY_ID"))
        self.assertIn("if: inputs.mode == 'publish' && steps.provenance.outputs.rustore_enabled == 'true'", self.workflow)
        self.assertIn("openssl version", self.workflow)
        self.assertIn("Git/usr/bin", self.workflow)

    def test_all_driver_release_mutations_share_one_workflow_lock(self) -> None:
        # History checks and writes must share the lock even when tag, SHA and
        # mode differ: two candidates must never validate against the same tip.
        groups = re.findall(r"(?m)^  group: (.+)$", self.workflow)
        self.assertEqual(groups, ["driver-release-mutations"])
        self.assertEqual(len(re.findall(r"(?m)^\s*concurrency:", self.workflow)), 1)
        self.assertIn("\nconcurrency:\n", self.workflow)
        self.assertIn("  cancel-in-progress: false\n", self.workflow)
        self.assertLess(self.workflow.index("\nconcurrency:\n"), self.workflow.index("\njobs:\n"))

    def test_manual_job_has_only_protected_read_permissions_and_publish_secrets(self) -> None:
        self.assertIn("\n  rustore-publish:\n", self.workflow)
        manual = self.workflow.split("\n  rustore-publish:\n", 1)[1]
        self.assertIn("if: ${{ inputs.mode == 'rustore-publish' }}", manual)
        self.assertIn("needs: immutable-policy", manual)
        self.assertIn("environment: production", manual)
        self.assertIn("contents: read", manual)
        self.assertIn("actions: read", manual)
        self.assertEqual(manual.count("uses: actions/checkout@"), 1)
        self.assertIn("ref: ${{ github.sha }}", manual)
        self.assertEqual(re.findall(r"secrets\.([A-Z0-9_]+)", manual),
                         ["RUSTORE_PUBLISH_KEY_ID", "RUSTORE_PUBLISH_PRIVATE_KEY_PKCS8_BASE64"])
        for forbidden in ("SOURCE_REPO", "ANDROID_", "FIREBASE", "MAPKIT", "RUSTORE_SUBMIT", "contents: write",
                          "download-artifact", "flutter", "gradle", "--clobber", "continue-on-error"):
            self.assertNotIn(forbidden, manual)
        self.assertIn("      confirmation:\n", self.workflow)
        self.assertIn("if: ${{ inputs.mode == 'build-only' || inputs.mode == 'publish' }}",
                      self.workflow.split("\n  build:\n", 1)[1].split("\n  publish:\n", 1)[0])
        self.assertLess(manual.index("POLICY_OPERATION: manual-preflight"), manual.index("secrets.RUSTORE_PUBLISH_KEY_ID"))
        self.assertIn("POLICY_OPERATION: manual-publish", manual)
        self.assertIn("RECEIPT_SHA256: ${{ steps.preflight.outputs.receipt_sha256 }}", manual)

    def pending_bundle(self, root: Path) -> None:
        from tool.rustore_release import ReleaseManifest, RustoreReceipt
        self.bundle(root)
        manifest = ReleaseManifest.from_path(root / "release-manifest.json")
        receipt = RustoreReceipt(**vars(manifest), rustore_version_id=123, publish_type="MANUAL",
                                 partial_value=100, status="MODERATION", observed_at="2026-09-23T12:00:00Z")
        receipt.write(root / "rustore-submission.json")
        self.call("write_checksums", root, "v1.2.3")

    def exercise_manual_preflight(self, fault: str | None = None) -> None:
        self.assertIn("manual_preflight", self.policy, "Manual pre-credential gate is missing")
        public = "tikhonmoskvin039/alt-parking-driver-releases"
        names = ["ALT-PARKING-Driver-v1.2.3.apk", "release-manifest.json", "rustore-submission.json", "SHA256SUMS.txt"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            origin, temporary = root / "origin", root / "temporary"
            origin.mkdir()
            temporary.mkdir()
            self.pending_bundle(origin)
            if fault == "disabled":
                self.bundle(origin)
            if fault in ("package", "source", "signer", "tag", "version", "code"):
                field, value = {"package": ("packageName", "ru.altparking.guard"), "source": ("sourceCommit", "b" * 40),
                                "signer": ("signingCertificateSha256", "F" * 64), "tag": ("sourceTag", "v1.2.4"),
                                "version": ("versionName", "1.2.4"), "code": ("versionCode", 19)}[fault]
                (origin / "release-manifest.json").write_text(json.dumps({**self.manifest(), field: value}), encoding="utf-8")
                self.call("write_checksums", origin, "v1.2.3")
            if fault in ("receipt-id", "receipt-extra", "receipt-active", "receipt-manual", "receipt-partial"):
                path = origin / "rustore-submission.json"
                value = json.loads(path.read_bytes())
                field, changed = {"receipt-id": ("rustoreVersionId", 0), "receipt-extra": ("unexpected", True),
                                  "receipt-active": ("status", "ACTIVE"), "receipt-manual": ("publishType", "INSTANTLY"),
                                  "receipt-partial": ("partialValue", 50)}[fault]
                value[field] = changed
                path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
                self.call("write_checksums", origin, "v1.2.3")
            if fault in ("apk-bytes", "manifest-bytes", "receipt-bytes", "checksum-duplicate", "checksum-missing"):
                name = {"apk-bytes": names[0], "manifest-bytes": names[1], "receipt-bytes": names[2],
                        "checksum-duplicate": names[3], "checksum-missing": names[3]}[fault]
                path = origin / name
                path.write_bytes(path.read_bytes() + b"changed" if fault.endswith("bytes") else
                                 (path.read_bytes() + path.read_bytes().splitlines(keepends=True)[0] if fault.endswith("duplicate") else b""))
            release = dict(id=4, tag_name="v1.2.3", draft=False, prerelease=False, immutable=True,
                           assets=[dict(id=i + 1, name=name, state="uploaded") for i, name in enumerate(names)])
            for field in ("draft", "prerelease", "immutable"):
                if fault == field:
                    release[field] = field != "immutable"
            if fault == "remote-tag":
                release["tag_name"] = "v1.2.4"
            if fault == "missing-asset":
                release["assets"].pop()
            if fault in ("extra-asset", "duplicate-asset", "unsafe-asset"):
                release["assets"].append(dict(id=99, name={"extra-asset": "extra.json", "duplicate-asset": names[0],
                                                          "unsafe-asset": "../secret"}[fault], state="uploaded"))
            output = root / "outputs"
            environment = dict(GITHUB_REPOSITORY=public, GITHUB_REF="refs/heads/main", GITHUB_RUN_ID="42",
                               GITHUB_RUN_ATTEMPT="1", GITHUB_OUTPUT=str(output))
            if fault == "repository": environment["GITHUB_REPOSITORY"] = "other/repo"
            if fault == "ref": environment["GITHUB_REF"] = "refs/heads/other"
            if fault == "rerun": environment["GITHUB_RUN_ATTEMPT"] = "2"
            downloads = []
            requests = []

            def api(endpoint, **kwargs):
                self.assertEqual(endpoint, f"repos/{public}/releases/tags/v1.2.3")
                requests.append(endpoint)
                return release

            def pages(endpoint, key=None):
                self.assertEqual(endpoint, f"repos/{public}/actions/workflows/release.yml/runs?event=workflow_dispatch")
                self.assertEqual(key, "workflow_runs")
                attempts = [dict(id=42, display_title=f"Driver release v1.2.3 {SHA} rustore-publish")]
                if fault in ("prior-failed", "prior-ambiguous", "prior-success"):
                    attempts.append(dict(id=41, display_title=f"Driver release v1.2.3 {SHA} rustore-publish",
                                         conclusion={"prior-failed": "failure", "prior-ambiguous": None, "prior-success": "success"}[fault]))
                if fault == "history-malformed": attempts.append({})
                return attempts

            def download(selected, name):
                self.assertEqual(selected, release)
                downloads.append(name)
                return (origin / name).read_bytes()

            with patch.dict(os.environ, environment, clear=True), patch.dict(self.policy, {"api": api, "pages": pages, "download_asset": download}):
                args = (temporary, "v01.2.3" if fault == "input-tag" else "v1.2.3",
                        "A" * 40 if fault == "input-sha" else SHA,
                        "PUBLISH ru.altparking.driver 124" if fault == "confirmation" else "PUBLISH ru.altparking.driver 123")
                if fault:
                    with self.assertRaises(Exception):
                        self.call("manual_preflight", *args)
                    self.assertFalse(output.exists(), "Invalid publication emitted credential-step outputs")
                else:
                    self.call("manual_preflight", *args)
                    digest = hashlib.sha256((origin / "rustore-submission.json").read_bytes()).hexdigest()
                    self.assertEqual(output.read_text(), f"receipt_sha256={digest}\nrustore_version_id=123\n")
                    self.assertEqual(downloads, names)
            if fault in ("prior-failed", "prior-ambiguous", "prior-success", "history-malformed", "rerun", "repository", "ref", "input-tag", "input-sha"):
                self.assertEqual(requests, [])
            if fault in ("remote-tag", "draft", "prerelease", "immutable", "missing-asset", "extra-asset", "duplicate-asset", "unsafe-asset"):
                self.assertEqual(downloads, [])

    def test_manual_preflight_downloads_exact_immutable_bundle_and_emits_validated_receipt(self) -> None:
        self.exercise_manual_preflight()

    def test_manual_preflight_blocks_invalid_identity_bytes_receipts_and_repeat_attempts(self) -> None:
        for fault in ("repository", "ref", "rerun", "input-tag", "input-sha", "prior-failed", "prior-ambiguous", "prior-success",
                      "history-malformed", "remote-tag", "draft", "prerelease", "immutable", "missing-asset", "extra-asset",
                      "duplicate-asset", "unsafe-asset", "disabled", "package", "source", "signer", "tag", "version", "code",
                      "receipt-id", "receipt-extra", "receipt-active", "receipt-manual", "receipt-partial", "apk-bytes",
                      "manifest-bytes", "receipt-bytes", "checksum-duplicate", "checksum-missing", "confirmation"):
            with self.subTest(fault=fault):
                self.exercise_manual_preflight(fault)

    def test_manual_publish_invokes_driver_cli_once_and_requires_matching_active_receipt(self) -> None:
        self.assertIn("manual_publish", self.policy, "Manual publish operation is missing")
        from tool.rustore_release import ReleaseManifest, RustoreReceipt
        for status in ("ACTIVE", "READY_FOR_PUBLICATION", "PARTIAL_ACTIVE", "wrong-id", "failure"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                temporary = workspace / "temp"
                bundle = temporary / "assets"
                bundle.mkdir(parents=True)
                self.pending_bundle(bundle)
                manifest = ReleaseManifest.from_path(bundle / "release-manifest.json")
                digest = hashlib.sha256((bundle / "rustore-submission.json").read_bytes()).hexdigest()
                calls = []

                def command(argv, *, cwd=None):
                    calls.append(argv)
                    self.assertEqual(cwd, workspace / "controller")
                    self.assertEqual(argv, [sys.executable, "-m", "tool.rustore_release", "publish", "--manifest",
                                           str(bundle / "release-manifest.json"), "--apk", str(bundle / "ALT-PARKING-Driver-v1.2.3.apk"),
                                           "--receipt", str(bundle / "rustore-submission.json"), "--receipt-sha256", digest,
                                           "--confirmation", "PUBLISH ru.altparking.driver 123", "--output", str(temporary / "rustore-publication.json")])
                    if status == "failure": raise RuntimeError("Ambiguous operation")
                    receipt = RustoreReceipt(**vars(manifest), rustore_version_id=124 if status == "wrong-id" else 123,
                                             publish_type="MANUAL", partial_value=100,
                                             status="ACTIVE" if status == "wrong-id" else status, observed_at="2026-09-23T13:00:00Z")
                    receipt.write(temporary / "rustore-publication.json")
                    return b""

                with patch.dict(self.policy, {"run": command}), patch.dict(os.environ, {"RECEIPT_SHA256": digest}):
                    if status == "ACTIVE":
                        self.call("manual_publish", workspace, temporary, "v1.2.3", SHA, "PUBLISH ru.altparking.driver 123")
                    else:
                        with self.assertRaises(Exception):
                            self.call("manual_publish", workspace, temporary, "v1.2.3", SHA, "PUBLISH ru.altparking.driver 123")
                self.assertEqual(len(calls), 1)

    def test_manual_publish_rechecks_bundle_and_confirmation_before_cli(self) -> None:
        for fault in ("digest", "confirmation", "symlink", "disabled"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                temporary = workspace / "temp"
                bundle = temporary / "assets"
                bundle.mkdir(parents=True)
                self.pending_bundle(bundle)
                if fault == "disabled": self.bundle(bundle)
                digest = hashlib.sha256((bundle / "rustore-submission.json").read_bytes()).hexdigest()
                calls = []
                original_is_symlink = Path.is_symlink

                def is_symlink(path):
                    return (fault == "symlink" and path.name == "rustore-submission.json") or original_is_symlink(path)

                with patch.dict(self.policy, {"run": lambda *a, **k: calls.append(a)}), \
                        patch.dict(os.environ, {"RECEIPT_SHA256": "0" * 64 if fault == "digest" else digest}), \
                        patch.object(Path, "is_symlink", is_symlink):
                    with self.assertRaises(Exception):
                        self.call("manual_publish", workspace, temporary, "v1.2.3", SHA,
                                  "PUBLISH ru.altparking.driver 124" if fault == "confirmation" else "PUBLISH ru.altparking.driver 123")
                self.assertEqual(calls, [], "Invalid bundle reached the credential-bearing CLI")

    def test_manual_workflow_scripts_execute_preflight_then_single_publish_without_build(self) -> None:
        from tool.rustore_release import ReleaseManifest, RustoreReceipt
        manual = self.workflow.split("\n  rustore-publish:\n", 1)[1]
        scripts = []
        for name in ("Validate prior dispatches and exact immutable publication bundle", "Publish saved RuStore version once and require ACTIVE"):
            step = manual.split("      - name: " + name + "\n", 1)[1].split("\n      - ", 1)[0]
            scripts.append(textwrap.dedent(step.split("        run: |\n", 1)[1]))
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            runner_temp = workspace / "runner-temp"
            runner_temp.mkdir()
            workflow_path = workspace / "controller/.github/workflows/release.yml"
            workflow_path.parent.mkdir(parents=True)
            workflow_path.write_text(self.workflow, encoding="utf-8")
            origin = workspace / "origin"
            origin.mkdir()
            self.pending_bundle(origin)
            names = ["ALT-PARKING-Driver-v1.2.3.apk", "release-manifest.json", "rustore-submission.json", "SHA256SUMS.txt"]
            title = f"Driver release v1.2.3 {SHA} rustore-publish"
            release = dict(id=4, tag_name="v1.2.3", draft=False, prerelease=False, immutable=True,
                           assets=[dict(id=i + 1, name=name, state="uploaded") for i, name in enumerate(names)])
            calls = []

            def process(argv, **kwargs):
                calls.append(argv)
                if argv[:2] == ["gh", "api"]:
                    endpoint = argv[5]
                    prefix = "repos/tikhonmoskvin039/alt-parking-driver-releases/"
                    if endpoint == prefix + "actions/workflows/release.yml/runs?event=workflow_dispatch&per_page=100&page=1":
                        raw = json.dumps(dict(total_count=1, workflow_runs=[dict(id=42, display_title=title)])).encode()
                    elif endpoint == prefix + "releases/tags/v1.2.3":
                        raw = json.dumps(release).encode()
                    else:
                        self.assertIn(endpoint, [prefix + f"releases/assets/{n}" for n in (1, 2, 3, 4)])
                        raw = (origin / names[int(endpoint.rsplit("/", 1)[1]) - 1]).read_bytes()
                    return subprocess.CompletedProcess(argv, 0, b"HTTP/2.0 200 OK\r\n\r\n" + raw, b"")
                self.assertEqual(argv[:4], [sys.executable, "-m", "tool.rustore_release", "publish"])
                manifest = ReleaseManifest.from_path(Path(argv[argv.index("--manifest") + 1]))
                RustoreReceipt(**vars(manifest), rustore_version_id=123, publish_type="MANUAL", partial_value=100,
                               status="ACTIVE", observed_at="2026-09-23T13:00:00Z").write(Path(argv[argv.index("--output") + 1]))
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            environment = dict(GITHUB_WORKSPACE=str(workspace), RUNNER_TEMP=str(runner_temp),
                               GITHUB_REPOSITORY="tikhonmoskvin039/alt-parking-driver-releases", GITHUB_REF="refs/heads/main",
                               GITHUB_RUN_ID="42", GITHUB_RUN_ATTEMPT="1", GITHUB_OUTPUT=str(workspace / "outputs"),
                               RELEASE_MODE="rustore-publish", RELEASE_TAG="v1.2.3", SOURCE_SHA=SHA,
                               PUBLICATION_CONFIRMATION="PUBLISH ru.altparking.driver 123", POLICY_OPERATION="manual-preflight")
            with patch.dict(os.environ, environment, clear=True), patch("subprocess.run", side_effect=process), \
                    patch.object(sys, "path", list(sys.path)), redirect_stdout(io.StringIO()) as output:
                exec(compile(scripts[0], "manual-preflight-step", "exec"), {"__name__": "__main__"})
                self.assertEqual(len(calls), 6)  # History, exact release and four exact assets.
                os.environ["POLICY_OPERATION"] = "manual-publish"
                os.environ["RECEIPT_SHA256"] = (workspace / "outputs").read_text().splitlines()[0].split("=", 1)[1]
                exec(compile(scripts[1], "manual-publish-step", "exec"), {"__name__": "__main__"})
                self.assertEqual(len(calls), 7)
                self.assertEqual(output.getvalue(), "RuStore version 123: ACTIVE\n")
                self.assertEqual(os.environ["TMPDIR"], str(runner_temp / "driver-release"))

    @staticmethod
    def invalid_pagination_cases(mode="rustore-publish"):
        current = dict(id=42, display_title=f"Driver release v1.2.3 {SHA} {mode}")
        hundred = [current] + [dict(id=i, display_title="Unrelated") for i in range(100, 199)]
        envelope = lambda total, rows: dict(total_count=total, workflow_runs=rows)
        return {
            "missing-total": [dict(workflow_runs=[current])],
            "bool-total": [envelope(True, [current])],
            "negative-total": [envelope(-1, [current])],
            "string-total": [envelope("1", [current])],
            "float-total": [envelope(1.0, [current])],
            "unexpected-field": [{**envelope(1, [current]), "unexpected": True}],
            "truncated-short-page": [envelope(2, [current])],
            "truncated-empty-page": [envelope(101, hundred), envelope(101, [])],
            "drifting-total": [envelope(101, hundred), envelope(100, [])],
            "extra-rows": [envelope(0, [current])],
            "duplicate-rows": [envelope(3, [current, hundred[1], hundred[1]])],
            "duplicate-across-pages": [envelope(101, hundred), envelope(101, [hundred[1]])],
            "invalid-row-id": [envelope(2, [current, dict(id=True, display_title="Unrelated")])],
            "ceiling-exact": [envelope(1000, [current])],
            "ceiling-exceeded": [envelope(1001, [current])],
        }

    def test_keyed_pagination_rejects_incomplete_inconsistent_or_capped_responses(self) -> None:
        endpoint = "repos/example/repo/actions/workflows/release.yml/runs?event=workflow_dispatch"
        for fault, responses in self.invalid_pagination_cases().items():
            with self.subTest(fault=fault), patch.dict(self.policy, {"api": lambda url, **kwargs: responses[int(url.rsplit("=", 1)[1]) - 1]}):
                with self.assertRaises(RuntimeError):
                    self.call("pages", endpoint, "workflow_runs")

    def test_keyed_pagination_accepts_complete_subceiling_history_and_jobs_and_list_endpoints(self) -> None:
        for key, total in (("workflow_runs", 0), ("workflow_runs", 1), ("workflow_runs", 100),
                           ("workflow_runs", 101), ("workflow_runs", 999), ("jobs", 1000), (None, 101)):
            rows = [dict(id=i + 1) for i in range(total)]
            requests = []

            def api(url, token=None):
                self.assertEqual(token, "synthetic-read")
                requests.append(url)
                page = int(url.rsplit("=", 1)[1])
                values = rows[(page - 1) * 100:page * 100]
                return dict(total_count=total, **{key: values}) if key else values

            with self.subTest(key=key, total=total), patch.dict(self.policy, {"api": api}):
                self.assertEqual(self.call("pages", "repos/example/repo/items?filter=latest", key, "synthetic-read"), rows)
                self.assertTrue(requests)

    def test_manual_history_completeness_rejection_precedes_assets_outputs_and_credentials(self) -> None:
        for fault, responses in self.invalid_pagination_cases().items():
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                temporary = Path(directory)
                output = temporary / "outputs"
                requests = []

                def api(endpoint, **kwargs):
                    prefix = "repos/tikhonmoskvin039/alt-parking-driver-releases/actions/workflows/release.yml/runs?event=workflow_dispatch&per_page=100&page="
                    self.assertTrue(endpoint.startswith(prefix), "Incomplete history reached release assets")
                    requests.append(endpoint)
                    return responses[int(endpoint.removeprefix(prefix)) - 1]

                environment = dict(GITHUB_REPOSITORY="tikhonmoskvin039/alt-parking-driver-releases", GITHUB_REF="refs/heads/main",
                                   GITHUB_RUN_ATTEMPT="1", GITHUB_RUN_ID="42", GITHUB_OUTPUT=str(output))
                with patch.dict(os.environ, environment, clear=True), patch.dict(self.policy, {"api": api}):
                    with self.assertRaises(RuntimeError):
                        self.call("manual_preflight", temporary, "v1.2.3", SHA, "PUBLISH ru.altparking.driver 123")
                self.assertTrue(requests)
                self.assertFalse(output.exists())
                self.assertFalse((temporary / "assets").exists())

    def test_provenance_history_completeness_rejection_precedes_outputs_credentials_and_mutations(self) -> None:
        for fault, responses in self.invalid_pagination_cases("publish").items():
            with self.subTest(fault=fault):
                error, output, accepted, secrets, commands, requests = self._exercise_provenance(history_pages=responses)
                self.assertIsInstance(error, RuntimeError, f"Incomplete dispatch history accepted: {fault}")
                self.assertIsNone(output)
                self.assertFalse(accepted)
                self.assertEqual(secrets, [])
                self.assertFalse(any(endpoint.endswith("/releases") for endpoint in requests))
                self.assertFalse(any("git/matching-refs" in endpoint for endpoint in requests))

    def _exercise_provenance(self, fault: str | None = None, *, policy=None, history_pages=None):
        # Keep real reviewed helpers loaded when main prepends the fixture
        # controller path; temporary files exercise parity, not Python imports.
        from tool import release_metadata, release_state

        policy = self.policy if policy is None else policy
        real_pages = policy["pages"]
        private = "tikhonmoskvin039/mobile-driver-frontend"
        public = "tikhonmoskvin039/alt-parking-driver-releases"
        title = f"Driver release v1.2.3 {SHA} publish"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            temporary = workspace / "runner-temp" / "driver-release"
            temporary.mkdir(parents=True)
            source, controller = workspace / "source", workspace / "controller"
            paths = ["tool/" + name + suffix + ".py" for name in (
                "release_metadata", "release_state", "java_properties", "rustore_api", "rustore_release"
            ) for suffix in ("", "_test")]
            paths += ["tool/production_release_workflow_test.py", ".github/workflows/release.yml"]
            for path in paths:
                canonical = "distribution/github/workflows/release.yml" if path.startswith(".github/") else path
                for root, name in ((controller, path), (source, canonical)):
                    destination = root / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes((ROOT / canonical).read_bytes())
            (source / "pubspec.yaml").write_text("version: 1.2.3+18\n", encoding="utf-8")
            if fault in ("helper", "template"):
                changed = "tool/rustore_api.py" if fault == "helper" else ".github/workflows/release.yml"
                (controller / changed).write_bytes(b"noncanonical-fixture\n")
            output = workspace / "github-output"
            secret_reads = []
            commands = []
            requests = []
            ci = dict(id=8, name="CI", head_sha=SHA, head_branch="main", event="push", status="completed", conclusion="success")
            older_ci = {**ci, "id": 7}
            if fault == "latest-ci":
                ci["conclusion"] = "failure"
            foundation = dict(name="foundation", head_sha=SHA, status="completed", conclusion="success")
            if fault == "foundation":
                foundation["conclusion"] = "failure"

            class CredentialBoundary(dict):
                def __getitem__(self, key):
                    if key.startswith(("ANDROID_", "FIREBASE_", "YANDEX_", "RUSTORE_SUBMIT_")):
                        secret_reads.append(key)
                        raise AssertionError("Production credential read before provenance acceptance")
                    return super().__getitem__(key)

                def get(self, key, default=None):
                    return self[key] if key in self or key.startswith(("ANDROID_", "FIREBASE_", "YANDEX_", "RUSTORE_SUBMIT_")) else default

            environment = CredentialBoundary(
                GITHUB_WORKSPACE=str(workspace), RUNNER_TEMP=str(temporary.parent),
                GITHUB_REPOSITORY=public if fault != "repository" else "untrusted/repository",
                GITHUB_REF="refs/heads/main" if fault != "ref" else "refs/heads/untrusted",
                GITHUB_RUN_ATTEMPT="2" if fault == "rerun" else "1", GITHUB_RUN_ID="42",
                GITHUB_OUTPUT=str(output), RELEASE_TAG="v1.2.3", SOURCE_SHA=SHA,
                RELEASE_MODE="publish", DELIVERY_FLAG="true", POLICY_OPERATION="provenance",
                SOURCE_REPO_READ_TOKEN="synthetic-source-read-token",
            )

            def git(argv, *, cwd=None, **kwargs):
                self.assertEqual(cwd, source)
                commands.append(argv)
                if argv == ["git", "rev-parse", "HEAD"]:
                    return (("b" * 40 if fault == "head" else SHA) + "\n").encode()
                if argv == ["git", "merge-base", "--is-ancestor", SHA, "refs/remotes/origin/main"]:
                    if fault == "ancestry":
                        raise RuntimeError("Source is not on main")
                    return b""
                if argv == ["git", "rev-parse", "refs/tags/v1.2.3^{commit}"]:
                    return (("b" * 40 if fault == "tag" else SHA) + "\n").encode()
                raise AssertionError("Unexpected command at the provenance boundary")

            def pages(endpoint, key=None, token=None):
                requests.append(endpoint)
                if endpoint == f"repos/{private}/actions/workflows/ci.yml/runs?event=push&branch=main&head_sha={SHA}":
                    self.assertEqual(token, "synthetic-source-read-token")
                    return [older_ci, ci]
                if endpoint == f"repos/{private}/actions/runs/8/jobs?filter=latest":
                    self.assertEqual(token, "synthetic-source-read-token")
                    return [] if fault == "missing-foundation" else [foundation]
                if endpoint == f"repos/{public}/actions/workflows/release.yml/runs?event=workflow_dispatch":
                    if history_pages is not None:
                        return real_pages(endpoint, key, token)
                    return [{"id": 42, "display_title": title}, {"id": 41, "display_title": title if fault == "prior-dispatch" else "Unrelated release"}]
                if endpoint == f"repos/{public}/releases":
                    return []
                raise AssertionError("Unexpected API request at the provenance boundary")

            def api(endpoint, **kwargs):
                history_prefix = f"repos/{public}/actions/workflows/release.yml/runs?event=workflow_dispatch&per_page=100&page="
                if history_pages is not None and endpoint.startswith(history_prefix):
                    requests.append(endpoint)
                    return history_pages[int(endpoint.removeprefix(history_prefix)) - 1]
                self.assertEqual(endpoint, f"repos/{public}/git/matching-refs/tags/v1.2.3")
                self.assertEqual(kwargs, {})
                requests.append(endpoint)
                return []

            error = None
            with patch.object(os, "environ", environment), patch.object(sys, "path", sys.path.copy()), \
                    patch.dict(policy, {"run": git, "pages": pages, "api": api}), \
                    patch("subprocess.run", side_effect=AssertionError("Unexpected real subprocess")):
                try:
                    # Runs the actual operation selector, input/retry validation,
                    # provenance function and helper checks; only I/O is faked.
                    policy["main"]()
                except RuntimeError as raised:
                    error = raised
            return error, output.read_text(encoding="utf-8") if output.exists() else None, \
                (temporary / "first-release").exists(), secret_reads, commands, requests

    def _assert_provenance_rejected(self, fault, *, policy=None):
        error, output, history_accepted, secrets, commands, requests = self._exercise_provenance(fault, policy=policy)
        self.assertIsInstance(error, RuntimeError, f"Provenance accepted invalid {fault}")
        self.assertIsNone(output, "No credential-step enable output is allowed after rejection")
        self.assertFalse(history_accepted)
        self.assertEqual(secrets, [])
        self.assertFalse(any(endpoint.endswith("/releases") for endpoint in requests))
        if fault == "rerun":
            self.assertEqual(commands, [])
            self.assertEqual(requests, [])

    def test_provenance_accepts_only_complete_canonical_source_boundary(self) -> None:
        error, output, history_accepted, secrets, commands, requests = self._exercise_provenance()
        self.assertIsNone(error)
        self.assertEqual(output, "rustore_enabled=true\n")
        self.assertTrue(history_accepted)
        self.assertEqual(secrets, [])
        self.assertEqual(len(commands), 3)
        self.assertTrue(requests[-1].endswith("/releases"))

    def test_provenance_rejects_each_source_ci_parity_and_retry_failure(self) -> None:
        for fault in ("head", "ancestry", "tag", "repository", "ref", "helper", "template",
                      "latest-ci", "foundation", "missing-foundation", "prior-dispatch", "rerun"):
            with self.subTest(fault=fault):
                self._assert_provenance_rejected(fault)

    def test_provenance_negative_cases_detect_removed_security_checks(self) -> None:
        # Remove gates only in memory to prove these executable regression cases
        # kill the concrete bypasses identified in review, without editing files.
        mutations = {
            "head": "Source HEAD mismatch", "ancestry": 'run(["git", "merge-base"',
            "tag": "Private tag mismatch", "repository": "Wrong controller repository or ref",
            "ref": "Wrong controller repository or ref", "helper": "    verify_parity(controller, source)",
            "template": "    verify_parity(controller, source)", "latest-ci": "    select_ci(runs, jobs, sha)",
            "foundation": "Required foundation job did not pass", "missing-foundation": "Required foundation job did not pass",
            "prior-dispatch": "Earlier dispatch exists", "rerun": "Rerun forbidden",
        }
        for fault, needle in mutations.items():
            with self.subTest(fault=fault):
                lines = self.policy_code.splitlines()
                self.assertEqual(sum(needle in line for line in lines), 1)
                mutated = "\n".join(line for line in lines if needle not in line)
                policy = {"__name__": "mutated_policy_test"}
                exec(compile(mutated, "mutated-policy", "exec"), policy)
                with self.assertRaisesRegex(AssertionError, "Provenance accepted invalid"):
                    self._assert_provenance_rejected(fault, policy=policy)

    def test_workflow_runs_provenance_before_production_credentials(self) -> None:
        build = self.workflow.split("\n  build:\n", 1)[1].split("\n  publish:\n", 1)[0]
        gate = build.split("      - name: Validate provenance history and delivery flag\n", 1)[1].split("\n      - ", 1)[0]
        self.assertIn("POLICY_OPERATION: provenance", gate)
        self.assertIn('python "$env:RUNNER_TEMP/driver-release/policy.py"', gate)
        self.assertIn("if ($LASTEXITCODE -ne 0)", gate)
        self.assertNotIn("continue-on-error", build)
        for step in ("Prepare exclusive temporary production configuration and signing", "Submit verified APK to manual RuStore moderation once"):
            self.assertLess(build.index("Validate provenance history and delivery flag"), build.index(step))

    def test_input_gate_rejects_bad_flag_sha_tag_mode_and_rerun(self) -> None:
        self.assertEqual(self.call("validate_inputs", "v1.2.3", SHA, "publish", "true", "1"), True)
        self.assertEqual(self.call("validate_inputs", "v1.2.3", SHA, "publish", "false", "1"), False)
        self.assertEqual(self.call("validate_inputs", "v1.2.3", SHA, "build-only", "true", "1"), False)
        for field, value in ((0, "v01.2.3"), (1, "A" * 40), (1, "a" * 64),
                             (2, "rustore-publish"), (3, ""), (3, "TRUE"), (3, " true"), (4, "2")):
            args = ["v1.2.3", SHA, "publish", "true", "1"]
            args[field] = value
            with self.subTest(args=args), self.assertRaises(RuntimeError):
                self.call("validate_inputs", *args)

    def test_parity_rejects_one_changed_helper_before_executing_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, controller = root / "source", root / "controller"
            mapping = self.call("canonical_files")
            self.assertEqual(set(mapping) - {".github/workflows/release.yml"}, {
                "tool/" + name + ".py" for name in (
                    "release_metadata", "release_metadata_test", "release_state", "release_state_test",
                    "java_properties", "java_properties_test", "rustore_api", "rustore_api_test",
                    "rustore_release", "rustore_release_test", "production_release_workflow_test")})
            for public, private in mapping.items():
                for base, name in ((source, private), (controller, public)):
                    (base / name).parent.mkdir(parents=True, exist_ok=True)
                    (base / name).write_bytes(b"canonical\n")
            self.call("verify_parity", controller, source)
            (controller / "tool/rustore_api.py").write_bytes(b"different\n")
            with self.assertRaises(RuntimeError):
                self.call("verify_parity", controller, source)

    def test_ci_requires_latest_matching_main_push_run_and_foundation_success(self) -> None:
        run = dict(id=7, name="CI", head_sha=SHA, head_branch="main", event="push", status="completed", conclusion="success")
        jobs = [dict(name="foundation", status="completed", conclusion="success", head_sha=SHA)]
        self.assertEqual(self.call("select_ci", [run], jobs, SHA), 7)
        for field, value in (("head_sha", "b" * 40), ("event", "pull_request"), ("head_branch", "other"),
                             ("status", "in_progress"), ("conclusion", "failure")):
            bad = {**run, field: value}
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.call("select_ci", [bad], jobs, SHA)
        with self.assertRaises(RuntimeError):
            self.call("select_ci", [{**run, "id": 8, "conclusion": "failure"}, run], jobs, SHA)
        with self.assertRaises(RuntimeError):
            self.call("select_ci", [run], [], SHA)

    def test_history_requires_absence_rejects_drafts_and_validates_exact_assets(self) -> None:
        self.assertEqual(self.call("validate_history", [], "v1.2.3"), [])
        names = self.call("asset_names", "v1.2.2")
        release = dict(id=1, tag_name="v1.2.2", draft=False, prerelease=False, immutable=True,
                       assets=[dict(id=i+1, name=name, state="uploaded") for i, name in enumerate(names)])
        self.assertEqual(self.call("validate_history", [release], "v1.2.3"), [release])
        for mutation in ({"draft": True}, {"prerelease": True}, {"immutable": False},
                         {"tag_name": "v1.2.3"}, {"assets": release["assets"][:-1]},
                         {"assets": release["assets"] + [release["assets"][0]]}):
            with self.subTest(mutation=mutation), self.assertRaises(Exception):
                self.call("validate_history", [{**release, **mutation}], "v1.2.3")

    def test_disabled_receipt_is_deterministic_without_store_id(self) -> None:
        receipt = self.call("disabled_receipt", self.manifest())
        self.assertEqual(receipt, self.call("disabled_receipt", self.manifest()))
        self.assertEqual(json.loads(receipt), {**self.manifest(), "status": "DISABLED", "publishable": False})

    def test_bundle_verifies_exact_names_bytes_manifest_and_disabled_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.bundle(root)
            self.call("verify_bundle", root, "v1.2.3", SHA, False)
            for name in (".env.driver-prod.json", "journal.json", "key.properties", "unexpected.aab"):
                (root / name).write_bytes(b"must-not-publish")
                with self.subTest(name=name), self.assertRaises(Exception):
                    self.call("verify_bundle", root, "v1.2.3", SHA, False)
                (root / name).unlink()
            (root / "ALT-PARKING-Driver-v1.2.3.apk").write_bytes(b"changed")
            with self.assertRaises(Exception):
                self.call("verify_bundle", root, "v1.2.3", SHA, False)

    def test_bundle_rejects_rehashed_identity_or_receipt_and_nonexact_checksum_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for mutation in ({"sourceCommit": "b" * 40}, {"packageName": "ru.altparking.guard"},
                             {"signingCertificateSha256": "F" * 64}):
                self.bundle(root)
                (root / "release-manifest.json").write_text(json.dumps({**self.manifest(), **mutation}), encoding="utf-8")
                self.call("write_checksums", root, "v1.2.3")
                with self.subTest(mutation=mutation), self.assertRaises(Exception):
                    self.call("verify_bundle", root, "v1.2.3", SHA, False)
            self.bundle(root)
            with self.assertRaises(Exception):
                self.call("verify_bundle", root, "v1.2.3", SHA, True)
            sums = root / "SHA256SUMS.txt"
            sums.write_bytes(sums.read_bytes() + sums.read_bytes().splitlines(keepends=True)[0])
            with self.assertRaises(Exception):
                self.call("verify_bundle", root, "v1.2.3", SHA, False)

    def test_apk_gate_rejects_wrong_package_version_code_or_extra_signers(self) -> None:
        badging = "package: name='ru.altparking.driver' versionCode='18' versionName='1.2.3' platformBuildVersionName='16'"
        certs = "Signer #1 certificate SHA-256 digest: " + SIGNER.lower()
        self.call("validate_apk_identity", badging, certs, "1.2.3", 18)
        for bad, certificate in ((badging.replace("driver", "guard"), certs),
                                 (badging.replace("'18'", "'17'"), certs),
                                 (badging.replace("'1.2.3'", "'1.2.4'"), certs),
                                 (badging, certs.replace(SIGNER.lower(), "a" * 64)),
                                 (badging, certs + "\nSigner #2 certificate SHA-256 digest: " + SIGNER.lower())):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                self.call("validate_apk_identity", bad, certificate, "1.2.3", 18)

    def test_production_config_has_exact_keys_and_rejects_empty_without_values(self) -> None:
        keys = {"APP_ENV", "API_BASE_URL", "WS_BASE_URL", "FIREBASE_API_KEY", "FIREBASE_APP_ID",
                "FIREBASE_MESSAGING_SENDER_ID", "FIREBASE_PROJECT_ID", "YANDEX_MAPKIT_API_KEY",
                "MAP_FALLBACK_LATITUDE", "MAP_FALLBACK_LONGITUDE", "SUPPORT_PHONE", "OAUTH_RETURN_URI"}
        self.assertEqual(set(self.call("production_config", {key: "synthetic" for key in keys})), keys)
        with self.assertRaises(RuntimeError) as raised:
            self.call("production_config", {key: "SECRET_VALUE" for key in keys - {"APP_ENV"}})
        self.assertNotIn("SECRET_VALUE", str(raised.exception))

    def test_isolated_immutable_policy_uses_admin_read_token_only_on_stdin(self) -> None:
        self.assertIn("\n  immutable-policy:\n", self.workflow)
        gate = self.workflow.split("\n  immutable-policy:\n", 1)[1].split("\n  build:\n", 1)[0]
        self.assertIn("environment: production", gate)
        self.assertIn("permissions: {}", gate)
        self.assertNotIn("actions/checkout", gate)
        self.assertEqual(re.findall(r"secrets\.([A-Z_]+)", gate), ["CONTROLLER_ADMIN_READ_TOKEN"])
        self.assertEqual(self.workflow.count("secrets.CONTROLLER_ADMIN_READ_TOKEN"), 1)
        script = textwrap.dedent(gate.split("        run: |\n", 1)[1])
        token = "github_pat_SYNTHETIC_READ_ONLY"
        for status, body, succeeds in ((200, b'{"enabled":true}', True), (200, b'{"enabled":false}', False),
                                       (200, b'{"enabled":"true"}', False), (404, b'{}', False),
                                       (201, b'{"enabled":true}', False), (200, b'bad-json', False)):
            calls = []

            def curl(argv, **kwargs):
                calls.append(argv)
                self.assertEqual(argv, ["curl", "--silent", "--show-error", "--config", "-", "--request", "GET",
                                       "--header", "Accept: application/vnd.github+json", "--header",
                                       "X-GitHub-Api-Version: 2026-03-10", "--write-out", "\n%{http_code}",
                                       "https://api.github.com/repos/tikhonmoskvin039/alt-parking-driver-releases/immutable-releases"])
                self.assertNotIn(token, " ".join(argv))
                self.assertEqual(kwargs["input"], f'header = "Authorization: Bearer {token}"\n'.encode())
                return subprocess.CompletedProcess(argv, 0, body + f"\n{status}".encode(), b"")

            output = io.StringIO()
            with self.subTest(status=status, body=body), patch.dict(os.environ, {"CONTROLLER_ADMIN_READ_TOKEN": token}), \
                    patch("subprocess.run", side_effect=curl), redirect_stdout(output):
                if succeeds:
                    exec(compile(script, "immutable-policy", "exec"), {"__name__": "__main__"})
                else:
                    with self.assertRaises(SystemExit):
                        exec(compile(script, "immutable-policy", "exec"), {"__name__": "__main__"})
            self.assertEqual(len(calls), 1)
            self.assertNotIn(token, output.getvalue())

    def test_history_rechecksums_trusted_manifests_and_selects_highest_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            releases = [dict(tag_name="v1.2.1", code=16), dict(tag_name="v1.2.2", code=17)]

            def download(release, name):
                manifest = {**self.manifest(), "sourceTag": release["tag_name"],
                            "versionName": release["tag_name"][1:], "versionCode": release["code"]}
                raw = json.dumps(manifest).encode()
                if name == "release-manifest.json":
                    return raw
                return "".join((hashlib.sha256(raw).hexdigest() if n == "release-manifest.json" else "a" * 64)
                               + "  " + n + "\n" for n in self.call("asset_names", release["tag_name"])[:-1]).encode()

            with patch.dict(self.policy, {"download_asset": download}):
                selected = self.call("previous_manifest", releases, temp)
                self.assertEqual(json.loads(selected.read_bytes())["versionCode"], 17)
            with patch.dict(self.policy, {"download_asset": lambda *a: b"tampered"}):
                with self.assertRaises(Exception):
                    self.call("previous_manifest", releases, temp)
            self.assertFalse((temp / "first-release").exists())

    def test_public_tag_is_absent_even_when_no_release_exists(self) -> None:
        with patch.dict(self.policy, {"api": lambda *a, **k: [{"ref": "refs/tags/v1.2.3"}]}):
            with self.assertRaises(RuntimeError):
                self.call("require_absent_public_tag", "v1.2.3")

    def test_github_api_requires_exact_http_status_before_using_response(self) -> None:
        for status, method in ((200, "GET"), (201, "POST"), (200, "PATCH")):
            response = f"HTTP/2.0 {status} OK\r\nContent-Type: application/json\r\n\r\n".encode() + b'{"enabled":true}'
            with patch.dict(self.policy, {"run": lambda *a, **k: response}):
                self.assertEqual(self.call("api", "repos/example/repo/immutable-releases", method=method), {"enabled": True})
        for status in (201, 202, 204, 301, 404, 500):
            response = f"HTTP/2.0 {status} Status\r\n\r\n".encode() + b'{"enabled":true}'
            with self.subTest(status=status), patch.dict(self.policy, {"run": lambda *a, **k: response}):
                with self.assertRaises(RuntimeError):
                    self.call("api", "repos/example/repo/immutable-releases")

    def test_publisher_promotes_once_only_after_exact_remote_bytes_and_assets(self) -> None:
        for corruption in (None, "bytes", "extra-asset", "duplicate-asset"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                bundle = workspace / "release-assets"
                bundle.mkdir()
                self.bundle(bundle)
                temp = workspace / "temp"
                temp.mkdir()
                remote = {}
                uploaded = {}
                mutations = []

                def api(endpoint, *, method="GET", payload=None, **kwargs):
                    if endpoint.endswith("/immutable-releases"):
                        return {"enabled": True}
                    if "git/matching-refs/tags/" in endpoint:
                        return []
                    if method == "POST":
                        mutations.append("create")
                        remote.update(id=123, tag_name="v1.2.3", draft=True, prerelease=False, assets=[])
                    elif method == "PATCH":
                        mutations.append("promote")
                        remote.update(draft=False, immutable=True)
                    elif corruption == "extra-asset":
                        remote["assets"].append(dict(id=99, name="secret.json", state="uploaded"))
                    elif corruption == "duplicate-asset":
                        remote["assets"].append(dict(remote["assets"][0], id=99))
                    return remote.copy()

                def upload(argv, **kwargs):
                    path = Path(argv[argv.index("--input") + 1])
                    self.assertNotIn(path.name, uploaded)
                    uploaded[path.name] = path.read_bytes()
                    remote["assets"].append(dict(id=len(uploaded), name=path.name, state="uploaded"))
                    return b"{}"

                environment = {"GITHUB_REPOSITORY": "tikhonmoskvin039/alt-parking-driver-releases",
                               "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": "c" * 40}
                with patch.dict("os.environ", environment), patch.dict(self.policy, {
                    "api": api, "run": upload, "pages": lambda *a, **k: [],
                    "download_asset": lambda release, name: b"changed" if corruption == "bytes" else uploaded[name],
                }):
                    if corruption:
                        with self.assertRaises(Exception):
                            self.call("publish", workspace, temp, "v1.2.3", SHA, False)
                    else:
                        self.call("publish", workspace, temp, "v1.2.3", SHA, False)
                self.assertEqual(mutations, ["create"] if corruption else ["create", "promote"])
                self.assertEqual(set(uploaded), {"ALT-PARKING-Driver-v1.2.3.apk", "release-manifest.json",
                                                "rustore-submission.json", "SHA256SUMS.txt"})

    def test_submission_bundle_accepts_pending_manual_receipt_and_rejects_active(self) -> None:
        from tool.rustore_release import ReleaseManifest, RustoreReceipt

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.bundle(root)
            manifest = ReleaseManifest.from_path(root / "release-manifest.json")
            for status in ("MODERATION", "READY_FOR_PUBLICATION", "ACTIVE"):
                receipt = RustoreReceipt(**vars(manifest), rustore_version_id=123, publish_type="MANUAL",
                                         partial_value=100, status=status, observed_at="2026-09-23T12:00:00Z")
                receipt.write(root / "rustore-submission.json")
                self.call("write_checksums", root, "v1.2.3")
                if status == "ACTIVE":
                    with self.assertRaises(RuntimeError):
                        self.call("verify_bundle", root, "v1.2.3", SHA, True)
                else:
                    self.call("verify_bundle", root, "v1.2.3", SHA, True)


if __name__ == "__main__":
    unittest.main()
