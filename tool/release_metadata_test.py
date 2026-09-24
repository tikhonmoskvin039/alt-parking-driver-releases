from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tool.release_metadata import (
    ReleaseValidationError,
    build_manifest,
    parse_pubspec_version,
    validate_release,
)


ROOT = Path(__file__).parent.parent
SIGNER = "E0BEBA119BAA0F69D988495744D3BE2F531AC729656B1B4A05560B2EEB0CE414"
SOURCE = "a" * 40
APK = "b" * 64
MANIFEST = {
    "application": "driver",
    "packageName": "ru.altparking.driver",
    "versionName": "0.1.10",
    "versionCode": 17,
    "sourceCommit": SOURCE,
    "sourceTag": "v0.1.10",
    "apkSha256": APK,
    "signingCertificateSha256": SIGNER,
}


class ReleaseMetadataTest(unittest.TestCase):
    def _assert_driver_repository_identity(self, pubspec: str) -> None:
        version_name, build_number = parse_pubspec_version(pubspec)
        metadata = validate_release(f"v{version_name}", pubspec, None)
        self.assertEqual(
            (metadata.tag, metadata.version_name, metadata.build_number),
            (f"v{version_name}", version_name, build_number),
        )
        self.assertGreaterEqual(build_number, 17)
        gradle = (ROOT / "android/app/build.gradle.kts").read_text(encoding="utf-8")
        self.assertIn('applicationId = "ru.altparking.driver"', gradle)
        self.assertIn(SIGNER, gradle)

    def test_repository_identity_matches_production_android(self) -> None:
        self._assert_driver_repository_identity((ROOT / "pubspec.yaml").read_text(encoding="utf-8"))

    def test_repository_identity_accepts_next_release(self) -> None:
        pubspec = "name: altparking_driver\nversion: 0.1.11+18\n"
        self._assert_driver_repository_identity(pubspec)
        metadata = validate_release("v0.1.11", pubspec, json.dumps(MANIFEST))
        self.assertEqual((metadata.tag, metadata.version_name, metadata.build_number), ("v0.1.11", "0.1.11", 18))

    def test_validates_tag_and_increasing_version_code(self) -> None:
        prior = {**MANIFEST, "versionName": "0.1.9", "versionCode": 16, "sourceTag": "v0.1.9"}
        metadata = validate_release("v0.1.10", "name: altparking_driver\nversion: 0.1.10+17\n", json.dumps(prior))
        self.assertEqual((metadata.tag, metadata.version_name, metadata.build_number), ("v0.1.10", "0.1.10", 17))

    def test_rejects_invalid_tag_version_and_build(self) -> None:
        for tag, pubspec in (
            ("0.1.10", "version: 0.1.10+17\n"),
            ("v01.1.10", "version: 01.1.10+17\n"),
            ("v0.1.10-extra", "version: 0.1.10+17\n"),
            ("v0.1.11", "version: 0.1.10+17\n"),
            ("v0.1.10", "version: 0.1.10+0\n"),
            ("v0.1.10", "version: 0.1.10+17.0\n"),
        ):
            with self.subTest(tag=tag, pubspec=pubspec), self.assertRaises(ReleaseValidationError):
                validate_release(tag, pubspec, None)

    def test_rejects_nonincreasing_or_malformed_prior_manifest(self) -> None:
        for prior in (
            {**MANIFEST, "versionCode": 17},
            {**MANIFEST, "versionCode": 18},
            {**MANIFEST, "versionCode": True},
            {**MANIFEST, "packageName": "ru.altparking.guard"},
            {**MANIFEST, "extra": "field"},
            {key: value for key, value in MANIFEST.items() if key != "sourceCommit"},
        ):
            with self.subTest(prior=prior), self.assertRaises(ReleaseValidationError):
                validate_release("v0.1.11", "version: 0.1.11+17\n", json.dumps(prior))
        with self.assertRaises(ReleaseValidationError):
            validate_release("v0.1.11", "version: 0.1.11+18\n", "not json")

    def test_builds_exact_immutable_manifest(self) -> None:
        metadata = validate_release("v0.1.10", "version: 0.1.10+17\n", None)
        self.assertEqual(build_manifest(metadata, "ru.altparking.driver", SOURCE, APK, SIGNER), MANIFEST)

    def test_rejects_other_identity_and_bad_hashes(self) -> None:
        metadata = validate_release("v0.1.10", "version: 0.1.10+17\n", None)
        for package, source, apk, signer in (
            ("ru.altparking.guard", SOURCE, APK, SIGNER),
            ("ru.altparking.driver", "A" * 40, APK, SIGNER),
            ("ru.altparking.driver", "a" * 39, APK, SIGNER),
            ("ru.altparking.driver", SOURCE, "B" * 64, SIGNER),
            ("ru.altparking.driver", SOURCE, "b" * 63, SIGNER),
            ("ru.altparking.driver", SOURCE, APK, "0" * 64),
        ):
            with self.subTest(package=package, source=source, apk=apk, signer=signer), self.assertRaises(ReleaseValidationError):
                build_manifest(metadata, package, source, apk, signer)

    def test_cli_outputs_validate_metadata_and_deterministic_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pubspec = root / "pubspec.yaml"
            output = root / "github-output"
            manifest = root / "release-manifest.json"
            pubspec.write_text("version: 0.1.10+17\n", encoding="utf-8")
            validation = subprocess.run(
                [sys.executable, "-m", "tool.release_metadata", "validate", "--tag", "v0.1.10", "--pubspec", str(pubspec), "--github-output", str(output)],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(validation.returncode, 0, validation.stderr)
            self.assertEqual(output.read_text(encoding="utf-8"), "version_name=0.1.10\nbuild_number=17\n")
            creation = subprocess.run(
                [sys.executable, "-m", "tool.release_metadata", "manifest", "--tag", "v0.1.10", "--pubspec", str(pubspec),
                 "--package-id", "ru.altparking.driver", "--source-sha", SOURCE, "--apk-sha256", APK,
                 "--signing-certificate-sha256", SIGNER, "--output", str(manifest),
                 "--first-release", "NO_PREVIOUS_RELEASE"],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(creation.returncode, 0, creation.stderr)
            self.assertEqual(manifest.read_text(encoding="utf-8"), json.dumps(MANIFEST, indent=2, sort_keys=True) + "\n")

    def _manifest_cli(self, root: Path, *options: str) -> subprocess.CompletedProcess[str]:
        pubspec = root / "pubspec.yaml"
        pubspec.write_text("version: 0.1.10+17\n", encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-m", "tool.release_metadata", "manifest", "--tag", "v0.1.10",
             "--pubspec", str(pubspec), "--package-id", "ru.altparking.driver", "--source-sha", SOURCE,
             "--apk-sha256", APK, "--signing-certificate-sha256", SIGNER,
             "--output", str(root / "release-manifest.json"), *options],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )

    def test_manifest_cli_requires_explicit_release_history(self) -> None:
        for options in ((), ("--first-release",), ("--first-release", "true"),
                        ("--first", "NO_PREVIOUS_RELEASE")):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result = self._manifest_cli(root, *options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "release-manifest.json").exists())

    def test_manifest_cli_rejects_nonincreasing_build_without_writing(self) -> None:
        for prior_build in (17, 18):
            with self.subTest(prior_build=prior_build), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                previous = root / "previous.json"
                previous.write_text(json.dumps({**MANIFEST, "versionCode": prior_build}), encoding="utf-8")
                result = self._manifest_cli(root, "--previous-manifest", str(previous))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must exceed", result.stderr)
                self.assertFalse((root / "release-manifest.json").exists())

    def test_manifest_cli_validates_exact_previous_schema(self) -> None:
        prior = {**MANIFEST, "versionCode": 16}
        for text in (
            json.dumps({**prior, "extra": "field"}),
            json.dumps({key: value for key, value in prior.items() if key != "sourceCommit"}),
            json.dumps(prior)[:-1] + ', "versionCode": 15}',
            json.dumps({**prior, "sourceCommit": "A" * 40}),
            json.dumps({**prior, "signingCertificateSha256": "0" * 64}),
        ):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                previous = root / "previous.json"
                previous.write_text(text, encoding="utf-8")
                result = self._manifest_cli(root, "--previous-manifest", str(previous))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("previous manifest", result.stderr)
                self.assertFalse((root / "release-manifest.json").exists())

    def test_manifest_cli_accepts_increase_and_rejects_conflicting_first_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = root / "previous.json"
            previous.write_text(json.dumps({**MANIFEST, "versionCode": 16}), encoding="utf-8")
            conflict = self._manifest_cli(root, "--previous-manifest", str(previous),
                                          "--first-release", "NO_PREVIOUS_RELEASE")
            self.assertNotEqual(conflict.returncode, 0)
            self.assertFalse((root / "release-manifest.json").exists())
            result = self._manifest_cli(root, "--previous-manifest", str(previous))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((root / "release-manifest.json").read_text(encoding="utf-8")), MANIFEST)


if __name__ == "__main__":
    unittest.main()
