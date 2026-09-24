from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path

from tool.rustore_release import MANIFEST_FIELDS, ReleaseManifest, RustoreReleaseError, SIGNER_SHA256


PACKAGE_ID = "ru.altparking.driver"
TAG_PATTERN = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)
VERSION_PATTERN = re.compile(
    r"^version:[ \t]*((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\+([1-9][0-9]*)[ \t]*$",
    re.MULTILINE | re.ASCII,
)


class ReleaseValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReleaseMetadata:
    tag: str
    version_name: str
    build_number: int


def parse_pubspec_version(text: str) -> tuple[str, int]:
    matches = list(VERSION_PATTERN.finditer(text))
    if len(matches) != 1:
        raise ReleaseValidationError("pubspec version is missing, malformed, or duplicated")
    return matches[0].group(1), int(matches[0].group(2))


def _previous_manifest(text: str) -> ReleaseManifest:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseValidationError("previous manifest has duplicate fields")
            result[key] = value
        return result

    try:
        fields = json.loads(text, object_pairs_hook=unique_pairs)
    except (ValueError, RecursionError) as error:
        raise ReleaseValidationError("previous manifest is not valid JSON") from error
    if not isinstance(fields, dict) or set(fields) != set(MANIFEST_FIELDS):
        raise ReleaseValidationError("previous manifest must have the exact release schema")
    try:
        manifest = ReleaseManifest(**{name: fields[key] for key, name in MANIFEST_FIELDS.items()})
        manifest.validate()
    except RustoreReleaseError as error:
        raise ReleaseValidationError(f"previous manifest is invalid: {error}") from error
    return manifest


def validate_release(tag: str, pubspec_text: str, previous_manifest_text: str | None) -> ReleaseMetadata:
    if TAG_PATTERN.fullmatch(tag) is None:
        raise ReleaseValidationError("tag is not a valid vMAJOR.MINOR.PATCH release tag")
    version_name, build_number = parse_pubspec_version(pubspec_text)
    if tag != "v" + version_name:
        raise ReleaseValidationError("tag version does not match pubspec version")
    if previous_manifest_text is not None:
        previous = _previous_manifest(previous_manifest_text)
        if build_number <= previous.version_code:
            raise ReleaseValidationError(f"build number {build_number} must exceed {previous.version_code}")
    return ReleaseMetadata(tag, version_name, build_number)


def build_manifest(
    metadata: ReleaseMetadata,
    package_id: str,
    source_sha: str,
    apk_sha256: str,
    signing_certificate_sha256: str,
) -> dict[str, object]:
    if package_id != PACKAGE_ID:
        raise ReleaseValidationError("unexpected Driver package")
    if signing_certificate_sha256 != SIGNER_SHA256:
        raise ReleaseValidationError("unexpected Driver signing certificate")
    manifest = ReleaseManifest(
        application="driver",
        package_name=package_id,
        version_name=metadata.version_name,
        version_code=metadata.build_number,
        source_commit=source_sha,
        source_tag=metadata.tag,
        apk_sha256=apk_sha256,
        signing_certificate_sha256=signing_certificate_sha256,
    )
    try:
        manifest.validate()
    except RustoreReleaseError as error:
        raise ReleaseValidationError(str(error)) from error
    return {key: getattr(manifest, name) for key, name in MANIFEST_FIELDS.items()}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--tag", required=True)
    validate.add_argument("--pubspec", type=Path, required=True)
    validate.add_argument("--previous-manifest", type=Path)
    validate.add_argument("--github-output", type=Path, required=True)
    manifest = commands.add_parser("manifest", allow_abbrev=False)
    manifest.add_argument("--tag", required=True)
    manifest.add_argument("--pubspec", type=Path, required=True)
    history = manifest.add_mutually_exclusive_group(required=True)
    history.add_argument("--previous-manifest", type=Path)
    history.add_argument("--first-release", choices=("NO_PREVIOUS_RELEASE",))
    manifest.add_argument("--package-id", required=True)
    manifest.add_argument("--source-sha", required=True)
    manifest.add_argument("--apk-sha256", required=True)
    manifest.add_argument("--signing-certificate-sha256", required=True)
    manifest.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        pubspec = arguments.pubspec.read_text(encoding="utf-8")
        previous = arguments.previous_manifest.read_text(encoding="utf-8") if arguments.previous_manifest else None
        metadata = validate_release(arguments.tag, pubspec, previous)
        if arguments.command == "validate":
            arguments.github_output.write_text(
                f"version_name={metadata.version_name}\nbuild_number={metadata.build_number}\n", encoding="utf-8"
            )
        else:
            data = build_manifest(
                metadata, arguments.package_id, arguments.source_sha, arguments.apk_sha256,
                arguments.signing_certificate_sha256,
            )
            arguments.output.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ReleaseValidationError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
