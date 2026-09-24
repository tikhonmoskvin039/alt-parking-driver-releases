from __future__ import annotations

import argparse
import json
from collections.abc import Iterable, Sequence
from pathlib import Path


class ReleaseStateError(RuntimeError):
    pass


def select_release_state(tag: str, pages: Iterable[object], *, expected_assets: Sequence[str] | None = None) -> str:
    if not isinstance(expected_assets, Sequence) or isinstance(expected_assets, (str, bytes)) or not expected_assets:
        raise ReleaseStateError("a nonempty expected asset allowlist is required")
    expected_names: set[str] = set()
    for name in expected_assets:
        if not isinstance(name, str) or not name or Path(name).name != name or name in expected_names:
            raise ReleaseStateError("expected asset name is invalid or duplicated")
        expected_names.add(name)
    matches: list[dict[str, object]] = []
    seen_ids: set[int] = set()
    for page in pages:
        if not isinstance(page, list):
            raise ReleaseStateError("release API page must be a JSON array")
        for item in page:
            if not isinstance(item, dict):
                raise ReleaseStateError("release API item must be a JSON object")
            release_id = item.get("id")
            if type(release_id) is not int or release_id <= 0:
                raise ReleaseStateError("release API id must be a positive integer")
            if release_id in seen_ids:
                raise ReleaseStateError("pagination returned duplicate release id")
            seen_ids.add(release_id)
            release_tag = item.get("tag_name")
            if not isinstance(release_tag, str) or not release_tag:
                raise ReleaseStateError("release API tag_name must be a string")
            if release_tag == tag:
                matches.append(item)
    if len(matches) > 1:
        raise ReleaseStateError("multiple releases match tag")
    if not matches:
        return "absent"

    release = matches[0]
    draft, prerelease, assets = release.get("draft"), release.get("prerelease"), release.get("assets")
    if type(draft) is not bool or type(prerelease) is not bool or prerelease:
        raise ReleaseStateError("matching release has unexpected status")
    if not isinstance(assets, list):
        raise ReleaseStateError("matching release assets must be an array")
    seen_asset_ids: set[int] = set()
    seen_asset_names: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            raise ReleaseStateError("release asset must be an object")
        asset_id, name, state = asset.get("id"), asset.get("name"), asset.get("state")
        if type(asset_id) is not int or asset_id <= 0 or asset_id in seen_asset_ids:
            raise ReleaseStateError("release asset id is invalid or duplicated")
        if not isinstance(name, str) or not name or name in seen_asset_names or Path(name).name != name:
            raise ReleaseStateError("release asset name is invalid or duplicated")
        if state != "uploaded":
            raise ReleaseStateError("release asset status is unexpected")
        seen_asset_ids.add(asset_id)
        seen_asset_names.add(name)
    if draft:
        raise ReleaseStateError("existing draft cannot be reused without proven ownership")
    if seen_asset_names != expected_names:
        raise ReleaseStateError("published release has unexpected assets")
    return "published"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    select = commands.add_parser("select")
    select.add_argument("--tag", required=True)
    select.add_argument("--expected-asset", action="append", required=True)
    select.add_argument("pages", type=Path, nargs="+")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        pages = [json.loads(path.read_text(encoding="utf-8")) for path in arguments.pages]
        state = select_release_state(arguments.tag, pages, expected_assets=arguments.expected_asset)
    except (OSError, json.JSONDecodeError, ReleaseStateError) as error:
        parser.error(str(error))
    print(state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
