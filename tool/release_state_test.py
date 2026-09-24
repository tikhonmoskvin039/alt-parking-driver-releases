from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tool.release_state import ReleaseStateError, select_release_state


ROOT = Path(__file__).parent.parent


def release(identity: int, tag: str, *, draft: bool, assets: list[dict[str, object]] | None = None, prerelease: bool = False) -> dict[str, object]:
    return {"id": identity, "tag_name": tag, "draft": draft, "prerelease": prerelease, "assets": [] if assets is None else assets}


class ReleaseStateTest(unittest.TestCase):
    def test_selects_absent_and_published_across_pages(self) -> None:
        first = [release(1, "v0.1.9", draft=False)]
        self.assertEqual(select_release_state("v0.1.10", [first], expected_assets=("driver.apk",)), "absent")
        self.assertEqual(select_release_state("v0.1.10", [[release(2, "v0.1.10", draft=False, assets=[{"id": 3, "name": "driver.apk", "state": "uploaded"}])]], expected_assets=("driver.apk",)), "published")

    def test_rejects_duplicate_ids_tags_and_asset_names(self) -> None:
        bad_pages = (
            [[release(1, "v0.1.9", draft=False)], [release(1, "v0.1.10", draft=True)]],
            [[release(1, "v0.1.10", draft=True)], [release(2, "v0.1.10", draft=False)]],
            [[release(1, "v0.1.10", draft=False, assets=[{"id": 3, "name": "driver.apk", "state": "uploaded"}, {"id": 4, "name": "driver.apk", "state": "uploaded"}])]],
            [[release(1, "v0.1.10", draft=False, assets=[{"id": 3, "name": "driver.apk", "state": "uploaded"}, {"id": 3, "name": "manifest.json", "state": "uploaded"}])]],
        )
        for pages in bad_pages:
            with self.subTest(pages=pages), self.assertRaises(ReleaseStateError):
                select_release_state("v0.1.10", pages, expected_assets=("driver.apk", "manifest.json"))

    def test_rejects_unsafe_draft_reuse_and_unexpected_assets(self) -> None:
        for item in (
            release(1, "v0.1.10", draft=True),
            release(1, "v0.1.10", draft=True, assets=[{"id": 3, "name": "old.apk", "state": "uploaded"}]),
            release(1, "v0.1.10", draft=False, assets=[{"id": 3, "name": "old.apk", "state": "uploaded"}]),
            release(1, "v0.1.10", draft=False, assets=[]),
        ):
            with self.subTest(item=item), self.assertRaises(ReleaseStateError):
                select_release_state("v0.1.10", [[item]], expected_assets=("driver.apk",))

    def test_rejects_malformed_or_prerelease_status(self) -> None:
        for pages in (
            {"items": []},
            [["not an object"]],
            [[release(True, "v0.1.10", draft=True)]],
            [[{**release(1, "v0.1.10", draft=True), "draft": "true"}]],
            [[{**release(1, "v0.1.10", draft=True), "prerelease": "false"}]],
            [[release(1, "v0.1.10", draft=False, prerelease=True)]],
            [[{**release(1, "v0.1.10", draft=True), "assets": "none"}]],
            [[release(1, "v0.1.10", draft=False, assets=[{"id": 3, "name": "driver.apk", "state": "starter"}])]],
        ):
            with self.subTest(pages=pages), self.assertRaises(ReleaseStateError):
                select_release_state("v0.1.10", pages, expected_assets=("driver.apk",))

    def test_requires_nonempty_valid_asset_allowlist(self) -> None:
        pages = [[release(1, "v0.1.10", draft=False,
                          assets=[{"id": 3, "name": "unrelated.apk", "state": "uploaded"}])]]
        with self.subTest(expected="omitted"), self.assertRaises(ReleaseStateError):
            select_release_state("v0.1.10", pages)
        for expected in (None, (), [], "driver.apk", ("",), ("driver.apk", "driver.apk")):
            with self.subTest(expected=expected), self.assertRaises(ReleaseStateError):
                select_release_state("v0.1.10", [[]], expected_assets=expected)
        with self.assertRaises(ReleaseStateError):
            select_release_state("v0.1.10", pages, expected_assets=("driver.apk",))

    def test_cli_selects_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            page = Path(directory) / "page.json"
            page.write_text(json.dumps([release(1, "v0.1.9", draft=False)]), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "tool.release_state", "select", "--tag", "v0.1.10",
                 "--expected-asset", "driver.apk", str(page)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "absent\n")

    def test_cli_rejects_missing_allowlist_unrelated_assets_and_existing_drafts(self) -> None:
        for draft, name, options in (
            (False, "unrelated.apk", []),
            (False, "unrelated.apk", ["--expected-asset", "driver.apk"]),
            (False, "driver.apk", ["--expected-asset", ""]),
            (True, None, ["--expected-asset", "driver.apk"]),
        ):
            with self.subTest(draft=draft, name=name, options=options), tempfile.TemporaryDirectory() as directory:
                page = Path(directory) / "page.json"
                assets = [] if name is None else [{"id": 3, "name": name, "state": "uploaded"}]
                page.write_text(json.dumps([release(1, "v0.1.10", draft=draft, assets=assets)]), encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, "-m", "tool.release_state", "select", "--tag", "v0.1.10", *options, str(page)],
                    cwd=ROOT, capture_output=True, text=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
