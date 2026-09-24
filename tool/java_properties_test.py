from __future__ import annotations

import contextlib
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tool.java_properties import main, serialize_properties


class JavaPropertiesTest(unittest.TestCase):
    def test_escapes_key_separators_whitespace_and_unicode_values(self) -> None:
        self.assertEqual(
            serialize_properties({" store:file": " leading\\path:=#!\t\n\r\f🙂é", "alias": "водитель"}),
            "\\ store\\:file=\\ leading\\\\path\\:\\=\\#\\!\\t\\n\\r\\f\\uD83D\\uDE42\\u00E9\n"
            "alias=\\u0432\\u043E\\u0434\\u0438\\u0442\\u0435\\u043B\\u044C\n",
        )

    def test_android_signing_writes_only_private_properties_and_no_output(self) -> None:
        env = {
            "KEYSTORE_PATH": " C:\\driver\\release.jks",
            "ANDROID_STORE_PASSWORD": " secret:=пароль",
            "ANDROID_KEY_ALIAS": "driver:key",
            "ANDROID_KEY_PASSWORD": " line\nsecret",
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "key.properties"
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, env), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(main(["android-signing", "--output", str(output)]), 0)
            self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
            self.assertEqual(
                output.read_text(encoding="ascii"),
                "storeFile=\\ C\\:\\\\driver\\\\release.jks\n"
                "storePassword=\\ secret\\:\\=\\u043F\\u0430\\u0440\\u043E\\u043B\\u044C\n"
                "keyAlias=driver\\:key\n"
                "keyPassword=\\ line\\nsecret\n",
            )
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_android_signing_does_not_overwrite_an_existing_properties_file(self) -> None:
        env = {"KEYSTORE_PATH": "store.jks", "ANDROID_STORE_PASSWORD": "secret", "ANDROID_KEY_ALIAS": "driver", "ANDROID_KEY_PASSWORD": "secret"}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "key.properties"
            output.write_text("existing private material\n", encoding="ascii")
            with patch.dict(os.environ, env), self.assertRaises(FileExistsError):
                main(["android-signing", "--output", str(output)])
            self.assertEqual(output.read_text(encoding="ascii"), "existing private material\n")


if __name__ == "__main__":
    unittest.main()
