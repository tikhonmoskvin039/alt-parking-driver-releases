from __future__ import annotations

import argparse
import os
from collections.abc import Mapping, Sequence
from pathlib import Path


def _unicode_escape(character: str) -> str:
    code_point = ord(character)
    if code_point <= 0xFFFF:
        return f"\\u{code_point:04X}"
    code_point -= 0x10000
    high = 0xD800 + (code_point >> 10)
    low = 0xDC00 + (code_point & 0x3FF)
    return f"\\u{high:04X}\\u{low:04X}"


def _escape(value: str, *, key: bool) -> str:
    result: list[str] = []
    for index, character in enumerate(value):
        if character == " ":
            result.append("\\ " if key or index == 0 else " ")
        elif character == "\\":
            result.append("\\\\")
        elif character == "\t":
            result.append("\\t")
        elif character == "\n":
            result.append("\\n")
        elif character == "\r":
            result.append("\\r")
        elif character == "\f":
            result.append("\\f")
        elif character in "=:#!":
            result.append("\\" + character)
        elif 0x20 <= ord(character) <= 0x7E:
            result.append(character)
        else:
            result.append(_unicode_escape(character))
    return "".join(result)


def serialize_properties(properties: Mapping[str, str]) -> str:
    return "".join(f"{_escape(name, key=True)}={_escape(value, key=False)}\n" for name, value in properties.items())


def _write_private_properties(path: Path, properties: Mapping[str, str]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as output:
            descriptor = -1
            output.write(serialize_properties(properties))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.chmod(path, 0o600)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    signing = commands.add_parser("android-signing")
    signing.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "android-signing":
        properties = {
            "storeFile": os.environ["KEYSTORE_PATH"],
            "storePassword": os.environ["ANDROID_STORE_PASSWORD"],
            "keyAlias": os.environ["ANDROID_KEY_ALIAS"],
            "keyPassword": os.environ["ANDROID_KEY_PASSWORD"],
        }
        _write_private_properties(arguments.output, properties)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
