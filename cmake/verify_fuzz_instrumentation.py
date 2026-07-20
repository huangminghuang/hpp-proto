#!/usr/bin/env python3
"""Verify sanitizer coverage for every object-producing standalone fuzz target."""

from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path


EXPECTED_SOURCES = {
    "fuzz/common.cpp",
    "fuzz/json_extern.cpp",
    "fuzz/binpb_extern.cpp",
    "fuzz/fuzz_binpb.cpp",
    "fuzz/fuzz_json.cpp",
    "fuzz/fuzz_descriptor.cpp",
    "src/dynamic_message/factory.cpp",
}
IS_UTF8_SUFFIX = "/src/is_utf8.cpp"
REQUIRED_FLAGS = {
    "-fsanitize=fuzzer-no-link,address,undefined",
    "-fno-sanitize-recover=all",
}


def command_arguments(entry: dict[str, object]) -> list[str]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list):
        return [str(argument) for argument in arguments]
    command = entry.get("command")
    if isinstance(command, str):
        return shlex.split(command)
    raise ValueError(f"compile command has neither arguments nor command: {entry!r}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <compile_commands.json>", file=sys.stderr)
        return 2

    compile_commands_path = Path(sys.argv[1])
    entries = json.loads(compile_commands_path.read_text(encoding="utf-8"))
    source_root = Path(__file__).resolve().parent.parent
    required = {str((source_root / source).resolve()): source for source in EXPECTED_SOURCES}
    matched: set[str] = set()
    errors: list[str] = []

    for entry in entries:
        source = str(Path(str(entry["file"])).resolve())
        display_name = required.get(source)
        if display_name is None and source.replace("\\", "/").endswith(IS_UTF8_SUFFIX):
            display_name = "is_utf8/src/is_utf8.cpp"
        if display_name is None:
            continue

        matched.add(display_name)
        arguments = set(command_arguments(entry))
        missing = sorted(REQUIRED_FLAGS - arguments)
        if missing:
            errors.append(f"{display_name}: missing {' '.join(missing)}")

    expected_names = set(EXPECTED_SOURCES) | {"is_utf8/src/is_utf8.cpp"}
    for missing_source in sorted(expected_names - matched):
        errors.append(f"{missing_source}: no compile command found")

    if errors:
        print("standalone fuzz instrumentation verification failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"verified standalone fuzz instrumentation for {len(matched)} translation units")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
