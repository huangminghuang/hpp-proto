#!/usr/bin/env python3

import argparse
import os
import sys

# This script generates fuzzer seed corpora by appending a 1-byte `choice_options`
# to existing test inputs under `tests/data/`.
#
# - For binpb fuzzing (`fuzz/fuzz_binpb.cpp`), the input is:
#     [binpb bytes...][choice_options: uint8]
#   where choice_options is in [0, variant_size*2-1] (message type + split flag). This script generates only
#   the non-split variants (choice_options == message type index).
#
# - For json fuzzing (`fuzz/fuzz_json.cpp`), the input is:
#     [json bytes...][choice_options: uint8]
#   where choice_options is in [0, variant_size-1] (message type only).

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_bytes_or_warn(path: str) -> bytes | None:
    if not os.path.exists(path):
        print(f"  - WARNING: Source file not found, skipping: {path}", file=sys.stderr)
        return None
    with open(path, "rb") as f:
        return f.read()


def write_seed(out_path: str, choice: int, payload: bytes) -> None:
  if not (0 <= choice <= 255):
    raise ValueError("choice_options must fit in uint8")
  with open(out_path, "wb") as f:
    f.write(payload)
    f.write(bytes([choice]))


def generate_seed_corpus(
    *,
    format_name: str,
    ext: str,
    output_root: str,
    source_dir: str,
    message_type_map: dict[str, int],
) -> int:
    out_dir = os.path.join(output_root, f"{format_name}_seed_corpus")
    ensure_dir(out_dir)
    print(f"\nGenerating {format_name} seed corpus: {out_dir}")

    count = 0
    for message_type, type_index in message_type_map.items():
        filename = f"{message_type}.{ext}"
        source_path = os.path.join(source_dir, filename)
        payload = read_bytes_or_warn(source_path)
        if payload is None:
            continue
        out_path = os.path.join(out_dir, filename)
        write_seed(out_path, type_index, payload)
        count += 1
    return count


def main() -> int:
    # --- Configuration ---
    parser = argparse.ArgumentParser(
        description="Generate fuzzer seed corpora by prefixing choice options."
    )
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    parser.add_argument(
        "--output-root",
        type=str,
        default=os.path.join(base_dir, "fuzz", "prefixed_corpus"),
        help="Output root where *seed_corpus directories will be created.",
    )
    parser.add_argument(
        "--formats",
        type=str,
        default="binpb,json",
        help="Comma-separated list: binpb,json",
    )
    args = parser.parse_args()

    # Mapping from protobuf message type name to the index in the fuzzer's variant.
    # See `message_variant_t` in `fuzz/fuzz_binpb.cpp` and `fuzz/fuzz_json.cpp`.
    message_type_map = {
        "proto3_unittest.TestAllTypes": 0,
        "protobuf_unittest.TestAllTypes": 1,
        "protobuf_unittest.TestMap": 2,
    }
    source_dir = os.path.join(base_dir, "tests", "data")

    # --- Execution ---

    print(f"Source directory: {source_dir}")
    print(f"Output root: {args.output_root}")

    formats = {f.strip() for f in args.formats.split(",") if f.strip()}
    unknown = formats - {"binpb", "json"}
    if unknown:
        print(f"ERROR: Unknown formats: {sorted(unknown)}", file=sys.stderr)
        return 2

    processed_count = 0

    if "binpb" in formats:
        processed_count += generate_seed_corpus(
            format_name="binpb",
            ext="binpb",
            output_root=args.output_root,
            source_dir=source_dir,
            message_type_map=message_type_map,
        )

    if "json" in formats:
        processed_count += generate_seed_corpus(
            format_name="json",
            ext="json",
            output_root=args.output_root,
            source_dir=source_dir,
            message_type_map=message_type_map,
        )

    print(f"\nSuccessfully generated {processed_count} seed files.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
