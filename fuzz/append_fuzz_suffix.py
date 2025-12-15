#!/usr/bin/env python3

import os
import struct
import sys
import argparse

# This script appends a 1-byte trailer to existing protobuf binary files
# so they can be consumed by the fuzzer in fuzz/fuzz_pb_serializer.cpp.

# The fuzzer's `FuzzedDataProvider` first consumes an integer `choice_options`
# to select the message type to parse. We set this `choice_options` value
# to be the index of the message type in the fuzzer's `message_variant_t`.

def main():
    """
    Main function to process protobuf files and add the fuzzer prefix.
    """
    # --- Configuration ---
    parser = argparse.ArgumentParser(
        description="Append fuzzer-specific trailers to protobuf binary files."
    )
    # The base directory of the repo is the parent of the script's directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    parser.add_argument(
        "--output-dir",
        type=str,
        # Default to a directory inside the fuzz directory
        default=os.path.join(base_dir, "fuzz", "prefixed_corpus"),
        help="Directory where the fuzzer-ready corpus will be saved."
    )
    args = parser.parse_args()

    # Mapping from protobuf message type name to the index in the fuzzer's variant.
    # See `message_variant_t` in `fuzz/fuzz_pb_serializer.cpp`.
    message_type_map = {
        "proto3_unittest.TestAllTypes": 0,
        "protobuf_unittest.TestAllTypes": 1,
        "protobuf_unittest.TestMap": 2,
    }

    # Directory containing the source .binpb files
    source_dir = os.path.join(base_dir, "tests", "data")

    # Directory where the new fuzzer-ready corpus will be saved
    output_dir = args.output_dir

    # --- Execution ---

    print(f"Source directory: {source_dir}")
    print(f"Output directory: {output_dir}")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory.")

    # Map filename to its corresponding message type index
    file_to_index_map = {
        "proto3_unittest.TestAllTypes.binpb": message_type_map["proto3_unittest.TestAllTypes"],
        "protobuf_unittest.TestAllTypes.binpb": message_type_map["protobuf_unittest.TestAllTypes"],
        "protobuf_unittest.TestMap.binpb": message_type_map["protobuf_unittest.TestMap"],
    }

    print("\nProcessing files (appending type index as trailing byte)...")
    processed_count = 0
    for filename, type_index in file_to_index_map.items():
        source_path = os.path.join(source_dir, filename)
        output_path = os.path.join(output_dir, filename)

        if not os.path.exists(source_path):
            print(f"  - WARNING: Source file not found, skipping: {source_path}", file=sys.stderr)
            continue

        try:
            # Read the original binary protobuf data
            with open(source_path, "rb") as f:
                protobuf_data = f.read()

            # Pack the type index as a 1-byte unsigned integer.
            # This will be consumed by `provider.ConsumeIntegralInRange<unsigned>(...)`
            # which reads from the end of the buffer first.
            suffix = struct.pack("<B", type_index)  # <B means little-endian unsigned char (uint8_t)

            # Write the new file with the original data followed by the suffix
            with open(output_path, "wb") as f:
                f.write(protobuf_data)
                f.write(suffix)

            # Determine the relative path for cleaner logging
            try:
                rel_path = os.path.relpath(output_path, base_dir)
            except ValueError:
                rel_path = output_path # Handle cases where paths are on different drives (Windows)
            print(f"  - Created {rel_path} (type index: {type_index})")
            processed_count += 1

        except Exception as e:
            print(f"  - ERROR: Could not process {source_path}: {e}", file=sys.stderr)

    print(f"\nSuccessfully processed {processed_count} files.")

if __name__ == "__main__":
    main()
