#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess  # nosec B404
import sys
import tempfile
import threading
import time
from pathlib import Path


def _drain_stream(stream, buffer: list[str]) -> None:
    for line in iter(stream.readline, ""):
        buffer.append(line)
    stream.close()

def _resolve_executable(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as ex:
        raise ValueError(f"{label} binary not found: {path}") from ex
    if not resolved.is_file():
        raise ValueError(f"{label} binary is not a file: {resolved}")
    if not os.access(resolved, os.X_OK):
        raise ValueError(f"{label} binary is not executable: {resolved}")
    return resolved

def _validate_args(args: list[str]) -> list[str]:
    normalized: list[str] = []
    for arg in args:
        text = str(arg)
        if "\x00" in text:
            raise ValueError("invalid argument contains NUL byte")
        normalized.append(text)
    return normalized


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "Usage: run_grpc_test.py <server-binary> <client-binary> [client-args...]",
            file=sys.stderr,
        )
        return 1

    try:
        server_bin = _resolve_executable(Path(sys.argv[1]), "server")
        client_bin = _resolve_executable(Path(sys.argv[2]), "client")
        client_args = _validate_args(sys.argv[3:])
    except ValueError as ex:
        print(f"Invalid command arguments: {ex}", file=sys.stderr)
        return 1

    with tempfile.NamedTemporaryFile(delete=False) as port_tmp:
        port_file = Path(port_tmp.name)

    server_cmd = [str(server_bin), str(port_file)]
    server_proc = subprocess.Popen(  # nosec B603
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        text=True,
        universal_newlines=True,
    )

    output: list[str] = []
    reader = threading.Thread(
        target=_drain_stream, args=(server_proc.stdout, output), daemon=True
    )
    reader.start()

    target_phrase = "grpc_test_server listening on"
    ready = False
    start_time = time.time()
    while time.time() - start_time < 10:
        if server_proc.poll() is not None:
            break
        if any(target_phrase in line for line in output):
            ready = True
            break
        time.sleep(0.05)

    if not ready:
        server_proc.terminate()
        server_proc.wait(timeout=5)
        print("Server failed to start", file=sys.stderr)
        print("".join(output), file=sys.stderr)
        port_file.unlink(missing_ok=True)
        return 1

    try:
        endpoint = port_file.read_text().strip()
    except OSError as ex:
        print(f"Failed to read port file: {ex}", file=sys.stderr)
        port_file.unlink(missing_ok=True)
        return 1

    env = os.environ.copy()
    env["HPP_PROTO_GRPC_TEST_ENDPOINT"] = endpoint
    client_cmd = [str(client_bin), *client_args]
    try:
        client_result = subprocess.run(client_cmd, env=env, check=False, shell=False)  # nosec B603
        return_code = client_result.returncode
    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait(timeout=5)
        port_file.unlink(missing_ok=True)

    if return_code != 0:
        print("Client exited with non-zero status", file=sys.stderr)
        print("".join(output), file=sys.stderr)
    return return_code


if __name__ == "__main__":
    sys.exit(main())
