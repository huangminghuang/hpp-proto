#!/usr/bin/env python3
"""Run clang-tidy on translation units impacted by changed files.

This script combines git diff + CMake compile database + Ninja dependency data.
For changed headers, it finds impacted object targets from `ninja -t deps` and maps
those targets back to source files via `compile_commands.json`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx"}
HEADER_EXTS = {".h", ".hh", ".hpp", ".hxx"}


def run_cmd(cmd: List[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=check,
        text=True,
        capture_output=True,
    )


def repo_root() -> Path:
    proc = run_cmd(["git", "rev-parse", "--show-toplevel"])
    return Path(proc.stdout.strip()).resolve()


def changed_files(base_ref: str, root: Path) -> Tuple[List[Path], List[Path]]:
    proc = run_cmd(["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base_ref}...HEAD"], cwd=root)
    srcs: List[Path] = []
    hdrs: List[Path] = []
    for rel in proc.stdout.splitlines():
        rel = rel.strip()
        if not rel:
            continue
        p = (root / rel).resolve()
        ext = p.suffix.lower()
        if ext in SOURCE_EXTS:
            srcs.append(p)
        elif ext in HEADER_EXTS:
            hdrs.append(p)
    return srcs, hdrs


def load_compile_db(build_dir: Path) -> Dict[Path, Path]:
    db = build_dir / "compile_commands.json"
    if not db.exists():
        raise FileNotFoundError(
            f"Missing {db}. Configure with CMake and -DCMAKE_EXPORT_COMPILE_COMMANDS=ON."
        )

    with db.open("r", encoding="utf-8") as f:
        entries = json.load(f)

    output_to_source: Dict[Path, Path] = {}
    for entry in entries:
        directory = Path(entry["directory"]).resolve()
        src = Path(entry["file"])
        if not src.is_absolute():
            src = (directory / src).resolve()
        else:
            src = src.resolve()

        output = entry.get("output")
        if output:
            out = Path(output)
            if not out.is_absolute():
                out = (directory / out).resolve()
            else:
                out = out.resolve()
            output_to_source[out] = src
            continue

        command = entry.get("command")
        if command:
            parsed = shlex.split(command)
            for i, token in enumerate(parsed):
                if token == "-o" and i + 1 < len(parsed):
                    out = Path(parsed[i + 1])
                    if not out.is_absolute():
                        out = (directory / out).resolve()
                    else:
                        out = out.resolve()
                    output_to_source[out] = src
                    break

    return output_to_source


def parse_ninja_deps(build_dir: Path) -> Dict[Path, Set[Path]]:
    proc = run_cmd(["ninja", "-C", str(build_dir), "-t", "deps"])
    target_deps: Dict[Path, Set[Path]] = {}
    current_target: Path | None = None

    target_re = re.compile(r"^(.*?):\s+#deps\s+\d+,")
    for raw in proc.stdout.splitlines():
        line = raw.rstrip("\n")
        m = target_re.match(line)
        if m:
            target = Path(m.group(1).strip())
            if not target.is_absolute():
                target = (build_dir / target).resolve()
            else:
                target = target.resolve()
            current_target = target
            target_deps.setdefault(current_target, set())
            continue

        if current_target is None:
            continue

        dep = line.strip()
        if not dep:
            continue
        dep_path = Path(dep)
        if not dep_path.is_absolute():
            dep_path = (build_dir / dep_path).resolve()
        else:
            dep_path = dep_path.resolve()
        target_deps[current_target].add(dep_path)

    return target_deps


def to_rel_or_abs(path: Path, root: Path) -> Tuple[Path | None, Path]:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = None
    return rel, path


def impacted_sources_for_headers(
    changed_headers: Iterable[Path],
    target_deps: Dict[Path, Set[Path]],
    output_to_source: Dict[Path, Path],
    root: Path,
) -> Set[Path]:
    changed_header_set: Set[Path] = set(changed_headers)
    changed_rel_set: Set[Path] = set()
    for h in changed_header_set:
        rel, _ = to_rel_or_abs(h, root)
        if rel is not None:
            changed_rel_set.add(rel)

    impacted: Set[Path] = set()
    for target, deps in target_deps.items():
        hit = False
        for dep in deps:
            if dep in changed_header_set:
                hit = True
                break
            rel, _ = to_rel_or_abs(dep, root)
            if rel is not None and rel in changed_rel_set:
                hit = True
                break

        if not hit:
            continue

        src = output_to_source.get(target)
        if src is not None and src.suffix.lower() in SOURCE_EXTS:
            impacted.add(src)

    return impacted


def run_clang_tidy(
    files: List[Path],
    build_dir: Path,
    root: Path,
    clang_tidy_bin: str,
    warnings_as_errors: bool,
) -> int:
    failures = 0
    for src in files:
        rel = src
        try:
            rel = src.relative_to(root)
        except ValueError:
            pass

        cmd = [clang_tidy_bin, "-p", str(build_dir)]
        if warnings_as_errors:
            cmd.append("--warnings-as-errors=*")
        cmd.append(str(rel))

        print(f"[clang-tidy] {' '.join(shlex.quote(c) for c in cmd)}")
        proc = subprocess.run(cmd, cwd=str(root), text=True)
        if proc.returncode != 0:
            failures += 1
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main", help="Git base ref used for diff (default: origin/main)")
    parser.add_argument("--build-dir", default="build", help="CMake build directory (default: build)")
    parser.add_argument("--clang-tidy", default="clang-tidy", help="clang-tidy binary name/path")
    parser.add_argument("--dry-run", action="store_true", help="Print impacted files without running clang-tidy")
    parser.add_argument(
        "--no-warnings-as-errors",
        action="store_true",
        help="Do not pass --warnings-as-errors=* to clang-tidy",
    )
    args = parser.parse_args()

    root = repo_root()
    build_dir = Path(args.build_dir)
    if not build_dir.is_absolute():
        build_dir = (root / build_dir).resolve()

    if not build_dir.exists():
        print(f"Build directory not found: {build_dir}", file=sys.stderr)
        return 2

    changed_srcs, changed_hdrs = changed_files(args.base, root)

    if not changed_srcs and not changed_hdrs:
        print("No changed C/C++ files detected.")
        return 0

    print(f"Changed source files: {len(changed_srcs)}")
    print(f"Changed header files: {len(changed_hdrs)}")

    try:
        output_to_source = load_compile_db(build_dir)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        target_deps = parse_ninja_deps(build_dir)
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.strip() or exc.stdout.strip() or str(exc), file=sys.stderr)
        print(
            "Failed to read Ninja deps. Ensure build dir was generated with Ninja and built at least once.",
            file=sys.stderr,
        )
        return 2

    impacted: Set[Path] = set(changed_srcs)
    if changed_hdrs:
        impacted |= impacted_sources_for_headers(changed_hdrs, target_deps, output_to_source, root)

    impacted_files = sorted(impacted)
    if not impacted_files:
        print("No impacted translation units found.")
        return 0

    print(f"Impacted translation units: {len(impacted_files)}")
    for p in impacted_files:
        try:
            rel = p.relative_to(root)
            print(f"  - {rel}")
        except ValueError:
            print(f"  - {p}")

    if args.dry_run:
        return 0

    failures = run_clang_tidy(
        impacted_files,
        build_dir,
        root,
        args.clang_tidy,
        warnings_as_errors=not args.no_warnings_as_errors,
    )
    if failures:
        print(f"clang-tidy failed for {failures} file(s).", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
