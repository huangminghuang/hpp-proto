# Vcpkg Overlay Ports

This directory contains local vcpkg overlay ports used by this repository.

## Purpose

- Keep `hpp-proto` consumable as a local port during CI and local testing.
- Apply repository-specific dependency controls that are not guaranteed by the upstream vcpkg registry.
- Make vcpkg installs reproducible across environments.

## Ports in This Directory

- `ports/hpp-proto`: local port for this project.
  - Default mode is `find` (looks for `protoc` on system `PATH`).
  - Feature `vcpkg-protobuf` uses `protobuf`/`protoc` from vcpkg host tools.
- `ports/glaze`: pinned overlay port for `glaze` `7.8.4`.
  - This overrides the registry `glaze` port when `--overlay-ports` points to this directory.
- `ports/is-utf8`: pinned overlay port for `is-utf8` `1.4.1`.
  - Its patch disables upstream benchmark downloads and installs the missing CMake target export.

## How Overlay Resolution Works

When you pass:

`--overlay-ports=<repo>/ports`

vcpkg prefers matching ports from this directory before registry ports.

## Usage

### Install `hpp-proto` from this repository overlay

From the repository root, with `protoc` installed and discoverable via `$PATH`:

```bash
"$VCPKG_ROOT/vcpkg" install \
  --triplet=x64-linux \
  --overlay-ports="$PWD/ports"
```

### Install `vcpkg-protobuf` mode

```bash
"$VCPKG_ROOT/vcpkg" install \
  "hpp-proto[vcpkg-protobuf]" \
  --classic \
  --triplet=x64-linux \
  --overlay-ports="$PWD/ports"
```

### In CMake configure

Pass the same overlay path so dependency resolution remains consistent:

```bash
cmake -S tutorial -B tutorial-build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
  -DVCPKG_TARGET_TRIPLET=x64-linux \
  -DVCPKG_OVERLAY_PORTS="$PWD/ports"
```

## Notes

- If triplet/arch differs (for example in ARM containers), use the matching triplet (for example `arm64-linux`).
- Keep the `glaze` and `is-utf8` overlay ports aligned with the versions expected by `hpp-proto`.
- The repository-root manifest pins the vcpkg registry baseline used by CI. Update the baseline and the pinned `vcpkg` input in `.github/workflows/vcpkg.yml` together.
