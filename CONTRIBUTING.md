# Contributing to hpp-proto

Thank you for your interest in contributing to `hpp-proto`! We welcome contributions of all kinds, from bug fixes and feature implementations to documentation improvements.

## Development Environment Setup

### Prerequisites

*   **C++23 Compatible Compiler**: Clang 19+, GCC 13+, or MSVC 19.42+.
*   **CMake**: Version 3.25 or newer.
*   **Ninja**: Highly recommended for faster builds.
*   **Protobuf Compiler (`protoc`)**: For code generation during tests and benchmarks.

### Building the Project

We use CMake presets to simplify the build process.

To configure and build for development:

```bash
# Using the developer preset (recommends Ninja)
cmake --preset dev
cmake --build build/debug
```

## Running Tests

Tests are enabled by default in the `dev` preset. We use `boost::ut` for unit testing.

To run all tests:

```bash
ctest --preset all
```

Or manually:

```bash
cd build/debug
ctest --output-on-failure
```

## Benchmarks

To run benchmarks and update results:

```bash
cmake --preset benchmark
cmake --build build/release --target report
```

## Coding Standards

### Code Style

*   **Clang-Format**: We use `.clang-format` to ensure consistent code styling. Please run `clang-format` on your changes before submitting.
*   **Clang-Tidy**: We use `.clang-tidy` for static analysis and ensuring best practices.

### Commit Messages

We prefer clear and concise commit messages. When applicable, use prefixes like `fix:`, `feat:`, `docs:`, or `refactor:`.

Example:
`fix: update C++ standard to 23 and enhance CMake presets`

## Pull Request Process

1.  **Fork the repository** and create your branch from `main`.
2.  **Ensure the code builds** and all tests pass.
3.  **Add tests** for any new features or bug fixes.
4.  **Format your code** using `clang-format`.
5.  **Submit a Pull Request** with a detailed description of your changes.

---
By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).
