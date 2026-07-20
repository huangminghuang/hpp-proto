# Reproducible Conan graphs

The CI profiles in `profiles/` define every host and build setting used by the
Linux and Windows workflows. Each job selects a committed lockfile and matching
package list from `locks/` and `packages/`.

Conan 2 lockfiles pin package versions and recipe revisions (RREVs), but do not
record binary package revisions (PREVs). The package lists complement the
lockfiles with exact package IDs and PREVs. CI downloads only that list, then
runs `conan create` and `conan install` with `--no-remote`; a changed or missing
binary therefore fails instead of silently changing the dependency graph.

To intentionally update the graph with Conan 2.30.0:

1. Generate each lock with `conan lock create .`, its matching host/build
   profiles, the corresponding `with_protobuf` option, and `--update`.
2. Run `conan graph info . --lockfile=<lock> --format=json` with the same
   profiles and option.
3. Convert the graph to a package list with
   `conan list --graph=<graph.json> --graph-binaries=Download --format=json`.
4. Review the version, RREV, package ID, and PREV changes in both files, then
   update the corresponding workflow matrix entry if a profile changed.

Do not hand-edit lockfiles or package lists.
