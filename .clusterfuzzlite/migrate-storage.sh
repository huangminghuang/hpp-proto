#!/usr/bin/env bash

set -euo pipefail

readonly source_url="${CFL_STORAGE_SOURCE_URL:-https://github.com/huangminghuang/hpp-proto-storage.git}"
if [[ -n "${CFL_STORAGE_DESTINATION_URL:-}" ]]; then
    readonly destination_url="${CFL_STORAGE_DESTINATION_URL}"
else
    readonly destination_repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
    readonly github_token="${GITHUB_TOKEN:?GITHUB_TOKEN must be set}"
    readonly destination_url="https://x-access-token:${github_token}@github.com/${destination_repository}.git"
fi

migrate_branch() (
    readonly source_branch="$1"
    readonly destination_branch="$2"

    if git ls-remote --exit-code --heads "${destination_url}" "refs/heads/${destination_branch}" >/dev/null; then
        return
    fi

    local migration_directory remote_commit source_tree snapshot_commit snapshot_date
    migration_directory="$(mktemp -d)"
    trap 'rm -rf -- "${migration_directory}"' EXIT

    git clone --quiet --depth 1 --no-tags --single-branch --branch "${source_branch}" \
        "${source_url}" "${migration_directory}"
    source_tree="$(git -C "${migration_directory}" rev-parse 'HEAD^{tree}')"
    snapshot_date="$(git -C "${migration_directory}" show -s --format=%aI HEAD)"
    snapshot_commit="$(
        printf 'Snapshot migrated ClusterFuzzLite %s\n' "${source_branch}" |
            GIT_AUTHOR_NAME=CIFuzz \
                GIT_AUTHOR_EMAIL=cifuzz@clusterfuzz.com \
                GIT_AUTHOR_DATE="${snapshot_date}" \
                GIT_COMMITTER_NAME=CIFuzz \
                GIT_COMMITTER_EMAIL=cifuzz@clusterfuzz.com \
                GIT_COMMITTER_DATE="${snapshot_date}" \
                git -C "${migration_directory}" commit-tree "${source_tree}"
    )"
    git -C "${migration_directory}" remote set-url origin "${destination_url}"
    if ! git -C "${migration_directory}" push origin "${snapshot_commit}:refs/heads/${destination_branch}"; then
        remote_commit="$(
            git ls-remote --heads "${destination_url}" "refs/heads/${destination_branch}" |
                awk 'NR == 1 { print $1 }'
        )"
        [[ "${remote_commit}" == "${snapshot_commit}" ]]
    fi
)

migrate_branch main cflite-corpus
migrate_branch gh-pages cflite-coverage
