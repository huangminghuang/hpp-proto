#!/usr/bin/env bash

set -euo pipefail

readonly source_repository="${CFL_STORAGE_SOURCE_REPOSITORY:-huangminghuang/hpp-proto-storage}"
readonly destination_repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
readonly github_token="${GITHUB_TOKEN:?GITHUB_TOKEN must be set}"
readonly destination_url="https://x-access-token:${github_token}@github.com/${destination_repository}.git"

migrate_branch() {
    local source_branch="$1"
    local destination_branch="$2"

    if git ls-remote --exit-code --heads "${destination_url}" "refs/heads/${destination_branch}" >/dev/null; then
        return
    fi

    local migration_directory
    migration_directory="$(mktemp -d)"
    git clone --quiet --single-branch --branch "${source_branch}" \
        "https://github.com/${source_repository}.git" "${migration_directory}"
    git -C "${migration_directory}" remote set-url origin "${destination_url}"
    git -C "${migration_directory}" push origin "HEAD:refs/heads/${destination_branch}"
    rm -rf "${migration_directory}"
}

migrate_branch main cflite-corpus
migrate_branch gh-pages cflite-coverage
