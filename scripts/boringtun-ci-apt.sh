#!/usr/bin/env bash
# Read-only candidate CI setup; workflow step timeouts bound the whole operation.
set -euo pipefail
if (( $# == 0 )); then
    echo 'At least one package is required' >&2
    exit 2
fi
for package in "$@"; do
    if [[ ! "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]]; then
        echo 'Invalid package name' >&2
        exit 2
    fi
done
options=(-o Acquire::Retries=2 -o Acquire::http::Timeout=30
         -o Acquire::https::Timeout=30 -o DPkg::Lock::Timeout=60)
sudo apt-get "${options[@]}" -o APT::Update::Error-Mode=any update
sudo apt-get "${options[@]}" install -y --no-install-recommends "$@"
