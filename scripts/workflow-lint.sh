#!/bin/bash
# Lints the workflows: zizmor for security mistakes (unpinned actions, template
# injection, broad token permissions, persisted credentials, cache poisoning),
# then actionlint for workflow errors and shellcheck in run: scripts.
#
#   workflow-lint.sh
#
# Both run from their official images pinned by digest, with no network and the
# repository mounted read-only. The pins live here, not in toolchain.env: they
# are not part of the build, and a change to toolchain.env rebuilds the image.
# toolchain.py does not check them, so update them by hand, to a release at
# least policy.COOLDOWN_DAYS old, taking the digest from
#   docker buildx imagetools inspect <image>:<version>
#
# A finding that is a deliberate choice gets an inline
# `# zizmor: ignore[<rule>]` comment saying why, not a blanket config.
set -euo pipefail
zizmor_image=ghcr.io/zizmorcore/zizmor:1.31.1@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9
actionlint_image=docker.io/rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
repo="$(cd "$(dirname "$0")/.." && pwd)"

status=0
docker run --rm --network none --read-only -v "$repo:/repo:ro" -w /repo \
    "$zizmor_image" --offline --format plain . || status=$?
# zizmor exits 10-14 for findings, by highest severity, and other nonzero codes
# for its own faults.
case "$status" in
    0) echo "ok   zizmor" ;;
    1[0-4]) echo "FAIL zizmor reported findings" >&2; exit 1 ;;
    *) echo "FAIL zizmor exited $status, a tool fault, not a finding" >&2; exit 2 ;;
esac

docker run --rm --network none --read-only -v "$repo:/repo:ro" -w /repo \
    "$actionlint_image" -no-color -oneline || { echo "FAIL actionlint" >&2; exit 1; }
echo "ok   actionlint"
echo "workflow-lint: pass"
