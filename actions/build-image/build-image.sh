#!/usr/bin/env bash
#
# build-image.sh — build a Dockerfile, then assert the image is linux/amd64 and
# carries no environment file.
#
# The app is expected to read configuration at runtime, so the build takes no
# build arguments and no secrets. The filesystem check fails the build when the
# image holds a .env, .env.* or .npmrc file.
#
# USAGE
#   build-image.sh IMAGE_TAG [CONTEXT_DIR]     CONTEXT_DIR defaults to .
#
# EXIT
#   0   the image built and holds no forbidden file
#   1   the build failed, or the image holds a forbidden file (each is named)
#   64  usage error
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -lt 1 || $# -gt 2 || ! "$1" =~ ^[a-zA-Z0-9._:/@-]+$ ]]; then
    echo "usage: build-image.sh IMAGE_TAG [CONTEXT_DIR]" >&2
    exit 64
fi
tag="$1"
context="${2:-.}"

echo "build-image: building ${tag} from ${context}"
# Build the architecture that Trivy and the runtime check validate.
docker build --platform linux/amd64 --progress=plain -t "${tag}" "${context}"

platform="$(docker image inspect "${tag}" --format '{{.Os}}/{{.Architecture}}')"
if [[ "${platform}" != "linux/amd64" ]]; then
    echo "build-image: expected linux/amd64, got ${platform}" >&2
    exit 1
fi
echo "build-image: verified ${platform} image"

# The runtime image has no shell or find, so inspect the exported filesystem
# on the host, failing closed on container, export or tar errors.
bash "${here}/container-image-filesystem-check.sh" "${tag}"
