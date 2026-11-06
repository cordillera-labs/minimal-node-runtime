#!/bin/bash
# Verifies one signature or attestation of a published digest as a consumer
# would. publish.yml runs it before signing, to skip what already verifies,
# and after attesting, to check all four.
#
#   verify-published.sh signature|vuln|provenance|sbom <repository>@<digest>
#
# Needs COSIGN_IMAGE, GITHUB_REPOSITORY and GH_TOKEN, and a docker login in
# $HOME/.docker. Exits 0 only when the check verifies.
set -euo pipefail
check=$1
reference=$2
identity="^https://github\.com/${GITHUB_REPOSITORY}/\.github/workflows/publish\.yml@refs/heads/main$"
signer="$GITHUB_REPOSITORY/.github/workflows/publish.yml"

cosign() {
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e DOCKER_CONFIG=/docker-config \
        -v "$HOME/.docker:/docker-config:ro" "$COSIGN_IMAGE" "$@" "$reference" \
        --certificate-identity-regexp "$identity" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null
}

case "$check" in
    signature) cosign verify ;;
    vuln) cosign verify-attestation --type vuln ;;
    provenance) gh attestation verify "oci://$reference" --repo "$GITHUB_REPOSITORY" --signer-workflow "$signer" ;;
    sbom)
        gh attestation verify "oci://$reference" --repo "$GITHUB_REPOSITORY" --signer-workflow "$signer" \
            --predicate-type https://cyclonedx.org/bom
        ;;
    *) echo "verify-published: unknown check $check" >&2; exit 2 ;;
esac
