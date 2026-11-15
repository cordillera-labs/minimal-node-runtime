#!/usr/bin/env bash
# Network-free tests for the Node runtime baseline check.
set -euo pipefail
cd "$(dirname "$0")"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
mkdir -p "$dir/bin"
cat > "$dir/bin/docker" <<'MOCK'
#!/usr/bin/env bash
case "$*" in
  "image inspect site-test:canary --format {{json .Config.Entrypoint}}")
    printf '%s\n' "${MOCK_NODE_ENTRYPOINT:-null}"
    ;;
  "run --rm --network none --entrypoint node site-test:canary --version")
    [[ "${MOCK_NODE_ENTRYPOINT:-null}" != '["/nodejs/bin/node"]' ]] || exit 98
    printf '%s\n' "${MOCK_NODE_VERSION:-v24.22.2}"
    ;;
  "run --rm --network none --entrypoint /nodejs/bin/node site-test:canary --version")
    [[ "${MOCK_NODE_ENTRYPOINT:-null}" == '["/nodejs/bin/node"]' ]] || exit 98
    printf '%s\n' "${MOCK_NODE_VERSION:-v24.22.2}"
    ;;
  *) exit 99 ;;
esac
MOCK
chmod +x "$dir/bin/docker"
export PATH="$dir/bin:$PATH"

for entrypoint in null '["docker-entrypoint.sh"]' '["/nodejs/bin/node"]'; do
    for version in v24.22.2 v24.22.3 v24.23.0; do
        MOCK_NODE_ENTRYPOINT="$entrypoint" MOCK_NODE_VERSION="$version" \
            bash ./container-node-runtime-check.sh site-test:canary 24.22.2 > /dev/null
    done
    for version in v24.22.1 v24.21.99 v22.99.99 v26.0.0 bad-version; do
        if MOCK_NODE_ENTRYPOINT="$entrypoint" MOCK_NODE_VERSION="$version" \
            bash ./container-node-runtime-check.sh site-test:canary 24.22.2 > /dev/null 2>&1; then
            echo "unsafe runtime accepted: $version ($entrypoint)" >&2
            exit 1
        fi
    done
done
if bash ./container-node-runtime-check.sh 'oops;whoami' 24.22.2 > /dev/null 2>&1; then
    echo 'untrusted image argument accepted' >&2
    exit 1
fi
echo '[container-security] Node runtime baseline checks passed'
