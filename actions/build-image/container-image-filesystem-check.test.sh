#!/usr/bin/env bash
# Shell-only regression tests: exporting image contents must be fail-closed.
set -euo pipefail
cd "$(dirname "$0")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/contents/app/subdir"
cat > "$tmp/bin/docker" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
  create)
    [[ "$*" == 'create site-test:canary' ]] || exit 99
    echo 'mock-container-id'
    ;;
  export)
    [[ "$2" == 'mock-container-id' ]] || exit 99
    cat "$MOCK_CONTAINER_ARCHIVE"
    ;;
  rm)
    [[ "$*" == 'rm mock-container-id' || "$*" == 'rm -f mock-container-id' ]] || exit 99
    ;;
  *) exit 99 ;;
esac
MOCK
chmod +x "$tmp/bin/docker"
export PATH="$tmp/bin:$PATH"
export MOCK_CONTAINER_ARCHIVE="$tmp/image.tar"

make_archive() {
    tar -cf "$MOCK_CONTAINER_ARCHIVE" -C "$tmp/contents" .
}
touch "$tmp/contents/app/normal"
make_archive
bash ./container-image-filesystem-check.sh site-test:canary >/dev/null

for path in .env app/.env.production app/subdir/.npmrc; do
    touch "$tmp/contents/$path"
    make_archive
    if bash ./container-image-filesystem-check.sh site-test:canary >/dev/null 2>&1; then
        echo "leaked image file accepted: $path" >&2
        exit 1
    fi
    rm -f "$tmp/contents/$path"
done

# Dot-env filenames with a dot suffix are forbidden by the existing policy.
touch "$tmp/contents/app/.env.example"
make_archive
if bash ./container-image-filesystem-check.sh site-test:canary >/dev/null 2>&1; then
    echo "dot-env suffixed filename was accepted" >&2
    exit 1
fi
rm -f "$tmp/contents/app/.env.example"

# A hyphen is not part of the forbidden .env[.suffix] pattern.
# Assert that harmless lookalikes do not broaden the policy by accident.
touch "$tmp/contents/app/.env-example"
make_archive
bash ./container-image-filesystem-check.sh site-test:canary >/dev/null
rm -f "$tmp/contents/app/.env-example"

if bash ./container-image-filesystem-check.sh 'bad;command' >/dev/null 2>&1; then
    echo "unsafe image reference accepted" >&2
    exit 1
fi
echo '[container-security] shell-free image file inventory checks passed'
