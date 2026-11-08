#!/bin/bash
# Select a deterministic CA bundle from pinned Debian roots.
#   select-ca-certificates.sh <cert-dir> <manual-path-exclusions> <bundle> \
#       [automatic-DER-SHA256-exclusions] [effective-excluded-DER-hashes]
set -euo pipefail
export LC_ALL=C
cert_dir=${1:?certificate directory required}
manual=${2:?manual exclusions file required}
bundle=${3:?output bundle required}
automatic=${4:-/dev/null}
exclusion_hashes=${5:-/dev/null}
fail() { echo "select-ca-certificates: $*" >&2; exit 1; }
[[ -d "$cert_dir" ]] || fail "missing certificate directory"
[[ -f "$manual" ]] || fail "missing exclusions file"
[[ -f "$automatic" ]] || fail "missing automatic exclusions file"
cert_dir=${cert_dir%/}
declare -A manual_exclusions=() automatic_hashes=()
while IFS= read -r entry || [[ -n "$entry" ]]; do
    [[ -z "$entry" || "$entry" == \#* ]] && continue
    if [[ "$entry" != *.crt || "$entry" == /* || "$entry" == *//* || "$entry" =~ [[:space:]] ]]; then
        fail "invalid exclusion path: $entry"
    fi
    IFS=/ read -r -a parts <<< "$entry"
    for part in "${parts[@]}"; do
        [[ -n "$part" && "$part" != . && "$part" != .. ]] || fail "invalid exclusion path: $entry"
    done
    [[ -f "$cert_dir/$entry" && ! -L "$cert_dir/$entry" ]] || fail "missing packaged certificate: $entry"
    [[ ! -v manual_exclusions["$entry"] ]] || fail "duplicate manual exclusion: $entry"
    manual_exclusions["$entry"]=1
done < "$manual"
: > "$exclusion_hashes"
while IFS= read -r entry || [[ -n "$entry" ]]; do
    [[ -z "$entry" || "$entry" == \#* ]] && continue
    [[ "$entry" =~ ^[0-9a-f]{64}$ ]] || fail "invalid automatic DER fingerprint: $entry"
    [[ ! -v automatic_hashes["$entry"] ]] || fail "duplicate automatic fingerprint: $entry"
    automatic_hashes["$entry"]=1
    # Include roots no longer shipped by Debian but still embedded in Node.
    printf '%s\n' "$entry" >> "$exclusion_hashes"
done < "$automatic"

hash_certificate() {
    sed -n '/^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/{ /^-----/d; p; }' "$1" \
        | base64 -d | sha256sum | cut -d ' ' -f1
}
mapfile -d '' certs < <(find "$cert_dir" -type f -name '*.crt' -print0 | sort -z)
(( ${#certs[@]} > 0 )) || fail "no packaged certificates found"
: > "$bundle"
selected=0
for cert in "${certs[@]}"; do
    relative=${cert#"$cert_dir/"}
    [[ $(grep -c '^-----BEGIN CERTIFICATE-----$' "$cert") -eq 1 ]] || fail "invalid PEM: $relative"
    [[ $(grep -c '^-----END CERTIFICATE-----$' "$cert") -eq 1 ]] || fail "invalid PEM: $relative"
    hash=$(hash_certificate "$cert") || fail "malformed certificate base64: $relative"
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || fail "bad DER hash: $relative"
    if [[ -v manual_exclusions["$relative"] || -v automatic_hashes["$hash"] ]]; then
        printf '%s\n' "$hash" >> "$exclusion_hashes"
        continue
    fi
    cat "$cert" >> "$bundle"
    [[ -z "$(tail -c 1 "$cert")" ]] || printf '\n' >> "$bundle"
    selected=$((selected+1))
done
(( selected > 0 )) || fail "no selected certificates remain"
# Node's embedded root store is also filtered against this same list.
sort -u "$exclusion_hashes" -o "$exclusion_hashes"
chmod 0644 "$bundle" "$exclusion_hashes"
echo "select-ca-certificates: selected $selected of ${#certs[@]} packaged certificates"
