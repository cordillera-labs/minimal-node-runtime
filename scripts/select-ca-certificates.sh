#!/bin/bash
# Build the CA bundle from the extracted, pinned Debian ca-certificates package.
#
#   select-ca-certificates.sh <cert-directory> <exclusions-file> <output-bundle>
#
# Debian normally generates /etc/ca-certificates.conf in its postinst script,
# which this FROM scratch build deliberately does not run. Debian defaults to
# trusting every packaged root. Keep that default, with an explicit reviewed
# list of roots to remove, rather than trusting an ungenerated config file.
set -euo pipefail
export LC_ALL=C

cert_dir=${1:?certificate directory is required}
exclusions=${2:?exclusions file is required}
bundle=${3:?output bundle is required}

fail() { echo "select-ca-certificates: $*" >&2; exit 1; }
[[ -d "$cert_dir" ]] || fail "missing certificate directory: $cert_dir"
[[ -f "$exclusions" ]] || fail "missing exclusions file: $exclusions"
cert_dir=${cert_dir%/}

declare -A excluded=()
while IFS= read -r entry || [[ -n "$entry" ]]; do
    [[ -z "$entry" || "$entry" == \#* ]] && continue
    # Each entry names a single .crt file relative to cert_dir. No globbing,
    # traversal, or whitespace: a typo must fail the build, not widen trust.
    if [[ "$entry" != *.crt || "$entry" == /* || "$entry" == *//* || "$entry" =~ [[:space:]] ]]; then
        fail "invalid exclusion path: $entry"
    fi
    IFS=/ read -r -a parts <<< "$entry"
    for part in "${parts[@]}"; do
        [[ -n "$part" && "$part" != . && "$part" != .. ]] || fail "invalid exclusion path: $entry"
    done
    [[ -f "$cert_dir/$entry" && ! -L "$cert_dir/$entry" ]] \
        || fail "excluded certificate is not a packaged file: $entry"
    [[ ! -v excluded["$entry"] ]] || fail "duplicate exclusion: $entry"
    excluded["$entry"]=1
done < "$exclusions"

mapfile -d '' certs < <(find "$cert_dir" -type f -name '*.crt' -print0 | sort -z)
(( ${#certs[@]} > 0 )) || fail "no packaged certificates found"
: > "$bundle"
selected=0
for cert in "${certs[@]}"; do
    relative=${cert#"$cert_dir/"}
    [[ -v excluded["$relative"] ]] && continue
    # A package update with an invalid PEM must not silently widen trust or
    # produce a broken bundle. Every Debian root is one PEM certificate.
    [[ $(grep -c '^-----BEGIN CERTIFICATE-----$' "$cert") -eq 1 ]] \
        || fail "not one PEM certificate: $relative"
    [[ $(grep -c '^-----END CERTIFICATE-----$' "$cert") -eq 1 ]] \
        || fail "not one PEM certificate: $relative"
    cat "$cert" >> "$bundle"
    [[ -z "$(tail -c 1 "$cert")" ]] || printf '\n' >> "$bundle"
    selected=$((selected + 1))
done
(( selected > 0 )) || fail "no selected certificates remain"
chmod 0644 "$bundle"
echo "select-ca-certificates: selected $selected of ${#certs[@]} packaged certificates"
