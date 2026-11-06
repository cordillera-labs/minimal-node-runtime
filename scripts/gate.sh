#!/bin/bash
# The scanner-visibility gate. It fails unless Trivy saw the image as Debian 13
# and listed exactly the packages in packages.list, at the versions in the lock.
# Without this check, a rootfs that Trivy cannot identify scans as "OS none"
# with zero findings, which reads as a pass.
#
#   gate.sh <trivy-report.json> <lock> [<rootfs-file-listing>]
#
# The report must come from `trivy image --format json --list-all-pkgs`.
# The optional listing is `tar -t` output of the exported image filesystem.
set -euo pipefail
export LC_ALL=C
report=$1
lock=$2
listing=${3:-}
root="$(cd "$(dirname "$0")/.." && pwd)"
failures=0

fail() {
    echo "FAIL $*"
    failures=$((failures + 1))
}
pass() {
    echo "ok   $*"
}

family=$(jq -r '.Metadata.OS.Family // "none"' "$report")
os_name=$(jq -r '.Metadata.OS.Name // ""' "$report")
if [ "$family" = debian ] && [[ "$os_name" =~ ^13(\.|$) ]]; then
    pass "Trivy detected debian $os_name"
else
    fail "Trivy detected OS family '$family' name '$os_name', expected debian 13"
fi

os_results=$(jq '[.Results[]? | select(.Class == "os-pkgs")] | length' "$report")
if [ "$os_results" = 1 ]; then pass "one OS package result"; else fail "$os_results OS package results, expected 1"; fi

lang_packages=$(jq '[.Results[]? | select(.Class == "lang-pkgs") | .Packages[]?] | length' "$report")
if [ "$lang_packages" = 0 ]; then pass "no language packages"; else fail "$lang_packages language packages found"; fi

expected=$(sed 's/#.*//' "$root/packages.list" | awk 'NF { print $1 }' | sort)
actual=$(jq -r '.Results[]? | select(.Class == "os-pkgs") | .Packages[]?.Name' "$report" | sort)
if [ "$actual" = "$expected" ]; then
    pass "packages: $(tr '\n' ' ' <<<"$actual")"
else
    fail "packages differ from packages.list: $(diff <(echo "$expected") <(echo "$actual") | grep '^[<>]' | tr '\n' ' ')"
fi

for package in $expected; do
    key="DEB_$(echo "$package" | tr '[:lower:]' '[:upper:]' | sed 's/+/X/g; s/[-.]/_/g')_VERSION"
    want=$(sed -n "s/^$key=//p" "$lock")
    got=$(jq -r --arg p "$package" '.Results[]? | select(.Class == "os-pkgs") | .Packages[]? | select(.Name == $p)
        | (if .Epoch and .Epoch != 0 then "\(.Epoch):" else "" end) + .Version + (if .Release and .Release != "" then "-\(.Release)" else "" end)' "$report")
    if [ "$got" = "$want" ]; then
        pass "$package $got"
    else
        fail "$package is '$got' in the scan, '$want' in the lock"
    fi
done

if jq -e '.Results[]? | .Packages[]? | select(.Name | test("^zlib"))' "$report" >/dev/null; then
    fail "zlib1g is in the package list"
else
    pass "zlib1g is absent from the package list"
fi
if [ -n "$listing" ]; then
    if grep -E '(^|/)(libz\.so|[^/]*zlib[^/]*)' "$listing"; then
        fail "a zlib file is in the image filesystem"
    else
        pass "no zlib file in the image filesystem"
    fi
    if grep -E '^(\./)?var/lib/dpkg/status\.d/zlib' "$listing"; then
        fail "a zlib status entry is in the image filesystem"
    fi
    # libc6 ships every shared library, not only the ones node links. Native
    # addons need them: the libvips inside sharp needs libresolv.so.2.
    if grep -qE '^(\./)?usr/lib/x86_64-linux-gnu/libresolv\.so\.2$' "$listing"; then
        pass "libresolv.so.2 is in the image filesystem"
    else
        fail "libresolv.so.2 is missing: libc6 must ship all of its shared libraries"
    fi
fi

if [ "$failures" -ne 0 ]; then
    echo "gate: $failures check(s) failed"
    exit 1
fi
echo "gate: pass"
