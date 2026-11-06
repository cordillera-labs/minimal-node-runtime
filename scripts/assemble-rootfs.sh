#!/bin/bash
# Assembles the image root filesystem inside the helper stage of the Dockerfile.
#
#   assemble-rootfs.sh <input-dir> <rootfs-dir> <output-dir>
#
# <input-dir> holds node.tar.gz, debs/<package>.deb and packages.list.
# The script writes the rootfs to <rootfs-dir> and the file manifest to
# <output-dir>/rootfs.manifest.
#
# Rules it enforces:
#   - the downloaded packages are exactly the packages in packages.list;
#   - node links only libraries that the pinned packages provide, checked with
#     the dynamic loader from the pinned libc6;
#   - the shipped libraries are every shared library of each listed package: the
#     files of the .deb that match *.so or *.so.<number> directly in a library
#     directory, with their symlinks. Plug-in modules in subdirectories, such as
#     libc6's gconv, are not libraries and do not ship;
#   - every shipped package has a dpkg status entry and its copyright file, and
#     no other package has an entry;
#   - every file in the rootfs is accounted for in the manifest.
set -euo pipefail
export LC_ALL=C
umask 022

in_dir=$1
root=$2
out_dir=$3
: "${NODE_VERSION:?NODE_VERSION is required}"
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"

fail() {
    echo "assemble-rootfs: $*" >&2
    exit 1
}

stage=$(mktemp -d)
manifest_entries="$stage/manifest-entries"
: > "$manifest_entries"
mkdir -p "$root" "$out_dir"

# ---- 1. packages ------------------------------------------------------------
expected_packages=$(sed 's/#.*//' "$in_dir/packages.list" | awk 'NF { print $1 }' | sort)
downloaded_packages=$(find "$in_dir/debs" -name '*.deb' -printf '%f\n' | sed 's/\.deb$//' | sort)
[ -n "$expected_packages" ] || fail "packages.list is empty"
[ "$expected_packages" = "$downloaded_packages" ] \
    || fail "downloaded packages differ from packages.list: $(tr '\n' ' ' <<<"$downloaded_packages")vs $(tr '\n' ' ' <<<"$expected_packages")"

for package in $expected_packages; do
    deb="$in_dir/debs/$package.deb"
    [ "$(dpkg-deb -f "$deb" Package)" = "$package" ] || fail "$deb is not package $package"
    case "$(dpkg-deb -f "$deb" Architecture)" in
        amd64 | all) ;;
        *) fail "$deb has architecture $(dpkg-deb -f "$deb" Architecture)" ;;
    esac
    mkdir -p "$stage/pkg/$package" "$stage/ctrl/$package" "$stage/all"
    dpkg-deb -x "$deb" "$stage/pkg/$package"
    dpkg-deb -e "$deb" "$stage/ctrl/$package"
    dpkg-deb -x "$deb" "$stage/all"
done

# Copies one path of a package into the rootfs, with the target of a symlink,
# and records it in the manifest.
ship() {
    local package=$1 rel=$2 tree="$stage/pkg/$1"
    [ -e "$tree/$rel" ] || [ -L "$tree/$rel" ] || fail "$package does not contain $rel"
    (cd "$tree" && cp -a --parents "$rel" "$root/")
    printf '%s\t%s\n' "$package" "$rel" >> "$manifest_entries"
    if [ -L "$tree/$rel" ]; then
        local target
        target=$(readlink "$tree/$rel")
        case "$target" in
            /*) target=${target#/} ;;
            *) target=$(realpath -m --relative-to="$tree" "$tree/$(dirname "$rel")/$target") ;;
        esac
        # A link may point into another package, such as /usr/share/doc/libgcc-s1
        # pointing to gcc-14-base. That package ships the target itself.
        if [ -e "$tree/$target" ] || [ -L "$tree/$target" ]; then
            ship "$package" "$target"
        fi
    fi
}

# Records a file the script generates, rather than one copied from a package.
generated() {
    printf '%s\t%s\n' "$1" "$2" >> "$manifest_entries"
}

# ---- 2. merged-usr layout -----------------------------------------------------
mkdir -p "$root/usr/lib" "$root/usr/lib64" "$root/usr/bin"
ln -s usr/lib "$root/lib"
ln -s usr/lib64 "$root/lib64"
ln -s usr/bin "$root/bin"
generated layout lib
generated layout lib64
generated layout bin

# ---- 3. node --------------------------------------------------------------------
mkdir -p "$stage/node"
tar -xzf "$in_dir/node.tar.gz" -C "$stage/node" --strip-components=1 \
    "node-v$NODE_VERSION-linux-x64/bin/node" "node-v$NODE_VERSION-linux-x64/LICENSE"
install -D -m 0755 "$stage/node/bin/node" "$root/nodejs/bin/node"
install -D -m 0644 "$stage/node/LICENSE" "$root/nodejs/LICENSE"
generated node nodejs/bin/node
generated node nodejs/LICENSE
install -D -m 0644 "$in_dir/ca-distrust.cjs" "$root/nodejs/lib/ca-distrust.cjs"
generated node nodejs/lib/ca-distrust.cjs

# ---- 4. the libraries: what node links, then every library of each package ---------
libdir="$stage/all/usr/lib/x86_64-linux-gnu"
loader="$libdir/ld-linux-x86-64.so.2"
[ -x "$loader" ] || fail "libc6 does not provide $loader"
listing=$("$loader" --library-path "$libdir" --list "$root/nodejs/bin/node") \
    || fail "the loader could not resolve node: $listing"
echo "$listing" > "$out_dir/ldd.txt"
if grep -q 'not found' <<<"$listing"; then
    fail "node links a library that no listed package provides: $(grep 'not found' <<<"$listing")"
fi
# Every line is "name => path (address)", except the vDSO, which has no file.
# The interpreter line names the PT_INTERP path in the first field.
resolved=$(awk '$2 == "=>" { print $3 }' <<<"$listing" | sort -u)
[ -n "$resolved" ] || fail "the loader listed no libraries for node"
awk '$1 == "/lib64/ld-linux-x86-64.so.2" && $2 == "=>" { found = 1 } END { exit !found }' <<<"$listing" \
    || fail "node does not use /lib64/ld-linux-x86-64.so.2 as its interpreter: $listing"
# The interpreter path itself: /lib64 -> usr/lib64, and libc6 ships the link
# usr/lib64/ld-linux-x86-64.so.2 to the loader.
ship libc6 usr/lib64/ld-linux-x86-64.so.2

for path in $resolved; do
    case "$path" in
        "$stage/all/"*) rel=${path#"$stage/all/"} ;;
        *) fail "the loader resolved $path outside the pinned packages" ;;
    esac
    owner=""
    for package in $expected_packages; do
        if [ -e "$stage/pkg/$package/$rel" ] || [ -L "$stage/pkg/$package/$rel" ]; then
            owner=$package
            break
        fi
    done
    [ -n "$owner" ] || fail "no listed package contains $rel"
    ship "$owner" "$rel"
done

# Every shared library of each listed package. The set comes from the file list
# of the .deb, so it follows each glibc or GCC update. A library sits directly
# in usr/lib, usr/lib/<triplet> or usr/lib64. A deeper path, such as
# usr/lib/x86_64-linux-gnu/gconv/*.so, is a plug-in that glibc loads only through
# a gconv-modules configuration, and does not ship. The loop covers the
# nss libraries (libnss_*.so.2) and libresolv.so.2 of libc6 as well as the
# libraries that node links.
library_pattern='^usr/lib(64)?(/x86_64-linux-gnu)?/[^/]+\.so(\.[0-9]+)*$'
for package in $expected_packages; do
    library_list="$stage/libraries-$package"
    dpkg-deb --fsys-tarfile "$in_dir/debs/$package.deb" | tar -t \
        | sed 's|^\./||; s|/$||' | { grep -E "$library_pattern" || true; } | sort > "$library_list"
    while read -r rel; do
        ship "$package" "$rel"
    done < "$library_list"
done

# ---- 5. CA bundle -------------------------------------------------------------------
# Select pinned Debian roots with a reviewed exclusion list. The Debian
# postinst-generated /etc/ca-certificates.conf does not exist in the .deb.
mkdir -p "$root/etc/ssl/certs"
bundle="$root/etc/ssl/certs/ca-certificates.crt"
bash "$in_dir/select-ca-certificates.sh" \
    "$stage/pkg/ca-certificates/usr/share/ca-certificates" \
    "$in_dir/certificates.exclude" "$bundle"
cert_count=$(grep -c 'BEGIN CERTIFICATE' "$bundle")
[ "$cert_count" -ge 100 ] || fail "the CA bundle holds only $cert_count certificates"
chmod 0644 "$bundle"
generated ca-certificates etc/ssl/certs/ca-certificates.crt

# ---- 6. base-files: OS identity and licence texts ------------------------------------
ship base-files etc/debian_version
ship base-files etc/os-release
for licence in "$stage/pkg/base-files/usr/share/common-licenses/"*; do
    ship base-files "usr/share/common-licenses/$(basename "$licence")"
done

# ---- 7. copyright files ------------------------------------------------------------------
for package in $expected_packages; do
    doc="usr/share/doc/$package"
    if [ -L "$stage/pkg/$package/$doc" ]; then
        ship "$package" "$doc"
    else
        ship "$package" "$doc/copyright"
    fi
done
for package in $expected_packages; do
    [ -f "$root/usr/share/doc/$package/copyright" ] \
        || fail "the copyright file of $package does not resolve in the rootfs"
done

# ---- 8. users, name service, writable directories --------------------------------------
printf 'root:x:0:0:root:/root:/sbin/nologin\nnonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin\n' > "$root/etc/passwd"
printf 'root:x:0:\nnonroot:x:65532:\n' > "$root/etc/group"
printf 'passwd: files\ngroup: files\nhosts: files dns\n' > "$root/etc/nsswitch.conf"
generated generated etc/passwd
generated generated etc/group
generated generated etc/nsswitch.conf
install -d -m 1777 "$root/tmp"
install -d -m 0755 -o 65532 -g 65532 "$root/home/nonroot"
generated generated tmp
generated generated home/nonroot

# ---- 9. dpkg status entries ---------------------------------------------------------------
# One stanza per shipped package, in the layout distroless uses, so a scanner
# reads the exact package versions. The md5sums list only the files that ship.
mkdir -p "$root/var/lib/dpkg/status.d"
for package in $expected_packages; do
    status="$root/var/lib/dpkg/status.d/$package"
    {
        echo "Package: $package"
        echo "Status: install ok installed"
        grep -v '^Package:' "$stage/ctrl/$package/control"
    } > "$status"
    generated dpkg-metadata "var/lib/dpkg/status.d/$package"
    shipped=$(awk -F '\t' -v p="$package" '$1 == p { print $2 }' "$manifest_entries" | sort -u)
    if [ -f "$stage/ctrl/$package/md5sums" ] && [ -n "$shipped" ]; then
        awk 'NR == FNR { want[$0] = 1; next } { path = $0; sub(/^[0-9a-f]+  /, "", path); if (path in want) print }' \
            <(echo "$shipped") "$stage/ctrl/$package/md5sums" > "$status.md5sums"
        if [ -s "$status.md5sums" ]; then
            generated dpkg-metadata "var/lib/dpkg/status.d/$package.md5sums"
        else
            rm -f "$status.md5sums"
        fi
    fi
done

# ---- 10. checks over the finished tree ---------------------------------------------------
if find "$root" \( -name '*libz.*' -o -name '*zlib*' \) | grep -q .; then
    fail "a zlib file is in the rootfs: $(find "$root" \( -name '*libz.*' -o -name '*zlib*' \))"
fi
for package in $expected_packages; do
    awk -F '\t' -v p="$package" '$1 == p { found = 1 } END { exit !found }' "$manifest_entries" \
        || fail "package $package ships no file"
done
# Every non-directory in the rootfs has a manifest entry, and every entry exists.
(cd "$root" && find . -mindepth 1 ! -type d -printf '%P\n' | sort) > "$stage/actual"
awk -F '\t' '{ print $2 }' "$manifest_entries" | sort -u > "$stage/recorded"
recorded_files=$(cd "$root" && while read -r rel; do [ -d "$rel" ] && [ ! -L "$rel" ] || echo "$rel"; done < "$stage/recorded")
if ! diff <(echo "$recorded_files" | sort -u) "$stage/actual" > "$stage/diff"; then
    fail "the rootfs and its manifest disagree: $(cat "$stage/diff")"
fi

# ---- 11. manifest and timestamps -----------------------------------------------------------
# rootfs.manifest: one "<owner>\t<path>\t<type>" line per path, where <type>
# is the file type and, for a symlink, its target. A change to this set is a
# breaking change by the definition in README.md.
while IFS=$'\t' read -r owner rel; do
    if [ -L "$root/$rel" ]; then
        type="link:$(readlink "$root/$rel")"
    elif [ -d "$root/$rel" ]; then
        type="dir"
    else
        type="file"
    fi
    printf '%s\t%s\t%s\n' "$owner" "$rel" "$type"
done < <(sort -u "$manifest_entries") | sort -t $'\t' -k2,2 -k1,1 > "$out_dir/rootfs.manifest"

find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
echo "assemble-rootfs: $(wc -l < "$out_dir/rootfs.manifest") paths from $(wc -w <<<"$expected_packages") packages and node $NODE_VERSION"
