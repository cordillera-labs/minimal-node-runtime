# check=skip=InvalidDefaultArgInFrom
# Variants of a built image that the gates must reject. scripts/negative-control.sh
# builds each target with the image under test as the named context "image".
ARG HELPER_IMAGE

FROM image AS original

FROM ${HELPER_IMAGE} AS edit
COPY --from=original / /rootfs/
RUN set -eu; \
    cp -a /rootfs /no-debian-version; \
    rm /no-debian-version/etc/debian_version; \
    sed 's/^Version: .*/Version: 2.36-9+deb12u1/' /rootfs/var/lib/dpkg/status.d/libc6 > /libc6; \
    printf 'Package: zlib1g\nStatus: install ok installed\nPriority: optional\nSection: libs\nArchitecture: amd64\nSource: zlib\nVersion: 1:1.3.dfsg+really1.3.1-1+b1\n' > /zlib1g

# Trivy cannot identify the OS without /etc/debian_version, and then reports
# no findings at all. The structural gate must fail on it.
FROM scratch AS no-debian-version
COPY --from=edit /no-debian-version/ /

# A libc6 entry with an old version. Trivy must report fixable findings, which
# proves it reads the dpkg metadata.
FROM original AS old-libc6
COPY --from=edit /libc6 /var/lib/dpkg/status.d/libc6

# An extra zlib1g entry. The package gate must fail on it.
FROM original AS zlib-entry
COPY --from=edit /zlib1g /var/lib/dpkg/status.d/zlib1g
