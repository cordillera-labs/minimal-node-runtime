# check=skip=InvalidDefaultArgInFrom
# A FROM scratch image that holds one Node.js binary, every shared library of
# the listed Debian packages, a CA bundle and a nonroot user, and nothing else. Every line (Node.js
# major) builds from this one file.
#
# Every input is pinned in state/<line>/*.lock and passed in as a build
# argument by scripts/lock.py build-args. Build with scripts/build.sh, not by
# hand.
#
# No `# syntax=` line: the frontend is the one built into the pinned BuildKit,
# so no extra image is pulled. The check directive above skips the warning
# about HELPER_IMAGE having no default: the lock is its only pin, by design.

ARG HELPER_IMAGE

# ---- assemble: a helper stage that is never shipped -------------------------
FROM ${HELPER_IMAGE} AS assemble

ARG NODE_VERSION
ARG NODE_SHA256
ARG DEB_BASE_FILES_SHA256
ARG DEB_CA_CERTIFICATES_SHA256
ARG DEB_GCC_14_BASE_SHA256
ARG DEB_LIBC6_SHA256
ARG DEB_LIBGCC_S1_SHA256
ARG DEB_LIBSTDCXX6_SHA256
ARG SOURCE_DATE_EPOCH

# BuildKit verifies the Node download against the pinned SHA-256 and fails
# the build on a mismatch. The checksum comes from a SHASUMS256.txt whose
# signature scripts/upstream.py verified against node-release-keys.txt.
ADD --checksum=sha256:${NODE_SHA256} https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz /in/node.tar.gz

# The .deb files come from the named context "debs", which
# scripts/fetch-debs.sh fills from the release assets or snapshot.debian.org.
# They are checked again here against the SHA-256 values in the lock.
COPY --from=debs *.deb /in/debs/
RUN set -eu; cd /in/debs; \
    printf '%s  %s\n' \
        "${DEB_BASE_FILES_SHA256}" base-files.deb \
        "${DEB_CA_CERTIFICATES_SHA256}" ca-certificates.deb \
        "${DEB_GCC_14_BASE_SHA256}" gcc-14-base.deb \
        "${DEB_LIBC6_SHA256}" libc6.deb \
        "${DEB_LIBGCC_S1_SHA256}" libgcc-s1.deb \
        "${DEB_LIBSTDCXX6_SHA256}" libstdc++6.deb \
    | sha256sum --strict -c -; \
    [ "$(ls | wc -l)" = 6 ]

COPY packages.list /in/packages.list
COPY scripts/assemble-rootfs.sh /in/assemble-rootfs.sh
COPY scripts/select-ca-certificates.sh /in/select-ca-certificates.sh
COPY runtime/ca-distrust.cjs /in/ca-distrust.cjs
COPY certificates.exclude /in/certificates.exclude
RUN NODE_VERSION="${NODE_VERSION}" SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    bash /in/assemble-rootfs.sh /in /rootfs /out

# ---- manifest: the rootfs file list and loader output, for scripts/build.sh --
FROM scratch AS manifest
COPY --from=assemble /out/ /

# ---- runtime ----------------------------------------------------------------
FROM scratch AS runtime
ARG NODE_VERSION
COPY --from=assemble /rootfs/ /
LABEL org.opencontainers.image.title="minimal-node-runtime" \
      org.opencontainers.image.description="Node.js ${NODE_VERSION} on a FROM scratch base with the Debian 13 shared libraries of glibc and the GCC runtime" \
      org.opencontainers.image.source="https://github.com/cordillera-labs/minimal-node-runtime" \
      org.opencontainers.image.version="${NODE_VERSION}"
ENV PATH=/nodejs/bin \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65532:65532
WORKDIR /home/nonroot
ENTRYPOINT ["/nodejs/bin/node"]
