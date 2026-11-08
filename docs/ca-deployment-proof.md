# End-to-end CA distrust image publication canary

Use **Actions → ca-deployment-proof → Run workflow** on `main`, leaving `phase=start`. This workflow is opt-in, never scheduled.

The first GitHub Actions run reads the actual published Node 22/24 images, selects a real certificate both currently trust, and feeds a synthetic Mozilla `CKT_NSS_TRUSTED_DELEGATOR` → `CKT_NSS_NOT_TRUSTED` transition through the **production monitor implementation**. It records the exclusion on a test-only `proof/ca-<run-id>` branch. **It does not modify main or the production exclusion list.**

That job uses `gh workflow run` to dispatch the same workflow's publication phase automatically on the proof branch, and waits for the child run to finish. The child builds both Node lines twice from the pinned production Dockerfile, publishes only these isolated GHCR tags:

- `ghcr.io/cordillera-labs/minimal-node-runtime:ca-proof-<run-id>-22`
- `ghcr.io/cordillera-labs/minimal-node-runtime:ca-proof-<run-id>-24`

The child verifies that the remote registry digest equals the reproducibly built digest, **pulls each image from GHCR**, and checks Node's effective default trust lost exactly the chosen root and gained no roots. It signs the pushed image digest and verifies the signature against its proof-workflow identity. Both runs provide auditable logs and image digests. The proof-only branches and tags remain available for inspection until explicitly cleaned up.

## Real-event production verification

When an **actual** authoritative Mozilla TLS distrust transition is accepted by
`root-trust.yml`, the workflow now dispatches `update.yml` with the root-trust
run ID as a correlation input and waits for that exact workflow to complete.
It then checks both Node stable locks were recorded by that update run, resolves
each stable GHCR tag to the recorded digest, pulls the digests, and verifies the
newly excluded DER SHA-256 fingerprints are **both baked into the images and
absent from Node's default TLS root list**.

A candidate-only publication, a failed image build, an unchanged stable tag, or
a successful GitHub dispatch without a completed published image **fails the
root-trust workflow** and opens the existing failure issue. This is a
production verification step that will run on future genuine distrust events;
it is not retroactive proof that such an event has already occurred.

## Evidence boundaries

This is a safe canary **using synthetic Mozilla source data**. It tests the real observer's transition logic, commit, GitHub workflow dispatch, production Dockerfile, image rebuild, GHCR publication, remote pull, signing, and Node TLS enforcement. It does **not** claim that Mozilla has actually revoked the test CA, nor does it exercise the production stable-tag and GitHub release operations: those would be unsafe for a synthetic distrust event.

The normal `root-trust.yml → update.yml → publish.yml` path still needs production verification following a real upstream distrust decision. Its exact stable-channel publication and signed attestations are separate from this canary. Also, GHCR image publication does not automatically restart existing consumer deployments: that requires an external image-update/redeployment mechanism.

**Before relying on production distrust**, confirm that the initial V1 image-layout change has passed the candidate-promotion gate into the stable image channel. The proof canary itself never moves stable or candidate tags.
