# Toolchain GitHub App setup

The hourly routine and security toolchain updaters can use a **dedicated,
single-repository GitHub App** to create and update pull requests. Unlike PRs
created with the workflow's automatic `GITHUB_TOKEN`, these PRs trigger
regular `pull_request` workflows without a human clicking **Approve workflows
to run**. The exact-head `workflow_dispatch` CI gate remains in place.

The App registration and secret provisioning require an organization
administrator. No private key is stored in this repository.

## Register and install

1. As an administrator of **cordillera-labs**, open
   [New organization GitHub App](https://github.com/organizations/cordillera-labs/settings/apps/new?name=cordillera-runtime-updater&description=Scoped%20toolchain%20pull%20request%20automation&url=https%3A%2F%2Fgithub.com%2Fcordillera-labs%2Fminimal-node-runtime&contents=write&pull_requests=write&webhook_active=false&public=false).
   The URL preselects a name and permissions; confirm the fields before
   submitting. If that name is already taken, choose another.
2. Set **Homepage URL** to the minimal-node-runtime GitHub repository.
   Do not request user OAuth authorization or enter a callback URL.
   **Disable the webhook** (this app is only used to mint installation tokens).
   Choose **Only on this account** for installation visibility.
3. Grant **repository permissions only**:
   - **Contents: Read and write** — push the single-pin branch.
   - **Pull requests: Read and write** — create and merge PRs.
   - Metadata: Read-only is GitHub's default implicit access.
   Leave Actions, Workflows, Issues, and other extra App permissions disabled.
4. Create the App, then open its **Install App** tab. Install on
   **cordillera-labs**, choosing **Only select repositories** and selecting
   **minimal-node-runtime**, *not* all repositories.
5. Under the App's **General** settings, note the **Client ID** and choose
   **Generate a private key**. GitHub downloads a PEM file; treat it as a
   credential, keep it out of source control, and rotate it if exposed.

## Provision the Actions credentials

In [minimal-node-runtime Settings → Secrets and variables → Actions](https://github.com/cordillera-labs/minimal-node-runtime/settings/secrets/actions):

- Under **Variables**, add `TOOLCHAIN_APP_CLIENT_ID` with the App's **Client
  ID** (not its numeric App ID).
- Under **Secrets**, add `TOOLCHAIN_APP_PRIVATE_KEY` with the **full raw PEM
  contents**, including BEGIN/END lines and line breaks.

Add the secret first and the variable second. The workflows only attempt App
authentication when the Client ID variable is set; before then the original
`GITHUB_TOKEN` behavior remains available. If the variable is set but the
secret is missing or invalid, token generation fails visibly rather than
silently using an unintended credential.

**Never paste the private key into a PR, commit, issue, or chat.**

## What the workflows do

- `update.yml`: mints a one-repository installation token, persists that
  token only for the trusted checkout's Git push, uses it to author/refresh
  routine PRs and perform guarded merges, and keeps its native job token for
  issues and `workflow_dispatch` CI.
- `toolchain-security.yml`: uses the same App for security PRs. It obtains
  **another short-lived App token after CI** before merging, since security
  validation can run longer than the one-hour installation token lifetime.
- Both workflows request only `contents: write` and
  `pull-requests: write` when creating the App token, and scope it to the
  current repository by omitting the App action's `owner`/`repositories`
  inputs. The separate security fast path and normal cooldown still apply.
- The existing toolchain workflow keeps a `GITHUB_TOKEN` fallback during
  migration, so unfinished App setup does not disable security updates. PRs
  created with that fallback still require workflow approval.

## First end-to-end check

1. Merge the App-wiring PR after regular CI.
2. From the repository Actions tab, manually dispatch `update` on `main`.
   Check the **toolchain** job: **Mint one-repository toolchain GitHub App
   token** must succeed, not skip.
3. Verify that a newly created or refreshed routine bot PR has no workflow
   approval prompt. Its usual PR-triggered checks and the explicit exact-head
   `ci.yml` dispatch can both run; the latter is the current auto-merge gate.
4. Confirm a same-major PR only merges after the exact-head CI succeeds, then
   check that `update.yml` was dispatched for publication.
5. Separately run `toolchain-security` on `main` to verify App token
   creation. If no published direct advisory qualifies, the run is a no-op
   rather than an artificially generated security PR.

The pre-existing BuildKit PR #39 was initially opened with `GITHUB_TOKEN`;
its *old* approval-required checks may still be visible. The App solves new
PR events and App-authored branch refreshes, not retroactive approvals for
historical events.

References:
- https://docs.github.com/en/actions/concepts/security/github_token
- https://github.com/actions/create-github-app-token
