"""Unit tests for scripts/publication.py: when a publish run reuses what an
earlier run published for the same digest, and when it fails closed."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import lock as lockfile  # noqa: E402
import publication  # noqa: E402
from test_policy import base_lock  # noqa: E402

IMAGE = "ghcr.io/cordillera-labs/minimal-node-runtime"
DIGEST = "sha256:" + "7" * 64
OTHER = "sha256:" + "8" * 64
TAG = "22.23.4-trixie-2824bdb231d8"
URL = f"https://github.com/cordillera-labs/minimal-node-runtime/releases/tag/{TAG}"
RUN = "https://github.com/cordillera-labs/minimal-node-runtime/actions/runs/42188163064"
COMMIT = "f" * 40


def temporary_directory(test):
    holder = tempfile.TemporaryDirectory()
    test.addCleanup(holder.cleanup)
    return holder.name


def collected():
    """sources.py collect output: one new entry, one carried by an earlier release."""
    return {
        "glibc 2.41-12": {"source": "glibc", "version": "2.41-12", "binaries": ["libc6"],
                          "files": [{"name": "glibc_2.41-12.dsc", "asset": "glibc_2.41-12.dsc",
                                     "sha256": "1" * 64, "size": 10}],
                          "release": None, "release_url": None, "downloaded_from": "https://live/"},
        "gcc-14 14.2.0-19": {"source": "gcc-14", "version": "14.2.0-19", "binaries": ["libgcc-s1"],
                             "files": [{"name": "gcc-14_14.2.0-19.dsc", "asset": "gcc-14_14.2.0-19.dsc",
                                        "sha256": "2" * 64, "size": 20}],
                             "release": "22.23.3-trixie-000000000000",
                             "release_url": "https://github.com/x/y/releases/tag/22.23.3-trixie-000000000000"},
    }


def released_sources():
    """sources.py record output, as the earlier run attached it."""
    sources = collected()
    sources["glibc 2.41-12"].update(release=TAG, release_url=URL,
                                    downloaded_from="https://snapshot.debian.org/archive/debian/x/")
    return sources


def body(digest=DIGEST, image=IMAGE, run=RUN):
    return (f"Channel: **stable**\n\nDigest: `{image}@{digest}`\n\nnon-breaking\n\n"
            f"## Verify\n\n```sh\ncosign verify {image}@{digest}\n```\n\nRun: {run}\n")


def release(**changes):
    lock = base_lock()
    names = list(publication.FIXED_ASSETS) + [row[4] for row in lockfile.debs(lock, lockfile.read_packages())]
    names += ["glibc_2.41-12.dsc", "debian-sources.txt"]
    entry = {"tag_name": TAG, "draft": False, "prerelease": False, "target_commitish": COMMIT,
             "body": body(), "assets": [{"name": name} for name in names]}
    entry.update(changes)
    return entry


def state(releases, channel="stable", sources=None, digest=DIGEST):
    return publication.release_state(releases, TAG, IMAGE, digest, channel, base_lock(),
                                     collected() if sources is None else sources)


class ReleaseState(unittest.TestCase):
    def test_no_release_with_the_tag_is_absent(self):
        other = release(tag_name="22.23.3-trixie-000000000000")
        self.assertEqual(state([]), "absent")
        self.assertEqual(state([other]), "absent")

    def test_a_complete_release_of_this_digest_is_present(self):
        self.assertEqual(state([release()]), "present")

    def test_a_candidate_release_is_present_for_the_candidate_channel(self):
        self.assertEqual(state([release(prerelease=True)], channel="candidate"), "present")

    def test_a_release_of_another_digest_is_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "not reused"):
            state([release(body=body(digest=OTHER))])

    def test_a_release_of_another_repository_is_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "not reused"):
            state([release(body=body(image="ghcr.io/someone/else"))])

    def test_a_release_that_records_no_digest_is_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "0 digest lines"):
            state([release(body="Channel: **stable**\n")])

    def test_a_release_that_records_two_digests_is_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "2 digest lines"):
            state([release(body=body() + body(digest=OTHER))])

    def test_a_draft_is_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "draft"):
            state([release(draft=True)])

    def test_two_releases_with_the_tag_are_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "2 releases"):
            state([release(), release(draft=True)])

    def test_a_release_on_the_other_channel_is_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "published to stable"):
            state([release()], channel="candidate")
        with self.assertRaisesRegex(publication.PublicationFault, "published to candidate"):
            state([release(prerelease=True)], channel="stable")

    def test_a_release_without_a_deb_is_a_fault(self):
        assets = [asset for asset in release()["assets"] if not asset["name"].endswith(".deb")]
        with self.assertRaisesRegex(publication.PublicationFault, "lacks the assets"):
            state([release(assets=assets)])

    def test_a_release_without_a_new_source_file_is_a_fault(self):
        assets = [asset for asset in release()["assets"] if asset["name"] != "glibc_2.41-12.dsc"]
        with self.assertRaisesRegex(publication.PublicationFault, "glibc_2.41-12.dsc"):
            state([release(assets=assets)])

    def test_a_source_carried_by_an_earlier_release_is_not_required(self):
        self.assertNotIn("gcc-14_14.2.0-19.dsc", publication.required_assets(base_lock(), collected(), TAG))

    def test_no_new_source_needs_no_source_list(self):
        sources = collected()
        del sources["glibc 2.41-12"]
        self.assertNotIn("debian-sources.txt", publication.required_assets(base_lock(), sources, TAG))


class ReleaseMatch(unittest.TestCase):
    def assets(self, lock=None, sbom_digest=DIGEST, sources=None):
        directory = temporary_directory(self)
        with open(os.path.join(directory, "inputs.lock"), "w") as handle:
            handle.write(lockfile.render(lock or base_lock(), "stable", lockfile.read_packages()))
        with open(os.path.join(directory, "sbom.cdx.json"), "w") as handle:
            json.dump({"metadata": {"component": {"name": IMAGE, "version": sbom_digest}}}, handle)
        with open(os.path.join(directory, "sources.json"), "w") as handle:
            json.dump(released_sources() if sources is None else sources, handle)
        return directory

    def match(self, directory, sources=None):
        return publication.release_match(directory, TAG, URL, DIGEST, base_lock(),
                                         collected() if sources is None else sources)

    def test_matching_assets_give_the_release_record(self):
        self.assertEqual(self.match(self.assets()), released_sources())

    def test_a_record_field_change_alone_still_matches(self):
        lock = base_lock()
        lock["EVALUATED_AT"] = "2026-11-06T09:30:00Z"
        lock["NODE_ACCEPTED"] = "initial"
        self.assertEqual(self.match(self.assets(lock=lock)), released_sources())

    def test_other_inputs_are_a_fault(self):
        lock = base_lock()
        lock["NODE_VERSION"] = "22.23.5"
        with self.assertRaisesRegex(publication.PublicationFault, "inputs.lock"):
            self.match(self.assets(lock=lock))

    def test_an_sbom_of_another_digest_is_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "SBOM"):
            self.match(self.assets(sbom_digest=OTHER))

    def test_other_source_packages_are_a_fault(self):
        sources = released_sources()
        del sources["gcc-14 14.2.0-19"]
        with self.assertRaisesRegex(publication.PublicationFault, "differ"):
            self.match(self.assets(sources=sources))

    def test_other_source_files_are_a_fault(self):
        sources = released_sources()
        sources["glibc 2.41-12"]["files"][0]["sha256"] = "9" * 64
        with self.assertRaisesRegex(publication.PublicationFault, "other files"):
            self.match(self.assets(sources=sources))

    def test_a_new_source_carried_by_another_release_is_a_fault(self):
        sources = released_sources()
        sources["glibc 2.41-12"]["release"] = "22.23.3-trixie-000000000000"
        with self.assertRaisesRegex(publication.PublicationFault, "carrier"):
            self.match(self.assets(sources=sources))

    def test_a_known_source_keeps_its_earlier_carrier(self):
        sources = released_sources()
        sources["gcc-14 14.2.0-19"].update(release=TAG, release_url=URL)
        with self.assertRaisesRegex(publication.PublicationFault, "carrier"):
            self.match(self.assets(sources=sources))


class ReleaseRecord(unittest.TestCase):
    def test_gives_the_commit_and_run_that_created_the_release(self):
        self.assertEqual(publication.release_record(release()), (COMMIT, RUN))

    def test_a_branch_target_is_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "not a commit"):
            publication.release_record(release(target_commitish="main"))

    def test_a_body_without_a_run_is_a_fault(self):
        with self.assertRaisesRegex(publication.PublicationFault, "names no run"):
            publication.release_record(release(body=body(run="")))


class Registry(unittest.TestCase):
    def responder(self, manifest_status=200, digest=DIGEST, token_status=200):
        calls = []

        def request(url, method="GET", headers=None, **_):
            calls.append((url, method, dict(headers or {})))
            if "/token?" in url:
                return token_status, {}, json.dumps({"token": "pull-token"}).encode()
            return manifest_status, ({"Docker-Content-Digest": digest} if digest else {}), b""
        return calls, request

    def test_a_404_is_absent(self):
        _, request = self.responder(manifest_status=404, digest="")
        with mock.patch.object(publication.upstream, "request", request):
            self.assertIsNone(publication.tag_digest(IMAGE, TAG, "actor", "secret"))

    def test_a_tag_gives_its_digest_and_the_credentials_go_to_the_registry_only(self):
        calls, request = self.responder()
        with mock.patch.object(publication.upstream, "request", request):
            self.assertEqual(publication.tag_digest(IMAGE, TAG, "actor", "secret"), DIGEST)
        token_url, _, token_headers = calls[0]
        self.assertTrue(token_url.startswith("https://ghcr.io/token?"))
        self.assertIn("repository:cordillera-labs/minimal-node-runtime:pull", token_url)
        self.assertTrue(token_headers["Authorization"].startswith("Basic "))
        manifest_url, method, headers = calls[1]
        self.assertEqual(manifest_url, f"https://ghcr.io/v2/cordillera-labs/minimal-node-runtime/manifests/{TAG}")
        self.assertEqual(method, "HEAD")
        self.assertEqual(headers["Authorization"], "Bearer pull-token")
        self.assertIn("application/vnd.oci.image.manifest.v1+json", headers["Accept"])

    def test_no_credentials_request_an_anonymous_token(self):
        calls, request = self.responder()
        with mock.patch.object(publication.upstream, "request", request):
            publication.tag_digest(IMAGE, TAG)
        self.assertNotIn("Authorization", calls[0][2])

    def test_another_status_is_a_fault(self):
        _, request = self.responder(manifest_status=500)
        with mock.patch.object(publication.upstream, "request", request):
            with self.assertRaisesRegex(publication.PublicationFault, "HTTP 500"):
                publication.tag_digest(IMAGE, TAG)

    def test_a_refused_token_is_a_fault(self):
        _, request = self.responder(token_status=403)
        with mock.patch.object(publication.upstream, "request", request):
            with self.assertRaisesRegex(publication.PublicationFault, "token endpoint"):
                publication.tag_digest(IMAGE, TAG)

    def test_an_answer_without_a_digest_is_a_fault(self):
        _, request = self.responder(digest="")
        with mock.patch.object(publication.upstream, "request", request):
            with self.assertRaisesRegex(publication.PublicationFault, "no digest"):
                publication.tag_digest(IMAGE, TAG)

    def test_an_unreadable_repository_is_a_fault(self):
        with self.assertRaises(publication.PublicationFault):
            publication.split_repository("ghcr.io")

    def test_tag_state(self):
        self.assertEqual(publication.tag_state(None, DIGEST, "x"), "absent")
        self.assertEqual(publication.tag_state(DIGEST, DIGEST, "x"), "present")
        with self.assertRaisesRegex(publication.PublicationFault, "never moved"):
            publication.tag_state(OTHER, DIGEST, "x")


class CommandLine(unittest.TestCase):
    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = publication.main(["publication.py", *args])
        return status, out.getvalue(), err.getvalue()

    def files(self, releases):
        directory = temporary_directory(self)
        paths = {}
        for name, content in (("releases.json", json.dumps(releases)), ("sources.json", json.dumps(collected())),
                              ("build.lock", lockfile.render(base_lock(), "stable", lockfile.read_packages()))):
            paths[name] = os.path.join(directory, name)
            with open(paths[name], "w") as handle:
                handle.write(content)
        return paths

    def release_state(self, releases, digest=DIGEST):
        paths = self.files(releases)
        return self.run_main("release-state", "--releases", paths["releases.json"], "--tag", TAG,
                             "--image", IMAGE, "--digest", digest, "--channel", "stable",
                             "--lock", paths["build.lock"], "--sources", paths["sources.json"])

    def test_prints_the_state(self):
        self.assertEqual(self.release_state([])[:2], (0, "absent\n"))
        self.assertEqual(self.release_state([release()])[:2], (0, "present\n"))

    def test_a_fault_exits_1_and_prints_nothing_to_stdout(self):
        status, out, err = self.release_state([release(body=body(digest=OTHER))])
        self.assertEqual((status, out), (1, ""))
        self.assertIn("not reused", err)

    def test_an_invalid_digest_exits_1(self):
        status, out, _ = self.release_state([], digest="sha256:short")
        self.assertEqual((status, out), (1, ""))


if __name__ == "__main__":
    unittest.main()
