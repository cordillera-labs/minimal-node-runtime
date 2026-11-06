"""Unit tests for scripts/sbom-merge.py.

The fixtures are real: tests/fixtures/process-versions.json is the output of
the image's own node 22.23.4, and tests/fixtures/trivy-sbom.cdx.json is the
Trivy 0.74.0 CycloneDX SBOM of the same image.
"""

import importlib.util
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("sbom_merge", os.path.join(HERE, "..", "scripts", "sbom-merge.py"))
sbom_merge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sbom_merge)

IMAGE = "ghcr.io/cordillera-labs/minimal-node-runtime"
DIGEST = "sha256:70b2ae2d006d1cfc94de7705f2c335be3cbb1f8e1c625702c624249b6c3ac8ff"
EPOCH = "1792540800"


def load(name):
    with open(os.path.join(HERE, "fixtures", name)) as handle:
        return json.load(handle)


def merged(sbom=None, versions=None):
    return sbom_merge.merge(sbom or load("trivy-sbom.cdx.json"), versions or load("process-versions.json"),
                            IMAGE, DIGEST, EPOCH)


def node_of(sbom):
    nodes = [component for component in sbom["components"] if component["name"] == "node"]
    assert len(nodes) == 1, f"expected one node component, found {len(nodes)}"
    return nodes[0]


def all_refs(components):
    for component in components:
        yield component["bom-ref"]
        yield from all_refs(component.get("components", []))


class BundledComponents(unittest.TestCase):
    def test_openssl_zlib_and_icu_match_process_versions(self):
        versions = load("process-versions.json")
        children = {child["name"]: child for child in node_of(merged())["components"]}
        for name in ("openssl", "zlib", "icu"):
            self.assertIn(name, children)
            self.assertEqual(children[name]["version"], versions[name])
            self.assertEqual(children[name]["purl"], f"pkg:generic/{name}@{versions[name]}")

    def test_every_component_key_is_listed_and_abi_numbers_are_not(self):
        versions = load("process-versions.json")
        names = {child["name"] for child in node_of(merged())["components"]}
        self.assertEqual(names, set(versions) - {"node", "modules", "napi"})

    def test_node_carries_its_version_and_the_children_name_it(self):
        node = node_of(merged())
        self.assertEqual(node["version"], "22.23.4")
        for child in node["components"]:
            self.assertIn({"name": "minimal-node-runtime:bundled-in", "value": "node@22.23.4"}, child["properties"])
            self.assertIn({"name": "minimal-node-runtime:source", "value": "process.versions"}, child["properties"])

    def test_versions_are_verbatim_and_percent_encoded_in_the_purl(self):
        versions = dict(load("process-versions.json"), openssl="3.0.17+quic")
        child = next(child for child in node_of(merged(versions=versions))["components"] if child["name"] == "openssl")
        self.assertEqual(child["version"], "3.0.17+quic")
        self.assertEqual(child["purl"], "pkg:generic/openssl@3.0.17%2Bquic")

    def test_known_purl_types(self):
        purls = {child["name"]: child["purl"] for child in node_of(merged())["components"]}
        self.assertEqual(purls["undici"], "pkg:npm/undici@6.29.1")
        self.assertEqual(purls["cjs_module_lexer"], "pkg:npm/cjs-module-lexer@2.2.0")
        self.assertEqual(purls["uv"], "pkg:github/libuv/libuv@v1.51.0")
        self.assertEqual(purls["v8"], "pkg:generic/v8@12.4.254.21-node.57")


class Determinism(unittest.TestCase):
    def test_merge_is_idempotent(self):
        once = sbom_merge.render(merged())
        twice = sbom_merge.render(sbom_merge.merge(json.loads(once), load("process-versions.json"),
                                                   IMAGE, DIGEST, EPOCH))
        self.assertEqual(once, twice)

    def test_trivy_random_values_do_not_reach_the_output(self):
        original = load("trivy-sbom.cdx.json")
        text = json.dumps(original)
        uuids = sorted(set(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}", text)))
        self.assertGreater(len(uuids), 0, "precondition: the Trivy fixture carries random UUIDs")
        for index, value in enumerate(uuids):
            text = text.replace(value, f"00000000-0000-4000-8000-{index:012d}")
        other = json.loads(text)
        other["metadata"]["timestamp"] = "2030-01-01T00:00:00+00:00"
        self.assertEqual(sbom_merge.render(merged(original)), sbom_merge.render(merged(other)))

    def test_timestamp_is_the_epoch_and_the_root_names_the_image(self):
        result = merged()
        self.assertEqual(result["metadata"]["timestamp"], "2026-10-21T00:00:00Z")
        self.assertEqual(result["metadata"]["component"]["name"], IMAGE)
        self.assertEqual(result["metadata"]["component"]["version"], DIGEST)
        self.assertNotIn("/github/workspace", sbom_merge.render(result))
        self.assertRegex(result["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")

    def test_every_dependency_names_a_component(self):
        result = merged()
        refs = set(all_refs(result["components"])) | {result["metadata"]["component"]["bom-ref"]}
        for entry in result["dependencies"]:
            self.assertIn(entry["ref"], refs)
            self.assertLessEqual(set(entry["dependsOn"]), refs)
        root = next(entry for entry in result["dependencies"]
                    if entry["ref"] == result["metadata"]["component"]["bom-ref"])
        self.assertIn("pkg:generic/node@22.23.4", root["dependsOn"])

    def test_the_debian_packages_stay(self):
        names = {component["name"] for component in merged()["components"]}
        self.assertLessEqual({"base-files", "ca-certificates", "gcc-14-base", "libc6", "libgcc-s1", "libstdc++6"},
                             names)


if __name__ == "__main__":
    unittest.main()
