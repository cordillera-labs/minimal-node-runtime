#!/usr/bin/env python3
"""Adds the components bundled into the node binary to a Trivy CycloneDX
SBOM, and makes the document deterministic.

  sbom-merge.py --sbom <trivy.cdx.json> --versions <process-versions.json>
                --image <repository> --digest <sha256:...> --epoch <SOURCE_DATE_EPOCH>
                --out <merged.cdx.json>

<process-versions.json> is the output of the image's own node:
  docker run --rm <image> -p 'JSON.stringify(process.versions)'

Trivy reads the Debian packages only. The libraries compiled into node
(OpenSSL, zlib, ICU, libuv and others) appear here as components nested
inside one node component, for inventory and advisory matching.

Determinism: the same Trivy SBOM content and the same process.versions give
byte-identical output. Trivy's random values are replaced: the serial number
and the UUID bom-refs derive from the image digest and the component
identity, the timestamp is SOURCE_DATE_EPOCH, and the root component names
the image instead of the local path Trivy read. Components, dependencies and
properties are sorted. Merging a merged document again gives the same bytes.
"""

import argparse
import datetime
import json
import re
import sys
import urllib.parse
import uuid

SOURCE_PROPERTY = "minimal-node-runtime:source"
BUNDLED_IN_PROPERTY = "minimal-node-runtime:bundled-in"
SOURCE_VALUE = "process.versions"

# process.versions keys that are not components: node is the parent, and
# modules and napi are ABI version numbers.
NOT_COMPONENTS = {"node", "modules", "napi"}

# Data sets, not code.
DATA_COMPONENTS = {"cldr", "tz", "unicode"}

# JavaScript packages bundled into node, by their npm name.
NPM_NAMES = {"acorn": "acorn", "amaro": "amaro", "cjs_module_lexer": "cjs-module-lexer", "undici": "undici"}

# Projects whose release tags are exactly "v<version>".
GITHUB_REPOSITORIES = {
    "ada": "ada-url/ada",
    "ares": "c-ares/c-ares",
    "brotli": "google/brotli",
    "nghttp2": "nghttp2/nghttp2",
    "simdjson": "simdjson/simdjson",
    "simdutf": "simdutf/simdutf",
    "uv": "libuv/libuv",
    "zstd": "facebook/zstd",
}

UUID_PATTERN = re.compile(r"^(urn:uuid:)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def quote(value):
    return urllib.parse.quote(value, safe=".-_~")


def purl_for(key, version):
    """The package URL of a bundled component."""
    if key in NPM_NAMES:
        return f"pkg:npm/{quote(NPM_NAMES[key])}@{quote(version)}"
    if key in GITHUB_REPOSITORIES:
        owner, name = GITHUB_REPOSITORIES[key].split("/")
        return f"pkg:github/{owner}/{name}@v{quote(version)}"
    return f"pkg:generic/{quote(key)}@{quote(version)}"


def node_component(versions):
    node_version = versions["node"]
    bundled_in = f"node@{node_version}"
    children = []
    for key in sorted(versions):
        if key in NOT_COMPONENTS:
            continue
        purl = purl_for(key, versions[key])
        children.append({
            "bom-ref": purl,
            "type": "data" if key in DATA_COMPONENTS else "library",
            "name": key,
            "version": versions[key],
            "purl": purl,
            "properties": [
                {"name": BUNDLED_IN_PROPERTY, "value": bundled_in},
                {"name": SOURCE_PROPERTY, "value": SOURCE_VALUE},
            ],
        })
    purl = f"pkg:generic/node@{quote(node_version)}"
    return {
        "bom-ref": purl,
        "type": "application",
        "name": "node",
        "version": node_version,
        "purl": purl,
        "properties": [{"name": SOURCE_PROPERTY, "value": SOURCE_VALUE}],
        "components": children,
    }


def is_ours(component):
    return {"name": SOURCE_PROPERTY, "value": SOURCE_VALUE} in component.get("properties", [])


def refs_of(components):
    for component in components:
        if "bom-ref" in component:
            yield component["bom-ref"]
        yield from refs_of(component.get("components", []))


def stable_ref(component, namespace):
    identity = json.dumps([component.get("type"), component.get("name"), component.get("version"),
                           component.get("purl")], sort_keys=True)
    return str(uuid.uuid5(namespace, identity))


def sort_component(component):
    if "properties" in component:
        component["properties"] = sorted(component["properties"], key=lambda item: (item["name"], item["value"]))
    if "components" in component:
        component["components"] = sorted((sort_component(child) for child in component["components"]),
                                         key=component_key)
    return component


def component_key(component):
    return (component.get("type", ""), component.get("name", ""), component.get("version", ""),
            component.get("bom-ref", ""))


def merge(sbom, versions, image, digest, epoch):
    sbom = json.loads(json.dumps(sbom))
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, f"{image}@{digest}")
    metadata = sbom.setdefault("metadata", {})
    root = metadata.setdefault("component", {"type": "container"})

    # Drop an earlier merge, so that merging twice gives the same document.
    ours = {ref for component in sbom.get("components", []) if is_ours(component)
            for ref in refs_of([component])}
    sbom["components"] = [component for component in sbom.get("components", []) if not is_ours(component)]
    dependencies = [entry for entry in sbom.get("dependencies", []) if entry["ref"] not in ours]
    for entry in dependencies:
        entry["dependsOn"] = [ref for ref in entry.get("dependsOn", []) if ref not in ours]

    # Replace random UUID bom-refs with refs derived from the digest and the
    # component, and name the image instead of the local path Trivy read.
    renamed = {}
    root_ref = str(uuid.uuid5(namespace, "root"))
    if "bom-ref" in root:
        renamed[root["bom-ref"]] = root_ref
    root.update({"bom-ref": root_ref, "name": image, "version": digest,
                 "purl": f"pkg:oci/{quote(image.rsplit('/', 1)[-1])}@{quote(digest)}"
                         f"?repository_url={quote(image)}"})
    for component in sbom["components"]:
        ref = component.get("bom-ref", "")
        if UUID_PATTERN.match(ref):
            renamed[ref] = stable_ref(component, namespace)
            component["bom-ref"] = renamed[ref]
    for entry in dependencies:
        entry["ref"] = renamed.get(entry["ref"], entry["ref"])
        entry["dependsOn"] = [renamed.get(ref, ref) for ref in entry.get("dependsOn", [])]

    node = node_component(versions)
    sbom["components"].append(node)
    root_entry = next((entry for entry in dependencies if entry["ref"] == root_ref), None)
    if root_entry is None:
        root_entry = {"ref": root_ref, "dependsOn": []}
        dependencies.append(root_entry)
    root_entry["dependsOn"].append(node["bom-ref"])
    dependencies.append({"ref": node["bom-ref"], "dependsOn": [child["bom-ref"] for child in node["components"]]})
    for child in node["components"]:
        dependencies.append({"ref": child["bom-ref"], "dependsOn": []})

    sbom["components"] = sorted((sort_component(component) for component in sbom["components"]), key=component_key)
    sort_component(root)
    sbom["dependencies"] = sorted(({"ref": entry["ref"], "dependsOn": sorted(set(entry["dependsOn"]))}
                                   for entry in dependencies), key=lambda entry: entry["ref"])
    sbom["serialNumber"] = f"urn:uuid:{uuid.uuid5(namespace, 'sbom')}"
    metadata["timestamp"] = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) \
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    return sbom


def render(sbom):
    return json.dumps(sbom, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv):
    parser = argparse.ArgumentParser()
    for name in ("--sbom", "--versions", "--image", "--digest", "--epoch", "--out"):
        parser.add_argument(name, required=True)
    args = parser.parse_args(argv[1:])
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.digest) or not args.epoch.isdigit():
        print("sbom-merge.py: --digest must be sha256:<64 hex> and --epoch an integer", file=sys.stderr)
        return 2
    with open(args.sbom) as handle:
        sbom = json.load(handle)
    with open(args.versions) as handle:
        versions = json.load(handle)
    if not isinstance(versions, dict) or not isinstance(versions.get("node"), str):
        print("sbom-merge.py: --versions is not a process.versions object", file=sys.stderr)
        return 2
    with open(args.out, "w") as handle:
        handle.write(render(merge(sbom, versions, args.image, args.digest, args.epoch)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
