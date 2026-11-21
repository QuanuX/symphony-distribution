"""Prepare optional Ubuntu node DEB carriers using the distribution's D08 format."""
import argparse
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile


PACKAGES = {
    "amd64": ("linux-64", "06dc5d3b62fa42d3f7274685f9d02a185f4bfe2a214b097941645f2c52a94ecf"),
    "arm64": ("linux-aarch64", "9221fc8c99d1bc1bf37bb6637ffd6cc044732d8a0703bd0919037219823c094c"),
}
BUILD_SOURCE = "e0c60d911676778bab5663145112dd3dfde4418f"
RELEASE_SOURCE = "f828e558cae86ffb860a4fd3b55c6e0d0623d1c9"
SOURCE_TREE = "db96c62e62378499f9adb24dfc7b3ea170d01887"


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def indexed_deb(path, arch):
    data = subprocess.check_output(["/usr/bin/ar", "-p", str(path), "control.tar.xz"])
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
        control = archive.extractfile("./control").read().decode("utf-8")
    fields = dict(line.split(": ", 1) for line in control.splitlines()
                  if not line.startswith(" ") and ": " in line)
    if (fields["Package"], fields["Version"], fields["Architecture"]) != (
        "symphony-node-keyring", "0.1.1~dev2", arch
    ):
        raise ValueError("Unexpected Debian package version or architecture")
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ["core", "distribution", "debs", "out"]:
        parser.add_argument("--" + arg, type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        raise FileExistsError(out)
    if any(git(args.core, "rev-parse", sha + "^{tree}") != SOURCE_TREE
           for sha in [BUILD_SOURCE, RELEASE_SOURCE]):
        raise ValueError("Mismatched build/release source tree")
    sys.path.insert(0, str(args.distribution.resolve() / "installer_assembly"))
    import carriers as c
    from supplements import write_archive
    out.mkdir(parents=True)
    results = []
    # This is a supplemental Ubuntu 26.04 ARM64 delivery, distinct from the
    # Ubuntu 24.04 ARM64 installer. Only the local carrier routing is extended.
    c.PROFILES["ubuntu26.04-arm64"] = ("linux-aarch64", "linux", "arm64")
    for arch, (subdir, digest) in PACKAGES.items():
        name = f"symphony-node-keyring_0.1.1~dev2_{arch}.deb"
        path = args.debs.resolve() / name
        raw = path.read_bytes()
        c.require(c.sha(raw) == digest, "Debian bytes differ from the verified dev2 package")
        fields = indexed_deb(path, arch)
        profile = f"ubuntu26.04-{arch}"
        provenance = {"built_source_commit": BUILD_SOURCE, "merged_source_commit": RELEASE_SOURCE,
                      "source_tree": SOURCE_TREE, "filename": name, "sha256": digest,
                      "debian_version": fields["Version"], "debian_dependencies": fields["Depends"],
                      "profile": profile, "native_deployment_owner": "Debian package manager"}
        unit = {"unit_id": "debian:node-keyring", "kind": "optional_debian_delivery",
                "component_id": "node-keyring-deb", "native_version": "0.1.1-dev",
                "dependency_units": [], "external_dependency_units": [], "sdk_exports": [],
                "payload_paths": [], "provenance": provenance, "optional_install": True}
        recipe_dir = out / "recipes" / profile
        evidence = {"source_commit": RELEASE_SOURCE, "source_tree": SOURCE_TREE,
                    "native_package_sha256": digest, "target": profile}
        entry = c.recipe(unit, recipe_dir, [c.file_row(name, raw)], {name: lambda: raw},
                         profile, evidence, None)
        entry["recipe_path"] = recipe_dir.relative_to(out).as_posix()
        result = write_archive(out, entry)
        c.require(result["subdir"] == subdir, "Incorrect platform")
        results.append({**result, "profile": profile, "payload_tar_sha256": entry["payload_sha256"],
                        "carrier_destination": entry["carrier_destination"], "debian": provenance})

    (out / "supplement.json").write_text(json.dumps({
        "release_candidate": "0.2.0-beta.2.1", "distribution_toolkit": git(args.distribution, "rev-parse", "HEAD"),
        "source_commit": RELEASE_SOURCE, "source_tree": SOURCE_TREE, "conda_package_handling": "2.6.0",
        "default_installer_inclusion": False, "archives": results
    }, indent=2) + "\n")
    (out / "SHA256SUMS").write_text("".join(
        f"{r['sha256']}  channel/{r['subdir']}/{r['filename']}\n" for r in results))


if __name__ == "__main__":
    main()
