"""Render the Cloudflare Bulk Redirects configuration from the published beta records."""

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOST = "downloads.quanux.org"
CHANNEL = "https://conda.anaconda.org/QuanuX/label/"
DOWNLOADS = "https://quanux.org/downloads"
LIST_NAME = "symphony_public_downloads"
PUBLICATIONS = (
    "evidence/d14-publication.json",
    "evidence/beta2-publication.json",
    "evidence/beta21-publication.json",
)
SUBDIRS = {
    "macos15-arm64": "osx-arm64",
    "ubuntu24.04-amd64": "linux-64",
    "ubuntu24.04-arm64": "linux-aarch64",
    "ubuntu26.04-amd64": "linux-64",
}


def redirects(root=ROOT):
    paths = {
        "/": DOWNLOADS,
        "/symphony": DOWNLOADS,
        "/symphony/": DOWNLOADS,
        "/favicon.ico": "https://quanux.org/favicon.svg",
        "/robots.txt": "https://quanux.org/robots.txt",
    }
    for publication in PUBLICATIONS:
        record = json.loads((root / publication).read_bytes())
        release = record["release"]
        index_digest = record["signature"]["release_index_sha256"]
        label = f"beta-{release}-{index_digest[:12]}"
        prefix = f"/symphony/{release}"
        tag = f"https://github.com/QuanuX/symphony-distribution/releases/tag/v{release}"
        paths[prefix] = paths[prefix + "/"] = tag
        channel = record["anaconda"]
        profiles = channel.get("per_profile") or channel["profiles"]
        if set(profiles) != set(SUBDIRS):
            raise ValueError(f"Unexpected profile inventory for {release}")
        for profile, receipt in profiles.items():
            raw = (root / receipt["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != receipt["sha256"]:
                raise ValueError(f"Package receipt differs for {release}/{profile}")
            data = json.loads(raw)
            packages = data if isinstance(data, list) else data["packages"]
            for package in packages:
                name = package["filename"]
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+\-]*\.conda", name):
                    raise ValueError(f"Invalid package filename for {release}/{profile}")
                archive = f"{SUBDIRS[profile]}/{name}"
                expected = f"{CHANNEL}beta/{archive}"
                observed = package.get("public_readbacks") or [package["url"]]
                if expected not in observed:
                    raise ValueError(f"Package receipt does not match {archive}")
                path = f"{prefix}/packages/{profile}/{name}"
                if path in paths:
                    raise ValueError(f"Duplicate package address: {path}")
                paths[path] = f"{CHANNEL}{label}/{archive}"
    return paths


def configuration():
    items = [
        {"redirect": {
            "source_url": HOST + path, "target_url": url, "status_code": 301,
            "include_subdomains": False, "subpath_matching": False,
            "preserve_path_suffix": False, "preserve_query_string": False,
        }}
        for path, url in sorted(redirects().items())
    ]
    return {
        "list": {"name": LIST_NAME, "kind": "redirect", "description": "Symphony public download links"},
        "items": items,
        "rule": {
            "ref": LIST_NAME,
            "description": "Resolve published Symphony download links",
            "expression": (f'http.host eq "{HOST}" and http.request.method in {{"GET" "HEAD"}} '
                           f'and http.request.full_uri in ${LIST_NAME}'),
            "action": "redirect", "enabled": True,
            "action_parameters": {"from_list": {"name": LIST_NAME, "key": "http.request.full_uri"}},
        },
    }


if __name__ == "__main__":
    print(json.dumps(configuration(), indent=2))
