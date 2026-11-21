#!/usr/bin/env python3
"""Install the current Symphony public beta and its supporting packages for this user."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile


RELEASE = "0.2.0-beta.2.1"
VERIFIER_SHA256 = "0c94359511013edb19d990f853b2720a2049ceb40f6aa2ad9dd47b603156b547"
INDEX_SHA256 = "69c89fef8a2ab2eed8e78b56168fcdbbf285989fedf698a43ea499cd2883e9f0"
GITHUB = f"https://github.com/QuanuX/symphony-distribution/releases/download/v{RELEASE}"
DOWNLOADS = f"https://downloads.quanux.org/symphony/{RELEASE}"
ARCHIVES = {
    "macos15-arm64": "MacOSX-arm64",
    "ubuntu24.04-amd64": "Linux-x86_64",
    "ubuntu24.04-arm64": "Linux-aarch64",
    "ubuntu26.04-amd64": "Linux-x86_64",
}


def host_profile():
    system, machine = platform.system(), platform.machine().lower()
    if system == "Darwin":
        version = platform.mac_ver()[0]
        if version.split(".")[0] == "15" and machine == "arm64":
            return "macos15-arm64"
        raise ValueError(f"Detected macOS {version} ({machine}). The macOS beta requires macOS 15 and native Apple Silicon.")
    if system == "Linux":
        os_info = platform.freedesktop_os_release()
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine)
        profile = os_info.get("ID", "") + os_info.get("VERSION_ID", "") + "-" + arch
        if os_info.get("ID") == "ubuntu" and profile in ARCHIVES:
            return profile
        detected = f"{os_info.get('PRETTY_NAME', 'Linux')} ({machine})"
    else:
        detected = f"{system} ({machine})"
    raise ValueError(f"Unsupported system: {detected}. See supported platforms at https://quanux.org/downloads.")


def check_digest(path, expected):
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected:
        raise ValueError(f"SHA-256 verification failed for {path.name}.")


def fetch(url, path, limit):
    subprocess.run([
        "curl", "--disable", "--fail", "--silent", "--show-error", "--location",
        "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "30",
        "--retry", "2", "--max-filesize", str(limit), "--output", str(path), url,
    ], check=True)
    if path.stat().st_size > limit:
        raise ValueError(f"Download exceeds the expected size: {path.name}.")


def verify(work, artifact):
    subprocess.run([sys.executable, "-I", str(work / "verify_beta.py"),
                    "--release", RELEASE, "--artifact", artifact], cwd=work, check=True,
                   stdout=subprocess.DEVNULL)


def prepare(work, profile):
    for name, limit in (("verify_beta.py", 1024 * 1024), ("beta-cert.pem", 65536),
                        ("beta-manifest.json", 4 * 1024 * 1024), ("beta-manifest.sig", 384),
                        ("release-index.json", 4 * 1024 * 1024)):
        fetch(f"{GITHUB}/{name}", work / name, limit)
    check_digest(work / "verify_beta.py", VERIFIER_SHA256)
    check_digest(work / "release-index.json", INDEX_SHA256)
    verify(work, "release-index.json")
    index = json.loads((work / "release-index.json").read_bytes())
    selected = f"installers/{profile}/Symphony-{RELEASE}-{ARCHIVES[profile]}.sh"
    installer, = [row for row in index["artifacts"] if row["path"] == selected]
    path = work / selected
    path.parent.mkdir(parents=True)
    print(f"Downloading the {profile} installer ({installer['size'] / 1_000_000:.0f} MB)…", flush=True)
    fetch(f"{DOWNLOADS}/{selected}", path, installer["size"])
    verify(work, selected)
    return path, index["profiles"][profile]


def install(root, archive, profile_info):
    # Constructor requires its final prefix. Reserve a fresh parent atomically so
    # two installers cannot start writing the same prefix.
    root.mkdir(mode=0o700)
    packages, tools = root / "packages", root / "tools"
    try:
        print(f"Installing the verified packages in {packages}…", flush=True)
        environment = os.environ.copy()
        environment.pop("BASH_ENV", None)
        environment.pop("ENV", None)
        with (root / "install.log").open("xb") as log:
            subprocess.run(["/bin/bash", str(archive), "-b", "-p", str(packages)],
                           cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)
            helper = packages / "share/symphony/installer/symphony-retain.py"
            check_digest(helper, profile_info["retention_helper_sha256"])
            subprocess.run([sys.executable, "-I", str(helper), "--prefix", str(packages),
                            "--index-sha256", profile_info["retention_index_sha256"],
                            "--output", str(tools), "--owners"], cwd=root,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        (root / "bin").mkdir(mode=0o700)
        cli = root / "bin/qxctl"
        cli.symlink_to("../tools/candidate/go/qxctl/bin/qxctl")
        subprocess.run([str(cli), "version"], cwd=root, check=True)
    except (OSError, ValueError, subprocess.CalledProcessError, KeyboardInterrupt):
        # Preserve any partial installation without blocking a fresh retry.
        incomplete = Path(tempfile.mkdtemp(prefix=f".{root.name}-incomplete-", dir=root.parent))
        root.replace(incomplete)
        print(f"Incomplete installation preserved at {incomplete}. See its install.log for details.", file=sys.stderr)
        raise
    print(f"Symphony {RELEASE} is ready.\n"
          f"Check your installation: {shlex.quote(str(cli))} version\n"
          f"Codex client: {tools / 'client'}\n"
          f"Client setup: {DOWNLOADS}/docs/BETA-INSTALL.md")


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if sys.version_info < (3, 11):
        raise ValueError("Python 3.11 or newer is required.")
    profile = host_profile()
    if os.geteuid() == 0:
        raise ValueError("Run the installer as your normal user, without sudo.")
    for command in ("curl", "openssl", "/bin/bash"):
        if not shutil.which(command):
            raise ValueError(f"Required command missing: {command}.")
    home = Path.home().resolve(strict=True)
    if not home.is_dir() or home.stat().st_uid != os.getuid():
        raise ValueError("Your home directory must be owned by your account.")
    root = home / f"symphony-{RELEASE}"
    if os.path.lexists(root):
        raise ValueError(f"{root} already exists. Check your existing installation with "
                         f"{shlex.quote(str(root / 'bin/qxctl'))} version. For other setups, see {DOWNLOADS}/docs/BETA-INSTALL.md.")
    os.umask(0o077)
    print(f"Preparing Symphony {RELEASE} for {profile}…", flush=True)
    with tempfile.TemporaryDirectory(prefix="symphony-download-") as temporary:
        work = Path(temporary).resolve(strict=True)
        archive, profile_info = prepare(work, profile)
        install(root, archive, profile_info)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Installation interrupted.")
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"Installation stopped: {error}")
