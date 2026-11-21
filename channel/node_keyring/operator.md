# Optional Linux node keyring for Symphony beta 2.1

These Ubuntu 26.04 downloads contain Debian package `symphony-node-keyring` version `0.1.1~dev2`. Select the `ubuntu26.04-amd64` or `ubuntu26.04-arm64` directory for the node. The Conda archive delivers the same Debian package under the selected Conda prefix. The Debian package manager owns the runtime and SDKs under `/opt/symphony`.

Download `beta-manifest.json`, `beta-manifest.sig`, `beta-cert.pem`, `publisher-decision.json`, `release-index.json`, and the files you select, preserving their release-relative paths. Verify the files with the distribution's independently pinned `channel/verify_beta.py`. For example on AMD64, run the following from the downloaded release root. Substitute `ubuntu26.04-arm64` on ARM64.

```sh
profile=ubuntu26.04-amd64
base=supplements/linux-node-keyring
python3 /path/to/symphony-distribution/channel/verify_beta.py \
  --artifact-root . --signature-root . --release 0.2.0-beta.2.1 \
  --artifact "$base/index.json" --artifact "$base/$profile/explicit.txt" \
  --artifact "$base/$profile/symphony-node-keyring.deb" \
  --artifact source/optional-node-keyring/corresponding-source.tar.gz
```

To install directly on an Ubuntu node, use the verified Debian download. Package installation places inactive service profiles and does not enroll a node.

```sh
sudo apt install "./$base/$profile/symphony-node-keyring.deb"
```

To receive the Debian package through Anaconda, first install the verified architecture-specific explicit file into a fresh prefix. Use a new working directory for the extracted Debian file. The signed index gives the expected embedded filename, location, and hash.

```sh
set -eu
prefix="$PWD/node-delivery"
conda create --prefix "$prefix" --file "$base/$profile/explicit.txt"
mkdir extracted-deb
(
  cd extracted-deb
  arch=$(dpkg --print-architecture)
  deb="symphony-node-keyring_0.1.1~dev2_${arch}.deb"
  tar -xOf "$prefix"/share/symphony/carriers/node-keyring-deb/0.1.1-dev/*/payload.tar "$deb" >"$deb"
  case "$arch" in
    amd64) digest=06dc5d3b62fa42d3f7274685f9d02a185f4bfe2a214b097941645f2c52a94ecf ;;
    arm64) digest=9221fc8c99d1bc1bf37bb6637ffd6cc044732d8a0703bd0919037219823c094c ;;
    *) exit 1 ;;
  esac
  printf '%s  %s\n' "$digest" "$deb" | sha256sum -c -
  sudo apt install "./$deb"
)
```

After installation, use the versioned node README in `/opt/symphony/share/symphony/ssiag-node-keyring/0.1.1-dev/README.md` to enroll the service account, set the pinned OpenSSH ingress, and configure the local keyring. C++ consumers use `find_package(SymphonyNodeKeyring 0.1.1 EXACT CONFIG REQUIRED)` and link `Symphony::NodeKeyring`. Select `-DCMAKE_PREFIX_PATH=/opt/symphony` and install the development prerequisites described in the source README. Provision remotely over SSH and fetch locally during a connection handshake or reconnect. The installed offline tests use a disposable software-backed local store. A hardware-gated deployment requires its own TPM2 or FIDO2 qualification.

Remove the host package with `sudo apt remove symphony-node-keyring`. Remove a dedicated Conda delivery prefix with `conda remove --prefix "$prefix" --all`. Manage vaults, service enrollment, and credentials through the node's configured owner procedures.
