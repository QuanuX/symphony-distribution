#!/usr/bin/env bash
set -euo pipefail
[[ -f /.dockerenv && $(id -u) == 0 && -z $(hostname -I | tr -d '[:space:]') ]]
arch=$1
subdir=$2
[[ $(dpkg --print-architecture) == "$arch" ]]
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 26.04 ]]
if ! id ubuntu >/dev/null 2>&1; then useradd --create-home --shell /bin/sh ubuntu; fi
conda=/tools/standalone-$arch
pkg_prefix=/tmp/symphony-conda
prefix=/opt/symphony
[[ ! -e "$prefix" && ! -e "$pkg_prefix" ]]
export CONDA_PKGS_DIRS=/tmp/pkgcache CONDA_SOLVER=classic CONDA_NO_PLUGINS=true CONDARC=/tmp/condarc
printf 'channels: []\nregister_envs: false\nreport_errors: false\n' >"$CONDARC"
conda_cmd=(runuser -u ubuntu -- "$conda" --no-plugins)
echo "Host $ID $VERSION_ID $arch"
"${conda_cmd[@]}" --version
cd /candidate
sha256sum -c SHA256SUMS
archive=(channel/"$subdir"/*.conda)
[[ ${#archive[@]} == 1 ]]
hash=$(sha256sum "${archive[0]}" | cut -d' ' -f1)
printf '@EXPLICIT\nfile:///candidate/%s#sha256:%s\n' "${archive[0]}" "$hash" >/tmp/candidate-explicit.txt
"${conda_cmd[@]}" create -y --offline -p "$pkg_prefix" --file /tmp/candidate-explicit.txt
[[ ! -e "$prefix" ]]
carrier=("$pkg_prefix"/share/symphony/carriers/node-keyring-deb/0.1.1-dev/*/payload.tar)
[[ ${#carrier[@]} == 1 ]]
deb="symphony-node-keyring_0.1.1~dev2_${arch}.deb"
mkdir /tmp/received
tar -xOf "${carrier[0]}" "$deb" >/tmp/received/"$deb"
python3 - "$arch" "/tmp/received/$deb" <<'PY'
import hashlib, json, sys
from pathlib import Path
rows = json.loads(Path('/candidate/supplement.json').read_text())['archives']
selected = next(r for r in rows if r['profile'] == 'ubuntu26.04-' + sys.argv[1])
assert hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest() == selected['debian']['sha256']
PY
dpkg -i "/tmp/received/$deb"
[[ $(dpkg-query -W -f='${Version}' symphony-node-keyring) == '0.1.1~dev2' ]]
find "$prefix"/libexec/symphony/ssiag-node-keyring -type f | sort
! find /etc/systemd/system -type l -name 'symphony-node-keyring*' | grep -q .
source_dir=/source/modules/secure-identity-access-governance/platform/linux-node-keyring
export CXX=clang++-21 CMAKE_GENERATOR=Ninja
cmake -S "$source_dir/tests/installed" -B /tmp/consumer -DCMAKE_PREFIX_PATH="$prefix"
cmake --build /tmp/consumer --parallel 2
consumer=/tmp/consumer/node-keyring-installed-consumer
runuser -u ubuntu -- "$consumer" --expect-refusal binding /tmp/missing-node-binding
echo 'PASS consumer linked against both packaged native SDKs and returned the expected refusal'
bin=$prefix/libexec/symphony/ssiag-node-keyring/0.1.1-dev
bash "$source_dir/tests/activate-test.sh" "$bin/symphony-node-keyring-activate"
/tools/fixture-"$arch" ssh "$prefix" "$consumer"
/tools/fixture-"$arch" restart "$bin/symphony-node-keyring-session" "$bin/symphony-node-keyring-import" "$consumer"
dpkg -r symphony-node-keyring
[[ ! -e "$bin/symphony-node-keyring-session" ]]
"${conda_cmd[@]}" remove --offline -y -p "$pkg_prefix" --all
[[ ! -e "$pkg_prefix/conda-meta" ]]
echo "PASS Ubuntu 26.04 $arch Conda delivery, native installation, offline authentication and removal"
