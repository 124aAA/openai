#!/usr/bin/env bash
# Explicit disposable-host acceptance. Real init and official core, no mock init.
set -Eeuo pipefail
umask 077
[[ ${1:-} == --disposable && $# -ge 4 ]] || { echo 'usage: acceptance-platform.sh --disposable /absolute/bundle --core-archive /official.tar.gz [--candidate-archive FILE --candidate-sha256 SHA]' >&2; exit 2; }
BUNDLE=$2
shift 2
CORE='' CANDIDATE='' CANDIDATE_SHA=''
while (($#)); do
  (($# >= 2)) || exit 2
  case "$1" in
    --core-archive) CORE=$2;;
    --candidate-archive) CANDIDATE=$2;;
    --candidate-sha256) CANDIDATE_SHA=$2;;
    *) exit 2;;
  esac
  shift 2
done
[[ $EUID == 0 && $BUNDLE == /* && -f $BUNDLE/install.sh && -f $CORE ]] || exit 2
[[ ! -e /var/lib/qingnode && ! -e /usr/local/bin/qingnode && ! -e /etc/systemd/system/qingnode.service && ! -e /etc/init.d/qingnode ]] || { echo 'refusing nonempty QingNode host' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'test-only Python3 is required' >&2; exit 1; }
WORK=$(mktemp -d /var/tmp/qingnode-platform-XXXXXXXX)
SCRIPTS=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export QINGNODE_VM_DISPOSABLE=1
EVIDENCE=${QINGNODE_PLATFORM_EVIDENCE_DIR:-$WORK/public-evidence}
[[ $EVIDENCE == /* && ! -L $EVIDENCE ]] || exit 2
install -d -m 700 "$EVIDENCE"
PHASE=environment
echo "QINGNODE_PLATFORM_WORK=$WORK"
finish() {
  local result=$?
  trap - EXIT
  python3 - "$EVIDENCE/acceptance-status.json" "$result" "$PHASE" <<'PY'
import json, os, pathlib, sys, time
path = pathlib.Path(sys.argv[1])
value = {'version': 1, 'exit_code': int(sys.argv[2]), 'last_phase': sys.argv[3],
         'finished_unix': time.time(), 'pid1': pathlib.Path('/proc/1/comm').read_text().strip(),
         'evidence_scope': 'disposable VM; no public or native ARM acceptance',
         'private_fixture_included': False}
with path.open('x') as output:
    json.dump(value, output, indent=2)
    output.write('\n')
os.chmod(path, 0o600)
PY
  if ((result)); then echo "FAILED: private disposable fixture retained at $WORK" >&2
  else echo "PASS: private fixture retained for bounded evidence collection at $WORK"; fi
  exit "$result"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
uname -a
cat /etc/os-release
cat /proc/1/comm
mkdir "$WORK/foreign"
printf 'foreign application data\n' > "$WORK/foreign/sentinel"
FOREIGN=$(sha256sum "$WORK/foreign/sentinel")
install_bundle() { bash "$BUNDLE/install.sh" "$@" 2>&1 | "$BUNDLE/qingnode" redact-log; }
PHASE=install
install_bundle --protocol ss2022 --name acceptance-ss --server 127.0.0.1 --listen 127.0.0.1 --port 443 --core-archive "$CORE"
qingnode capabilities --skip-loopback --json > "$EVIDENCE/capabilities.json"
python3 - "$EVIDENCE/capabilities.json" <<'PY'
import json, pathlib, sys
actual = json.loads(pathlib.Path(sys.argv[1]).read_text())['host']
expected = {}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
    key, sep, value = line.partition('=')
    if sep and key in ('ID', 'VERSION_ID'):
        expected[key] = value.strip().strip('"\'')
assert actual['distro'] == expected['ID'], 'host distro differs from actual os-release'
assert actual['distro_version'] == expected['VERSION_ID'], 'host version differs from actual os-release'
assert actual['init']['controller_available'], 'host init controller was not observed'
assert not actual['install_target'].startswith('unsupported:'), 'actual supported host reported unsupported'
PY
qingnode status
qingnode check
cp /var/lib/qingnode/current/state.json "$WORK/original-state.json"
PHASE=transport
python3 "$SCRIPTS/test-platform-flow.py" --disposable --work-dir "$WORK" --node acceptance-ss
cp "$WORK/flow-runtime.json" "$EVIDENCE/flow-runtime.json"
PHASE=managed-tls
python3 "$SCRIPTS/test-platform-tls.py" --disposable --work-dir "$WORK" --out "$EVIDENCE/managed-tls.json"
# Reinstallation is the manager upgrade transaction, not a fresh identity.
cp /var/lib/qingnode/current/state.json "$WORK/before-upgrade.json"
PHASE=manager-upgrade
install_bundle --reinstall --core-archive "$CORE"
cmp /var/lib/qingnode/current/state.json "$WORK/before-upgrade.json"
qingnode service disable
PHASE=stopped-state
qingnode stop
qingnode edit --id acceptance-ss --name acceptance-stopped
qingnode status > "$WORK/stopped-status.txt"
grep -q '^ActiveState=inactive$' "$WORK/stopped-status.txt"
install_bundle --reinstall --core-archive "$CORE"
qingnode status > "$WORK/stopped-after-upgrade.txt"
grep -q '^ActiveState=inactive$' "$WORK/stopped-after-upgrade.txt"
grep -q '^UnitFileState=disabled$' "$WORK/stopped-after-upgrade.txt"
qingnode edit --id acceptance-stopped --name acceptance-ss
qingnode start
qingnode service enable
openssl rand -base64 32 > "$WORK/passphrase"
PHASE=backup-restore
qingnode backup --file "$WORK/config.qnbak" --password-file "$WORK/passphrase"
qingnode edit --id acceptance-ss --port 14443
qingnode rollback
qingnode check
if qingnode edit --id acceptance-ss --port 0; then echo 'invalid port accepted' >&2; exit 1; fi
qingnode restore --file "$WORK/config.qnbak" --password-file "$WORK/passphrase" --yes
if [[ -n $CANDIDATE ]]; then
  PHASE=core-upgrade-rollback
  [[ -f $CANDIDATE && $CANDIDATE_SHA =~ ^[a-fA-F0-9]{64}$ ]] || exit 2
  qingnode update --version 1.14.3 --sha256 "$CANDIDATE_SHA" --archive "$CANDIDATE"
  qingnode check
  qingnode rollback
  qingnode check
fi
python3 "$SCRIPTS/test-platform-flow.py" --disposable --work-dir "$(mktemp -d "$WORK/recheck-XXXXXXXX")" --node acceptance-ss
PHASE=remove-reinstall
qingnode uninstall --yes
qingnode core install --archive "$CORE"
qingnode start
qingnode check
PHASE=auxiliary-services
python3 "$SCRIPTS/test-platform-aux.py" --disposable --work-dir "$WORK" --out "$EVIDENCE/auxiliary.json" --node acceptance-ss
if [[ ${QINGNODE_PLATFORM_FIREWALL_TEST:-0} == 1 ]]; then
  PHASE=firewalld
  python3 "$SCRIPTS/test-platform-firewall.py" --disposable --phase exercise --work-dir "$WORK" --out "$EVIDENCE/firewalld-exercise.json"
fi
PHASE=purge
qingnode uninstall --purge --yes
if [[ ${QINGNODE_PLATFORM_FIREWALL_TEST:-0} == 1 ]]; then
  python3 "$SCRIPTS/test-platform-firewall.py" --disposable --phase verify-after-uninstall --work-dir "$WORK" --out "$EVIDENCE/firewalld-uninstall.json"
  python3 "$SCRIPTS/test-platform-firewall.py" --disposable --phase cleanup --work-dir "$WORK" --out "$EVIDENCE/firewalld-cleanup.json"
fi
[[ ! -e /var/lib/qingnode && ! -e /usr/local/bin/qingnode && ! -e /etc/systemd/system/qingnode.service && ! -e /etc/init.d/qingnode ]]
[[ $(sha256sum "$WORK/foreign/sentinel") == "$FOREIGN" ]]
echo 'QINGNODE_PLATFORM_ACCEPTANCE_PASS=install,nonroot,lowport,tcp,udp,reinstall,stopped-state,backup,rollback,uninstall,foreign-data'
PHASE=complete
echo 'Reboot autostart, public reachability and native ARM require separately recorded checks; optional firewall evidence is separate.'
