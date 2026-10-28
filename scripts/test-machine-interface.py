#!/usr/bin/env python3
"""Run the exact built CLI against private offline State and owned local sockets.

No service install, public network, production State or proxy traffic is involved.
The independent terminal/core/platform gates remain necessary.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('terminal_binary_guard', Path(__file__).with_name('test-terminal-workflow.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

CHECKS = [
    'actual-cli-private-running-and-final-receipts',
    'actual-cli-noop-preserves-generation-and-identity',
    'actual-cli-public-object-json-nat-ipv6-and-credential-redaction',
    'actual-cli-explicit-export-bytes-not-captured-in-receipt',
    'actual-cli-invalid-input-receipt-without-State-initialization',
    'actual-cli-result-directory-conflict-precedes-mutation',
    'actual-cli-offline-doctor-preserves-pending-transaction',
    'actual-cli-real-tcp-udp-listeners-not-business-or-public-proof',
    'actual-cli-canceled-query-reaps-owned-process',
    'actual-cli-query-output-limit-reaps-owned-process',
    'actual-cli-query-timeout-reaps-owned-process',
    'actual-cli-result-publication-conflict-never-overwrites',
    'actual-cli-concurrent-edits-have-truthful-receipts-and-keep-identities',
]


def require(value, category):
    if not value:
        raise RuntimeError(category)


def document(raw):
    require(len(raw) <= 4 << 20, 'machine output exceeds budget')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    require(isinstance(value, dict) and value.get('version') == 1, 'invalid machine document version')
    return value


def receipt(directory, expected, code):
    start = document((directory / 'started.json').read_bytes())
    final = document((directory / 'result.json').read_bytes())
    require(start['status'] == 'running' and start['exit_code'] is None and start['finished_at'] is None,
            'starting receipt claimed completion')
    require(final['kind'] == 'qingnode-command-result' and final['status'] == expected and final['exit_code'] == code,
            'execution outcome differs from command return')
    require('actual process exit code' in final['exit_code_scope'], 'operation/process exit code scope absent')
    require(directory.stat().st_mode & 0o777 == 0o700, 'result directory permissions')
    for name in ('started.json', 'result.json'):
        require((directory / name).stat().st_mode & 0o777 == 0o600, 'result file permissions')
    return final


def run_suite(binary, work):
    state_root = work / 'state'
    prefix = [str(binary), '--offline', '--root', str(state_root)]

    def call(args, *, report=None, expected=0, env=None, timeout=15):
        command = prefix + list(args)
        if report is not None:
            command = [str(binary), '--result-dir', str(report), *prefix[1:], *args]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, timeout=timeout)
        require(result.returncode == expected, 'unexpected CLI exit code')
        require(len(result.stdout) + len(result.stderr) <= 4 << 20, 'CLI output exceeds evidence budget')
        return result

    def state():
        return json.loads((state_root / 'current/state.json').read_bytes())

    init = ['init', '--protocol', 'ss2022', '--server', '203.0.113.8', '--listen', '127.0.0.1',
            '--port', '24443', '--connect-port', '30000', '--name', '手机 中文😀', '--quiet']
    created = work / 'created'
    call(init, report=created)
    first = receipt(created, 'completed', 0)
    require(first['apply_confirmations_observed'] == 1, 'initial Apply confirmation absent')
    original_generation = os.readlink(state_root / 'current')
    original = state()
    node_id, user_id = original['nodes'][0]['id'], original['nodes'][0]['users'][0]['id']
    repeated = work / 'repeated'
    call(init, report=repeated)
    receipt(repeated, 'completed', 0)
    require(state() == original and os.readlink(state_root / 'current') == original_generation,
            'no-op altered node identity or generation')

    call(['endpoint', 'add', '--id', node_id, '--endpoint', '6666666666666666', '--server', '[2001:db8::8]', '--connect-port', '30001'])
    remote_password = 'private-machine-fixture-password'
    call(['egress', 'add', '--id', '3333333333333333', '--name', '出口 中文', '--protocol', 'socks5',
          '--server', '203.0.113.9', '--port', '35443', '--username', 'fixture-user', '--password', remote_password])
    call(['forward', 'add', '--id', '4444444444444444', '--name', '中转 中文', '--listen', '127.0.0.1', '--port', '35555',
          '--network', 'tcp+udp', '--target-host', '203.0.113.10', '--target-port', '443'])
    call(['device', 'create', '--name', '手机 设备', '--binding', node_id + ':' + user_id])
    device_id = state()['devices'][0]['id']
    call(['expiration', 'set', '--node', node_id, '--user', user_id, '--expires-at', '2090-01-02T03:04:05Z', '--yes'])
    private_state = state()
    secrets = [remote_password, original['nodes'][0]['shadowsocks']['server_key'], original['nodes'][0]['users'][0]['password']]
    queries = [
        ['status', '--json'], ['overview', '--json'], ['list', '--json'], ['info', '--id', node_id, '--json'],
        ['dns', 'show', '--json'], ['hy2', 'show', '--json'], ['endpoint', 'list', '--id', node_id, '--json'],
        ['egress', 'list', '--json'], ['egress', 'show', '--id', '3333333333333333', '--json'],
        ['egress', 'policy', 'list', '--json'], ['forward', 'list', '--json'],
        ['device', 'list', '--json'], ['device', 'show', '--id', device_id, '--json'],
        ['expiration', 'list', '--json'], ['subscription', 'status', '--json'],
    ]
    before = (state_root / 'current/state.json').read_bytes()
    for args in queries:
        report = document(call(args).stdout)
        rendered = json.dumps(report, ensure_ascii=False)
        require(all(value not in rendered for value in secrets), 'public query exposed authentication')
        if args[:2] == ['endpoint', 'list']:
            data = report['data']
            require(data['listen_port'] == 24443 and [entry['port'] for entry in data['connection_endpoints']] == [30000, 30001]
                    and data['connection_endpoints'][1]['host'] == '2001:db8::8' and data['public_ingress'] == 'unknown',
                    'NAT/IPv6 declaration or observation scope incorrect')
    require(before == (state_root / 'current/state.json').read_bytes(), 'queries modified State')
    export = call(['export', '--id', node_id, '--user', user_id, '--format', 'uri']).stdout
    exported = work / 'exported'
    require(call(['export', '--id', node_id, '--user', user_id, '--format', 'uri'], report=exported).stdout == export,
            'receipt altered private export')
    receipt(exported, 'completed', 0)
    require(all(value.encode() not in (exported / 'result.json').read_bytes() for value in [*secrets, export.decode().strip()]),
            'execution receipt captured private stdout')
    absent = work / 'absent-state'
    invalid = work / 'invalid'
    result = subprocess.run([str(binary), '--result-dir', str(invalid), '--offline', '--root', str(absent),
                             'add', '--protocol', 'ss2022', '--port', 'private-invalid-input'],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    require(result.returncode == 1 and not absent.exists(), 'invalid input changed State')
    receipt(invalid, 'failed', 1)
    require(b'private-invalid-input' not in (invalid / 'result.json').read_bytes(), 'receipt exposed an input')
    call(['edit', '--id', node_id, '--name', 'must-not-apply'], report=created, expected=1)
    require(before == (state_root / 'current/state.json').read_bytes(), 'existing result path allowed mutation')
    journal = state_root / 'transaction.json'
    pending = b'preserve interrupted transaction exactly'
    journal.write_bytes(pending)
    diagnosis = document(call(['doctor', '--json'], expected=1).stdout)
    require(diagnosis['offline'] and diagnosis['public_ingress'] == 'unknown'
            and any(check['id'] == 'pending/transaction.json' and check['status'] == 'degraded' for check in diagnosis['checks']),
            'offline diagnostic invented connectivity or repaired transaction')
    require(journal.read_bytes() == pending and before == (state_root / 'current/state.json').read_bytes(), 'doctor mutated recovery material')
    journal.unlink()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1', 0)); tcp.listen(1); udp.bind(('127.0.0.1', 0))
        listeners = document(call(['ports', '--json']).stdout)
        require(listeners['query_status'] == 'completed' and listeners['public_ingress'] == 'unknown'
                and listeners['proxy_authentication'] == 'not-tested' and listeners['udp_business_traffic'] == 'not-tested',
                'listener observation fabricated proxy or public proof')
        for network, port in [('tcp', tcp.getsockname()[1]), ('udp', udp.getsockname()[1])]:
            require(any(item['transport'] == network and item['local_endpoint'] == '127.0.0.1:' + str(port)
                        for item in listeners['listeners']), 'real owned listener absent')

    helper_dir = work / 'helper'; helper_dir.mkdir(mode=0o700)
    helper = helper_dir / 'ss'
    helper.write_text('#!' + sys.executable + '\n' + '''from pathlib import Path
import os,sys,time
Path(os.environ['QINGNODE_MACHINE_CHILD_PID']).write_text(str(os.getpid()))
mode=os.environ['QINGNODE_MACHINE_CHILD_MODE']
if mode=='oversized':
 for _ in range(96):sys.stdout.buffer.write(b'x'*(64<<10));sys.stdout.buffer.flush()
elif mode=='release':
 deadline=time.monotonic()+6
 while not Path(os.environ['QINGNODE_MACHINE_RELEASE']).exists() and time.monotonic()<deadline:time.sleep(.01)
 print('udp UNCONN 0 0 127.0.0.1:5353 0.0.0.0:*')
else:time.sleep(30)
''', encoding='utf-8')
    helper.chmod(0o700)
    for mode in ('cancel', 'oversized', 'timeout', 'release'):
        pidfile = work / ('owned-' + mode + '.pid')
        output_dir = work / ('query-' + mode)
        release = work / 'release'
        env = {**os.environ, 'PATH': str(helper_dir) + os.pathsep + os.environ.get('PATH', os.defpath),
               'QINGNODE_MACHINE_CHILD_PID': str(pidfile), 'QINGNODE_MACHINE_CHILD_MODE': mode,
               'QINGNODE_MACHINE_RELEASE': str(release)}
        process = subprocess.Popen([str(binary), '--result-dir', str(output_dir), *prefix[1:], 'ports', '--json'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        child_pid = None
        try:
            deadline = time.monotonic() + 4
            while not pidfile.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            require(pidfile.exists(), 'owned query helper did not start')
            child_pid = int(pidfile.read_text())
            require(child_pid > 0, 'invalid owned query PID')
            if mode == 'cancel':
                process.send_signal(signal.SIGTERM)
            elif mode == 'release':
                (output_dir / 'result.json').write_bytes(b'foreign-result-do-not-overwrite')
                release.write_bytes(b'1')
            stdout, stderr = process.communicate(timeout=12)
            require(process.returncode == 1 and len(stdout) + len(stderr) < 64 << 10, 'failure budget/exit code incorrect')
            value = document(stdout)
            if mode == 'release':
                require(value['query_status'] == 'completed' and (output_dir / 'result.json').read_bytes() == b'foreign-result-do-not-overwrite',
                        'publication conflict overwrote foreign file or changed query result')
            else:
                category = {'cancel': 'canceled', 'oversized': 'result-size-limit', 'timeout': 'timeout'}[mode]
                require(value['error_category'] == category and value['listeners'] is None, 'query cancellation/error fabricated data')
                receipt(output_dir, 'canceled' if mode == 'cancel' else 'failed', 1)
            require(not Path('/proc', str(child_pid)).exists(), 'owned query process survived completion')
        finally:
            if process.poll() is None:
                process.kill(); process.communicate(timeout=3)
            if child_pid is not None and Path('/proc', str(child_pid)).exists():
                executable = Path('/proc', str(child_pid), 'exe')
                if executable.exists() and os.path.samefile(executable, sys.executable):
                    os.kill(child_pid, signal.SIGKILL)

    def edit(index):
        directory = work / ('parallel-' + str(index))
        result = subprocess.run([str(binary), '--result-dir', str(directory), *prefix[1:], 'edit', '--id', node_id,
                                 '--name', 'parallel-' + str(index)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=10)
        require(result.returncode in (0, 1), 'unexpected concurrent command exit')
        receipt(directory, 'completed' if result.returncode == 0 else 'failed', result.returncode)
        return result.returncode
    with ThreadPoolExecutor(max_workers=2) as executor:
        codes = list(executor.map(edit, range(2)))
    require(0 in codes, 'no concurrent edit completed')
    final = state()
    require(final['nodes'][0]['users'] == private_state['nodes'][0]['users']
            and final['nodes'][0]['shadowsocks'] == private_state['nodes'][0]['shadowsocks']
            and final['nodes'][0]['name'] in ('parallel-0', 'parallel-1'), 'concurrent edits damaged authentication')
    call(['validate-state', '--file', str(state_root / 'current/state.json')])
    return CHECKS


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable', action='store_true', required=True)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.platform != 'linux':
        parser.error('actual Linux CLI execution required; not a Windows mock')
    binary = guard.checked_binary(args.bin, args.sha256)
    if not args.out.is_absolute() or args.out.exists() or args.out.is_symlink():
        parser.error('new absolute report path required')
    with tempfile.TemporaryDirectory(prefix='qingnode-machine-') as temporary:
        checks = run_suite(binary, Path(temporary))
    report = {'version': 1, 'status': 'passed', 'source': 'actual-built-linux-cli-private-state-and-owned-sockets',
              'binary_sha256': args.sha256, 'checks': checks, 'production_state_or_services_changed': False,
              'raw_output_or_private_fixture_included': False, 'proxy_authentication': 'not-tested',
              'public_ingress': 'unknown', 'client_GUI': 'not-tested'}
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(report, output, indent=2); output.write('\n'); output.flush(); os.fsync(output.fileno())
    print('PASS actual built CLI JSON and private receipts; service and public transport remain separate')


if __name__ == '__main__':
    main()
