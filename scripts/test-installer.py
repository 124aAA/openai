#!/usr/bin/env python3
"""Isolated bootstrap fault tests. Real Bash/files/CLI; simulated host commands.

Does not install on this host. Fixed production paths are rewritten in a temporary
copy of install.sh. Mocks reject network access and perform no service/account/
firewall changes. This is NOT Debian/Ubuntu VM acceptance testing.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1]
MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, shutil, subprocess, sys
r=pathlib.Path(os.environ['QN_FIXTURE'])
name=pathlib.Path(sys.argv[0]).name
a=sys.argv[1:]
db=r/'host.json'
s=json.loads(db.read_text())
def save():
 tmp=r/('host-'+str(os.getpid())+'.tmp')
 tmp.write_text(json.dumps(s)); tmp.replace(db)
def fail(point):
 if os.environ.get('QN_FAULT')==point and not (r/'fault-fired').exists():
  (r/'fault-fired').touch()
  print('injected '+point+' failure', file=sys.stderr)
  sys.exit(1)
with (r/'commands.log').open('a') as f: f.write(name+' '+' '.join(a)+'\n')
if name=='ps': print('systemd')
elif name=='uname': print('x86_64')
elif name=='sshd': print('port 22')
elif name=='getent':
 if a[0]=='ahosts':
  if os.environ.get('QN_DNS_FAIL'): sys.exit(2)
  print('192.0.2.2 STREAM github.com')
 elif a[0] in ('passwd','group'):
  if not s.get(a[0]): sys.exit(2)
  print('qingnode:x:999:999::/nonexistent:/usr/sbin/nologin' if a[0]=='passwd' else 'qingnode:x:999:')
 else: sys.exit(2)
elif name=='useradd':
 fail('useradd'); s.update(passwd=True, group=True); save()
elif name=='userdel':
 s.update(passwd=False, group=False); save()
elif name=='install':
 if any('qingnode.service.new.' in x for x in a): fail('unit-write')
 cleaned=[]; i=0
 while i<len(a):
  if a[i] in ('-o','-g'): i+=2; continue
  if a[i].startswith('/') and not a[i].startswith(str(r)+'/'):
   raise RuntimeError('refusing installation outside fixture: '+a[i])
  cleaned.append(a[i]); i+=1
 sys.exit(subprocess.call(['/usr/bin/install']+cleaned))
elif name=='systemctl':
 action=a[0]
 if action=='is-active': sys.exit(0 if s.get('active') else 3)
 if action=='is-enabled': sys.exit(0 if s.get('enabled') else 1)
 fail(action)
 if action=='enable': s['enabled']=True
 if action=='disable':
  s['enabled']=False
  if '--now' in a: s['active']=False
 if action in ('start','restart'): s['active']=True
 if action=='stop': s['active']=False
 save()
elif name=='apt-get': fail('apt')
elif name=='curl':
 urls=[x for x in a if x.startswith('https://')]
 prefix='https://github.com/124aAA/openai/releases/download/v0.2.4/'
 if len(urls)!=1 or not urls[0].startswith(prefix) or not (r/'release').is_dir():
  print('curl: (6) simulated DNS/download failure',file=sys.stderr); sys.exit(6)
 asset=urls[0][len(prefix):]
 if asset not in ('qingnode-0.2.4-linux-amd64.tar.gz','SHA256SUMS'):
  raise RuntimeError('unexpected remote asset '+asset)
 dest=pathlib.Path(a[a.index('-o')+1])
 if not str(dest).startswith(str(r)+'/'):
  raise RuntimeError('refusing download outside fixture')
 if os.environ.get('QN_CURL_CODE'):
  code=int(os.environ['QN_CURL_CODE'])
  print('curl: (%d) simulated transport failure'%code,file=sys.stderr); sys.exit(code)
 if os.environ.get('QN_FAULT')=='download':
  dest.write_bytes(b'partial download'); fail('download')
 shutil.copyfile(r/'release'/asset,dest)
elif name=='ss': pass
elif name=='qingnode':
 root=r/'system/var/lib/qingnode'
 if a[:2]==['core','install']:
  fail('core')
  (root/'cores/mock-core').write_text('fixture core, NOT an actual installed binary')
 elif a==['check']: fail('check')
 elif a==['restart']:
  sys.exit(subprocess.call(['systemctl','restart','qingnode.service']))
 elif a==['recover']: pass
 else:
  # Network discovery is a simulated host effect here; auto CLI tests exercise
  # the real selection logic with explicit probe dependencies.
  if a and a[0]=='init' and '--auto' in a:
   a.remove('--auto')
   if '--server' not in a: a+=['--server','203.0.113.7']
   protocol=a[a.index('--protocol')+1] if '--protocol' in a else 'reality'
   if protocol=='reality' and '--sni' not in a: a+=['--sni','example.com']
  direct=a and a[0] in ('redact-log','validate-state','version','service')
  argv=[os.environ['QN_REAL_BIN']]+([] if direct else ['--offline','--root',str(root)])+a
  rc=subprocess.call(argv)
  if rc==0 and a and a[0]=='init': rc=subprocess.call(['systemctl','restart','qingnode.service'])
  sys.exit(rc)
else: raise RuntimeError('unknown mocked command '+name)
'''


class Fixture:
    def __init__(self, base, distro='ubuntu', version='24.04'):
        self.root = Path(tempfile.mkdtemp(dir=base))
        self.state = self.root/'system/var/lib/qingnode'
        self.bin = self.root/'system/usr/local/bin/qingnode'
        self.unit = self.root/'system/etc/systemd/system/qingnode.service'
        self.lib = self.root/'system/usr/local/lib/qingnode'
        self.bundle = self.root/'bundle'
        self.bundle.mkdir()
        (self.root/'tmp').mkdir()
        mockdir = self.root/'mock'
        mockdir.mkdir()
        for path in (self.bin.parent, self.unit.parent, self.lib.parent,
                     self.root/'system/var/log', self.root/'system/run/lock'):
            path.mkdir(parents=True, exist_ok=True)
        (self.root/'host.json').write_text(json.dumps(dict(active=False, enabled=False)))
        release = self.root/'os-release'
        # os-release contains a human-readable VERSION as well as VERSION_ID.
        # Omitting it hides collisions with the installer's release tag variable.
        release.write_text(f'ID={distro}\nVERSION_ID="{version}"\n'
                           f'VERSION="{version} (distribution release)"\n'
                           f'PRETTY_NAME="{distro} {version}"\n')
        code = (SOURCE/'install.sh').read_text()
        for old, new in {
            '/var/lib/qingnode': self.state,
            '/usr/local/bin/qingnode': self.bin,
            '/etc/systemd/system/qingnode.service': self.unit,
            '/usr/local/lib/qingnode': self.lib,
            '/var/backups/qingnode': self.root/'system/var/backups/qingnode',
            '/var/log/qingnode-install-': self.root/'system/var/log/qingnode-install-',
            '/run/lock/qingnode-bootstrap.lock': self.root/'system/run/lock/qingnode-bootstrap.lock',
            '/etc/os-release': release,
        }.items():
            code = code.replace(old, str(new))
        self.installer = self.bundle/'install.sh'
        self.installer.write_text(code)
        self.manager = self.bundle/'qingnode'
        self.manager.write_text(MOCK)
        self.manager.chmod(0o755)
        for name in ('ps', 'uname', 'sshd', 'getent', 'useradd', 'userdel', 'install',
                     'systemctl', 'apt-get', 'curl', 'ss'):
            target = mockdir/name
            target.write_text(MOCK)
            target.chmod(0o755)
        self.env = dict(os.environ, QN_FIXTURE=str(self.root), QN_REAL_BIN=str(REAL_BIN),
                        TMPDIR=str(self.root/'tmp'), PATH=str(mockdir)+os.pathsep+os.environ['PATH'])
        self.sums()

    def sums(self):
        (self.bundle/'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
            for p in (self.manager, self.installer)))

    def remote_release(self, corrupt=''):
        release = self.root/'release'
        release.mkdir()
        if corrupt == 'inner':
            self.manager.write_text(MOCK+'\n# corrupted after inner checksum\n')
        archive = release/'qingnode-0.2.4-linux-amd64.tar.gz'
        with tarfile.open(archive, 'w:gz') as out:
            for p in (self.manager, self.installer, self.bundle/'SHA256SUMS'):
                out.add(p, arcname=p.name)
            if corrupt == 'path':
                out.add(self.manager, arcname='../escape')
        (release/'SHA256SUMS').write_text(
            f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')
        if corrupt == 'outer':
            archive.write_bytes(b'corrupted after outer checksum')

    def run(self, *args, fault='', dns=False, ok=True, online=False, curl_code=0):
        env = dict(self.env, QN_FAULT=fault)
        if dns:
            env['QN_DNS_FAIL'] = '1'
        if curl_code:
            env['QN_CURL_CODE'] = str(curl_code)
        command = ['bash', str(self.installer), *args]
        if online:
            # Preserve the actual /dev/fd entry semantics used by bash <(curl ...).
            command = ['bash', '-c', 'exec bash <(cat "$1") "${@:2}"',
                       'qingnode-online-test', str(self.installer), *args]
        p = subprocess.run(command, env=env,
                           stdin=subprocess.DEVNULL, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=35)
        if (p.returncode == 0) != ok:
            raise AssertionError(f'installer returned {p.returncode}:\n{p.stdout}')
        return p.stdout

    def install(self, **kw):
        return self.run('--server', '203.0.113.7', '--sni', 'example.com', **kw)

    def data(self):
        return (self.state/'current/state.json').read_bytes()

    def host(self, **update):
        path = self.root/'host.json'
        s = json.loads(path.read_text())
        if update:
            s.update(update)
            path.write_text(json.dumps(s))
        return s


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='qingnode-bootstrap-test-')
        self.addCleanup(self.tmp.cleanup)

    def fixture(self, *args):
        return Fixture(self.tmp.name, *args)

    def test_online_entry_fetches_bound_release_and_repeated_entry_opens_menu(self):
        f = self.fixture(); f.remote_release()
        self.assertIn('[8/8]', f.install(online=True))
        before = f.data()
        calls = (f.root/'commands.log').read_text()
        self.assertEqual(2, calls.count('\ncurl '))
        self.assertIn('124aAA/openai/releases/download/v0.2.4/', calls)
        self.assertIn('菜单需要交互终端', f.run(online=True, ok=False))
        self.assertEqual(before, f.data())
        self.assertEqual(calls.count('\ncurl '), (f.root/'commands.log').read_text().count('\ncurl '))

    def test_auto_entry_and_custom_node_export_hint(self):
        f = self.fixture(); f.remote_release()
        out = f.run('--auto', '--name', 'custom-node', '--port', '9443', online=True)
        state = json.loads(f.data())
        n = state['nodes'][0]
        self.assertEqual(('custom-node', 9443), (n['name'], n['port']))
        self.assertIn(f'qingnode export --id {n["id"]} --format uri', out)
        self.assertNotIn('qingnode export --id main', out)
        self.assertIn('qingnode init --auto', (f.root/'commands.log').read_text())
        before = f.data()
        f.run('--auto', online=True)
        self.assertEqual(before, f.data())

    def test_download_failures_have_specific_advice_before_mutation(self):
        for code, advice in [(6, 'DNS 解析失败'), (7, '无法连接下载服务器'),
                             (18, '下载内容不完整'), (22, 'HTTP 请求失败'),
                             (23, '无法写入下载文件'), (28, '下载超时'),
                             (35, 'TLS 或证书验证失败'), (60, 'TLS 或证书验证失败')]:
            with self.subTest(code=code):
                f = self.fixture(); f.remote_release()
                out = f.run('--auto', online=True, curl_code=code, ok=False)
                self.assertIn(advice, out)
                self.assertFalse(f.bin.exists())
                self.assertFalse(f.state.exists())
                self.assertFalse(f.host()['active'])

    def test_explicit_port_with_leading_zero_remains_decimal(self):
        for raw, expected in [('0443', 443), ('08443', 8443)]:
            with self.subTest(port=raw):
                f = self.fixture()
                f.run('--auto', '--protocol', 'ss2022', '--port', raw)
                self.assertEqual(expected, json.loads(f.data())['nodes'][0]['port'])

    def test_standalone_download_defaults_to_bound_release(self):
        f = self.fixture(); f.remote_release()
        standalone = f.root/'install.sh'
        standalone.write_bytes(f.installer.read_bytes())
        f.installer = standalone
        self.assertIn('[8/8]', f.install())

    def test_online_install_with_full_os_release_fields_on_five_versions(self):
        for distro, version in [('debian','12'), ('debian','13'), ('ubuntu','22.04'),
                                ('ubuntu','24.04'), ('ubuntu','26.04')]:
            with self.subTest(distro=distro, version=version):
                f = self.fixture(distro, version); f.remote_release()
                self.assertIn('[8/8]', f.install(online=True))
                before = f.data()
                f.run('--reinstall', online=True)
                self.assertEqual(before, f.data())

    def test_online_install_reads_actual_host_os_release_without_overwriting_tag(self):
        f = self.fixture(); f.remote_release()
        # Read the real file, but keep all host mutations and downloads simulated.
        (f.root/'os-release').write_bytes(Path('/etc/os-release').read_bytes())
        self.assertIn('[8/8]', f.install(online=True))

    def test_explicit_release_tag_survives_os_detection(self):
        f = self.fixture(); f.remote_release()
        # The mock intentionally has no old release; reaching this exact URL
        # proves --version was preserved, before any installation could happen.
        f.run('--repo', '124aAA/openai', '--version', 'v0.1.0', online=True, ok=False)
        calls = (f.root/'commands.log').read_text()
        self.assertIn('/releases/download/v0.1.0/qingnode-0.1.0-linux-amd64.tar.gz', calls)
        self.assertFalse(f.state.exists())

    def test_invalid_repository_and_tag_are_still_rejected(self):
        for args, message in [(('--repo', '../bad'), '仓库名无效'),
                              (('--repo', 'owner/..'), '仓库名无效'),
                              (('--repo', 'owner/.'), '仓库名无效'),
                              (('--version', 'v1.2.3; exit 0'), '管理器版本号无效')]:
            with self.subTest(args=args):
                f = self.fixture(); f.remote_release()
                self.assertIn(message, f.run(*args, online=True, ok=False))
                self.assertNotIn('\ncurl ', (f.root/'commands.log').read_text())
                self.assertFalse(f.state.exists())

    def test_online_failed_download_or_invalid_package_never_installs(self):
        for corrupt in ('download', 'outer', 'inner', 'path'):
            with self.subTest(corrupt=corrupt):
                f = self.fixture(); f.remote_release(corrupt)
                f.install(online=True, fault=corrupt, ok=False)
                self.assertFalse(f.state.exists())
                self.assertFalse(f.bin.exists())
                self.assertFalse((f.root/'tmp/escape').exists())
                self.assertFalse(f.host().get('passwd', False))

    def test_partial_local_bundle_never_falls_back_to_online(self):
        for missing in ('qingnode', 'SHA256SUMS'):
            with self.subTest(missing=missing):
                f = self.fixture(); f.remote_release()
                (f.bundle/missing).unlink()
                f.install(ok=False)
                self.assertNotIn('\ncurl ', (f.root/'commands.log').read_text())
                self.assertFalse(f.state.exists())

    def test_invalid_ports_fail_before_host_changes(self):
        for port in ('0', '65536', '-1', '443x', '000443', '443; exit 0'):
            with self.subTest(port=port):
                f = self.fixture()
                self.assertIn('端口无效', f.run('--port', port, ok=False))
                self.assertFalse(f.state.exists())
                self.assertFalse(f.bin.exists())
                self.assertNotIn('apt-get ', (f.root/'commands.log').read_text())

    def test_five_os_identifiers_and_repeat_install_keep_every_parameter(self):
        for distro, version in [('debian','12'), ('debian','13'), ('ubuntu','22.04'),
                                ('ubuntu','24.04'), ('ubuntu','26.04')]:
            with self.subTest(distro=distro, version=version):
                f = self.fixture(distro, version)
                self.assertIn('[8/8]', f.install())
                before = f.data()
                f.install()
                self.assertEqual(before, f.data())
                self.assertTrue(f.host()['enabled'])
                self.assertEqual(0o600, (f.state/'current/state.json').stat().st_mode & 0o777)

    def test_repeat_preserves_stopped_disabled_service(self):
        f = self.fixture(); f.install()
        f.host(active=False, enabled=False)
        before = f.data()
        f.run('--reinstall')
        self.assertFalse(f.host()['active'])
        self.assertFalse(f.host()['enabled'])
        self.assertEqual(before, f.data())

    def test_ss2022_and_ipv6_argument_forwarding(self):
        f = self.fixture()
        f.run('--protocol','ss2022','--name','SS-01','--server','2001:db8::7','--random-port')
        n = json.loads(f.data())['nodes'][0]
        self.assertEqual(('ss2022', 'SS-01', '::'), (n['protocol'], n['name'], n['listen']))
        self.assertGreaterEqual(n['port'], 10000)
        before = f.data(); f.run('--reinstall'); self.assertEqual(before, f.data())

    def test_unknown_os_and_unowned_paths_are_refused(self):
        f = self.fixture('ubuntu','20.04')
        f.install(ok=False); self.assertFalse(f.state.exists())
        for kind in ('binary', 'unit', 'directory', 'account'):
            with self.subTest(kind=kind):
                f = self.fixture()
                if kind == 'binary': f.bin.write_text('unrelated')
                if kind == 'unit': f.unit.write_text('unrelated')
                if kind == 'directory': f.state.mkdir(parents=True); (f.state/'other').write_text('keep')
                if kind == 'account': f.host(passwd=True, group=True)
                f.install(ok=False)
                if kind == 'binary': self.assertEqual('unrelated', f.bin.read_text())
                if kind == 'unit': self.assertEqual('unrelated', f.unit.read_text())
                if kind == 'directory': self.assertEqual('keep', (f.state/'other').read_text())
                if kind == 'account': self.assertTrue(f.host()['passwd'])

    def test_fresh_failures_remove_managed_partial_install(self):
        for fault in ('useradd', 'unit-write', 'daemon-reload', 'core', 'restart'):
            with self.subTest(fault=fault):
                f = self.fixture(); out = f.install(fault=fault, ok=False)
                self.assertTrue((f.root/'fault-fired').exists(), 'fault was not reached')
                self.assertIn('安装失败，日志', out)
                for p in (f.bin, f.unit, f.lib, f.state): self.assertFalse(p.exists(), str(p))
                self.assertFalse(f.host().get('passwd', False))
                self.assertFalse(f.host()['active'])

    def test_upgrade_failures_restore_manager_unit_and_credentials(self):
        for fault in ('unit-write','daemon-reload','core','check','restart'):
            with self.subTest(fault=fault):
                f = self.fixture(); f.install()
                before = (f.bin.read_bytes(), f.unit.read_bytes(), f.data())
                f.manager.write_text(MOCK+'\n# candidate update\n'); f.sums()
                f.run('--reinstall', fault=fault, ok=False)
                self.assertTrue((f.root/'fault-fired').exists(), 'fault was not reached')
                self.assertEqual(before, (f.bin.read_bytes(), f.unit.read_bytes(), f.data()))
                self.assertTrue(f.host()['active'])
                self.assertTrue(f.host()['enabled'])

    def test_dns_warning_local_install_and_download_failure(self):
        f = self.fixture()
        self.assertIn('DNS 查询失败', f.install(dns=True))
        self.assertNotIn('\ncurl ', (f.root/'commands.log').read_text())
        before = (f.bin.read_bytes(), f.data())
        f.run('--repo','example/qingnode','--version','v0.2.0', ok=False)
        self.assertEqual(before, (f.bin.read_bytes(), f.data()))

    def test_checksum_and_missing_manifest_entry_fail_before_mutation(self):
        for kind in ('mismatch','missing'):
            with self.subTest(kind=kind):
                f = self.fixture()
                if kind == 'mismatch': f.manager.write_text(MOCK+'\n# tampered\n')
                else: (f.bundle/'SHA256SUMS').write_text('')
                f.install(ok=False)
                self.assertFalse(f.state.exists())
                self.assertFalse(f.bin.exists())

    def test_concurrent_bootstrap_is_refused(self):
        f = self.fixture()
        with (f.root/'system/run/lock/qingnode-bootstrap.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIn('另一个安装操作', f.install(ok=False))
            self.assertFalse(f.state.exists())

    def test_retained_account_requires_exact_private_ownership_record(self):
        for valid in (True, False):
            with self.subTest(valid=valid):
                f = self.fixture(); f.host(passwd=True, group=True)
                record = f.root/'system/var/backups/qingnode/.qingnode-account'
                record.parent.mkdir(parents=True)
                record.write_text('QingNode retained account v1\nqingnode:x:999:999::/nonexistent:/usr/sbin/nologin\nqingnode:x:999:\n')
                record.chmod(0o600 if valid else 0o644)
                f.install(ok=valid)
                self.assertEqual(valid, f.state.exists())
                self.assertTrue(f.host()['passwd'])


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('The isolated harness needs root for install.sh EUID checks; all host effects are mocked.')
    with tempfile.TemporaryDirectory(prefix='qingnode-test-cli-') as build:
        REAL_BIN = Path(build)/'qingnode-real'
        subprocess.run([os.environ.get('GO', 'go'), 'build', '-mod=vendor', '-o', str(REAL_BIN),
                        './cmd/qingnode'], cwd=SOURCE, check=True)
        unittest.main(verbosity=2)
