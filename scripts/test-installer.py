#!/usr/bin/env python3
"""Isolated bootstrap fault tests. Real Bash/files/CLI; simulated host commands.

Does not install on this host. Fixed production paths are rewritten in a temporary
copy of install.sh. Mocks reject network access and perform no service/account/
firewall changes. This is NOT systemd/OpenRC VM acceptance testing.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import signal
import subprocess
import tarfile
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1]
RELEASE_TAG = re.search(r'\bVERSION=(v\d+\.\d+\.\d+)\b', (SOURCE/'install.sh').read_text()).group(1)
RELEASE_ASSET = f'qingnode-{RELEASE_TAG[1:]}-linux-amd64.tar.gz'
MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, shutil, signal, subprocess, sys
r=pathlib.Path(os.environ['QN_FIXTURE'])
name=pathlib.Path(sys.argv[0]).name
a=sys.argv[1:]
db=r/'host.json'
s=json.loads(db.read_text())
def save():
 tmp=r/('host-'+str(os.getpid())+'.tmp')
 tmp.write_text(json.dumps(s)); tmp.replace(db)
def fail(point):
 mutation=os.environ.get('QN_MUTATE_POINT')==point and not (r/'mutation-fired').exists()
 if os.environ.get('QN_MUTATE_RECOVERY_POINT')==point and (r/'fault-fired').exists() and not (r/'mutation-fired').exists(): mutation=True
 if mutation:
  kind=os.environ['QN_MUTATE_KIND']
  unit=r/('system/etc/init.d/qingnode' if os.environ.get('QN_PID1')=='init' else 'system/etc/systemd/system/qingnode.service')
  target={'unit':unit,'manager':r/'system/usr/local/bin/qingnode','installer':r/'system/usr/local/lib/qingnode/install.sh','rotation':r/'system/etc/logrotate.d/qingnode'}.get(kind)
  if target is not None: target.write_bytes(b'# External administrator fixture; preserve this exact content\n')
  elif kind=='unit-mode': unit.chmod(0o600)
  elif kind in ('unit-symlink','unit-hardlink'):
   foreign=r/'external-service-original'; foreign.write_bytes(b'# External linked definition; preserve\n')
   unit.unlink()
   if kind=='unit-symlink': unit.symlink_to(foreign)
   else: os.link(foreign,unit)
  elif kind in ('dropin','confd'):
   target=unit.with_name(unit.name+'.d')/'administrator.conf' if kind=='dropin' else r/'system/etc/conf.d/qingnode'
   target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(b'# External administrator override; preserve\n')
  else: raise RuntimeError('unknown fixture mutation')
  (r/'mutation-fired').write_text(kind)
  (r/'fault-fired').touch()
  print('injected external edit during '+point+' wait',file=sys.stderr)
  sys.exit(1)
 if os.environ.get('QN_PAUSE_POINT')==point and not (r/'pause-point.json').exists():
  marker=r/'pause-point.json'
  descriptor=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(descriptor,'w') as pause:
   json.dump({'version':1,'point':point,'pid':os.getpid()},pause)
   pause.flush(); os.fsync(pause.fileno())
  # Only this simulated command pauses. The real Bash parent and its EXIT
  # recovery trap remain unchanged, and production has no such override.
  signal.pause()
 if os.environ.get('QN_RECOVERY_FAULT')==point and (r/'fault-fired').exists():
  print('injected persistent recovery '+point+' failure', file=sys.stderr)
  sys.exit(1)
 if os.environ.get('QN_FAULT')==point and not (r/'fault-fired').exists():
  (r/'fault-fired').touch()
  print('injected '+point+' failure', file=sys.stderr)
  sys.exit(1)
with (r/'commands.log').open('a') as f: f.write(name+' '+' '.join(a)+'\n')
if name=='qingnode' and os.environ.get('QN_LEGACY_FIXTURE')=='1' and 'validate-install' in a:
 print('[ERROR] 未知命令 "validate-install"，运行 qingnode help 查看帮助', file=sys.stderr)
 sys.exit(1)
if name=='qingnode' and os.environ.get('QN_LEGACY_FIXTURE')=='1' and a==['version']:
 # This adapter models the fixed historical interface, independently of the
 # current source version. The actual official binary has its own Linux gate.
 print('QingNode 0.2.8 (legacy-interface-fixture)')
 sys.exit(0)
if name=='qingnode' and a and a[0] in ('init','wizard') and os.environ.get('QN_RECORD_INIT_FDS')=='1':
 # Observe the real Bash -> command descriptor boundary before delegating to
 # the real CLI. Never record argv or config/credential bytes in this fixture.
 descriptors={}
 for fd in pathlib.Path('/proc/self/fd').iterdir():
  try: descriptors[fd.name]=os.readlink(fd)
  except FileNotFoundError: pass
 descriptor=os.open(r/('init-fds-'+str(os.getpid())+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(descriptor,'w') as evidence:
  json.dump({'version':1,'operation':a[0],'descriptors':descriptors},evidence)
if name=='ps': print(os.environ.get('QN_PID1','systemd'))
elif name=='uname': print(os.environ.get('QN_ARCH','x86_64'))
elif name=='sshd': print('port 22')
elif name=='getent':
 if a[0]=='ahosts':
  if os.environ.get('QN_DNS_FAIL'): sys.exit(2)
  print('192.0.2.2 STREAM github.com')
 elif a[0] in ('passwd','group'):
  if not s.get(a[0]): sys.exit(2)
  print('qingnode:x:999:999::/nonexistent:/usr/sbin/nologin' if a[0]=='passwd' else 'qingnode:x:999:')
 else: sys.exit(2)
elif name in ('useradd','adduser'):
 fail('useradd'); s.update(passwd=True, group=True); save()
elif name in ('userdel','deluser'):
 s.update(passwd=False, group=False); save()
elif name in ('addgroup','delgroup'): pass
elif name=='install':
 if any('qingnode.service.new.' in x or '/init.d/qingnode.new.' in x for x in a): fail('unit-write')
 if str(r/'system/usr/local/bin/qingnode.recover') in a: fail('restore-bin')
 if str(r/'system/etc/systemd/system/qingnode.service') in a: fail('restore-unit')
 if str(r/'system/etc/init.d/qingnode') in a: fail('restore-unit')
 if str(r/'system/usr/local/lib/qingnode/install.sh') in a: fail('restore-installer')
 cleaned=[]; i=0
 while i<len(a):
  if a[i] in ('-o','-g'): i+=2; continue
  if a[i].startswith('/') and not a[i].startswith(str(r)+'/'):
   raise RuntimeError('refusing installation outside fixture: '+a[i])
  cleaned.append(a[i]); i+=1
 sys.exit(subprocess.call(['/usr/bin/install']+cleaned))
elif name=='systemctl':
 action=a[0]
 if action=='show':
  if os.environ.get('QN_INIT_UNAVAILABLE'): sys.exit(1)
  if '--property=FragmentPath,DropInPaths' in a:
   unit=r/'system/etc/systemd/system/qingnode.service'
   print('FragmentPath='+str(unit) if unit.exists() else 'FragmentPath=')
   print('DropInPaths='+os.environ.get('QN_LOADED_DROPINS',''))
  elif '--property=LoadState,ActiveState,UnitFileState,FragmentPath' in a:
   fail('service-snapshot')
   unit=r/'system/etc/systemd/system/qingnode.service'
   print('LoadState='+('loaded' if unit.exists() else 'not-found'))
   print('ActiveState='+os.environ.get('QN_SERVICE_ACTIVE_STATE', 'active' if s.get('active') else 'inactive'))
   print('UnitFileState='+os.environ.get('QN_SERVICE_UNIT_STATE', ('enabled' if s.get('enabled') else 'disabled') if unit.exists() else ''))
   print('FragmentPath='+str(unit) if unit.exists() else 'FragmentPath=')
  else: print('259')
  sys.exit(0)
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
elif name=='rc-status':
 if os.environ.get('QN_INIT_UNAVAILABLE'): sys.exit(1)
 print('default')
elif name=='rc-service':
 if a==['-l']: print('qingnode'); sys.exit(0)
 assert a[0]=='qingnode'
 action=a[1]
 if action=='status':
  if os.environ.get('QN_BAD_OPENRC_STATUS'):
   print('service controller unavailable',file=sys.stderr); sys.exit(1)
  print('status: started' if s.get('active') else 'status: stopped')
  sys.exit(0 if s.get('active') else 3)
 fail(action)
 if action in ('start','restart'): s['active']=True
 if action=='stop': s['active']=False
 save()
elif name=='rc-update':
 if a==['-q','show']:
  if s.get('enabled'): print('qingnode | '+' '.join(s.get('runlevels',['default'])))
  sys.exit(0)
 if a and a[0]=='--all': a=a[1:]
 action={'add':'enable','del':'disable'}[a[0]]
 fail(action)
 levels=set(s.get('runlevels',['default']) if s.get('enabled') else [])
 if action=='enable': levels.add(a[2])
 else:
  if not levels:
   print('service is not in any runlevel',file=sys.stderr); sys.exit(1)
  if len(a)>2:
   if a[2] not in levels:
    print('service is not in requested runlevel',file=sys.stderr); sys.exit(1)
   levels.remove(a[2])
  else: levels.clear()
 s.update(enabled=bool(levels), runlevels=sorted(levels)); save()
elif name=='supervise-daemon': print('supervise-daemon 0.62')
elif name in ('apt-get','dnf','apk'):
 if name=='apk' and a and a[0]=='info': sys.exit(1 if os.environ.get('QN_MISSING_ABI') else 0)
 fail('apt' if name=='apt-get' else name)
elif name=='setcap':
 fail('setcap')
 assert a[0]=='cap_net_bind_service=ep'
 assert str(a[1]).startswith(str(r)+'/system/')
 s['filecap']=a[1]; save()
elif name=='getcap':
 if s.get('filecap')==a[0] and not os.environ.get('QN_BAD_CAP_READBACK'):
  print(a[0]+' cap_net_bind_service=ep')
elif name=='restorecon': fail('restorecon')
elif name=='getenforce': print('Enforcing')
elif name=='logrotate': pass
elif name=='curl':
 urls=[x for x in a if x.startswith('https://')]
 tag=os.environ['QN_RELEASE_TAG']
 prefix='https://github.com/124aAA/openai/releases/download/'+tag+'/'
 latest='https://github.com/124aAA/openai/releases/latest/download/SHA256SUMS'
 if len(urls)!=1 or (urls[0]!=latest and not urls[0].startswith(prefix)) or not (r/'release').is_dir():
  print('curl: (6) simulated DNS/download failure',file=sys.stderr); sys.exit(6)
 asset='SHA256SUMS' if urls[0]==latest else urls[0][len(prefix):]
 if asset not in ('qingnode-'+tag[1:]+'-linux-amd64.tar.gz','SHA256SUMS'):
  raise RuntimeError('unexpected remote asset '+asset)
 dest=pathlib.Path(a[a.index('-o')+1])
 if not str(dest).startswith(str(r)+'/'):
  raise RuntimeError('refusing download outside fixture')
 if os.environ.get('QN_CURL_CODE'):
  code=int(os.environ['QN_CURL_CODE'])
  print('curl: (%d) simulated transport failure'%code,file=sys.stderr); sys.exit(code)
 if os.environ.get('QN_FAULT')=='download':
  dest.write_bytes(b'partial download'); fail('download')
 if os.environ.get('QN_STREAM_ASSET')==asset:
  # Deliberately ignore curl's --max-filesize, as old curl does when no length
  # is known. The actual child RLIMIT must stop this stream, not mock options.
  signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
  total=int(os.environ['QN_STREAM_BYTES']); written=0
  print('streaming response without Content-Length', file=sys.stderr)
  with dest.open('wb', buffering=0) as out:
   while written<total:
    written+=out.write(b'x'*min(65536,total-written))
    (r/'stream-progress').write_text(str(written))
  (r/'stream-complete').touch()
 else: shutil.copyfile(r/'release'/asset,dest)
elif name=='ss': pass
elif name=='qingnode':
 root=r/'system/var/lib/qingnode'
 if a[:2]==['core','install']:
  fail('core')
  (root/'cores/mock-core').write_text('fixture core, NOT an actual installed binary')
 elif a==['check']: fail('check')
 elif a==['restart']:
  sys.exit(subprocess.call(['rc-service','qingnode','restart'] if os.environ.get('QN_PID1')=='init' else ['systemctl','restart','qingnode.service']))
 elif a==['recover']: pass
 else:
  # Network discovery is a simulated host effect here; auto CLI tests exercise
  # the real selection logic with explicit probe dependencies.
  if a and a[0]=='init' and '--auto' in a:
   a.remove('--auto')
   if '--server' not in a: a+=['--server','203.0.113.7']
   protocol=a[a.index('--protocol')+1] if '--protocol' in a else 'reality'
   if protocol=='reality' and '--sni' not in a: a+=['--sni','example.com']
  if a and a[0]=='wizard' and '--fields-file' in a:
   # As for init --auto above, this harness simulates network discovery.
   # The collected file remains a real private, versioned argument file; only
   # its discovery request is removed before the real offline CLI applies it.
   fieldpath=pathlib.Path(a[a.index('--fields-file')+1])
   fieldvalues=fieldpath.read_bytes().split(b'\0')
   fieldpath.write_bytes(b'\0'.join(value for value in fieldvalues if value!=b'--auto'))
  direct=a and a[0] in ('redact-log','validate-state','validate-install','collect-install','version','service')
  argv=[os.environ['QN_REAL_BIN']]+([] if direct else ['--offline','--root',str(root)])+a
  rc=subprocess.call(argv)
  if rc==0 and a and a[0] in ('init','wizard'):
   rc=subprocess.call(['rc-service','qingnode','restart'] if os.environ.get('QN_PID1')=='init' else ['systemctl','restart','qingnode.service'])
  sys.exit(rc)
else: raise RuntimeError('unknown mocked command '+name)
'''


class Fixture:
    def __init__(self, base, distro='ubuntu', version='24.04'):
        self.root = Path(tempfile.mkdtemp(dir=base))
        self.state = self.root/'system/var/lib/qingnode'
        self.bin = self.root/'system/usr/local/bin/qingnode'
        self.unit = self.root/'system/etc/systemd/system/qingnode.service'
        self.openrc_unit = self.root/'system/etc/init.d/qingnode'
        if distro == 'alpine': self.unit = self.openrc_unit
        self.lib = self.root/'system/usr/local/lib/qingnode'
        self.rotation = self.root/'system/etc/logrotate.d/qingnode'
        self.bundle = self.root/'bundle'
        self.bundle.mkdir()
        (self.root/'tmp').mkdir()
        mockdir = self.root/'mock'
        mockdir.mkdir()
        for path in (self.bin.parent, self.root/'system/etc/systemd/system', self.openrc_unit.parent, self.lib.parent,
                     self.root/'system/var/log', self.root/'system/run/lock', self.root/'system/run/openrc', self.rotation.parent):
            path.mkdir(parents=True, exist_ok=True)
        (self.root/'system/run/openrc/softlevel').write_text('default\n')
        (self.root/'host.json').write_text(json.dumps(dict(active=False, enabled=False)))
        release = self.root/'os-release'
        # os-release contains a human-readable VERSION as well as VERSION_ID.
        # Omitting it hides collisions with the installer's release tag variable.
        release.write_text(f'ID={distro}\nVERSION_ID="{version}"\n'
                           f'VERSION="{version} (distribution release)"\n'
                           f'PRETTY_NAME="{distro} {version}"\n')
        code = (SOURCE/'install.sh').read_text()
        # Read actual Linux procfs in production. Only this copied fixture reads
        # its explicit simulated PID1; the installed script has no env bypass.
        assert 'QN_PID1=$(cat /proc/1/comm)' in code
        code = code.replace('QN_PID1=$(cat /proc/1/comm)', 'QN_PID1=${QN_PID1:?fixture PID1 missing}')
        for old, new in {
            '/var/lib/qingnode': self.state,
            '/usr/local/bin/qingnode': self.bin,
            '/etc/systemd/system/qingnode.service': self.root/'system/etc/systemd/system/qingnode.service',
            '/etc/init.d/qingnode': self.openrc_unit,
            '/etc/conf.d/qingnode': self.root/'system/etc/conf.d/qingnode',
            '/etc/logrotate.d': self.rotation.parent,
            '/usr/local/lib/qingnode': self.lib,
            '/var/backups/qingnode': self.root/'system/var/backups/qingnode',
            '/var/log/qingnode-install-': self.root/'system/var/log/qingnode-install-',
            '/run/lock': self.root/'system/run/lock',
            '/run/openrc/softlevel': self.root/'system/run/openrc/softlevel',
            '/etc/os-release': release,
        }.items():
            code = code.replace(old, str(new))
        self.installer = self.bundle/'install.sh'
        self.installer.write_text(code)
        self.manager = self.bundle/'qingnode'
        self.manager.write_text(MOCK)
        self.manager.chmod(0o755)
        for name in ('ps', 'uname', 'sshd', 'getent', 'useradd', 'userdel', 'install',
                     'systemctl', 'apt-get', 'curl', 'ss', 'rc-status', 'rc-service', 'rc-update',
                     'supervise-daemon', 'adduser', 'addgroup', 'deluser', 'delgroup',
                     'setcap', 'getcap', 'restorecon', 'getenforce', 'dnf', 'apk', 'logrotate'):
            target = mockdir/name
            target.write_text(MOCK)
            target.chmod(0o755)
        self.env = dict(os.environ, QN_FIXTURE=str(self.root), QN_REAL_BIN=str(REAL_BIN), QN_RELEASE_TAG=RELEASE_TAG,
                        QN_PID1='init' if distro == 'alpine' else 'systemd',
                        TMPDIR=str(self.root/'tmp'), PATH=str(mockdir)+os.pathsep+os.environ['PATH'])
        self.sums()

    def sums(self):
        (self.bundle/'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(self.bundle).as_posix()}\n'
            for p in (self.manager, self.installer, *sorted((self.bundle/'docs').glob('*')))))

    def require_packages(self):
        # Trigger the real package boundary while keeping all package operations
        # mocked. No production environment variable bypass is introduced.
        code = self.installer.read_text().replace('local -a packages=()', 'local -a packages=(curl)')
        self.installer.write_text(code); self.sums()

    def remote_release(self, corrupt='', tag=None):
        release = self.root/'release'
        release.mkdir()
        if corrupt == 'inner':
            self.manager.write_text(MOCK+'\n# corrupted after inner checksum\n')
        archive = release/('qingnode-'+(tag or RELEASE_TAG)[1:]+'-linux-amd64.tar.gz')
        with tarfile.open(archive, 'w:gz') as out:
            for p in (self.manager, self.installer, self.bundle/'SHA256SUMS'):
                out.add(p, arcname=p.name)
            if (self.bundle/'docs').exists():
                out.add(self.bundle/'docs', arcname='docs')
            if corrupt == 'path':
                out.add(self.manager, arcname='../escape')
        (release/'SHA256SUMS').write_text(
            f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')
        if corrupt == 'outer':
            archive.write_bytes(b'corrupted after outer checksum')

    def run(self, *args, fault='', recovery_fault='', dns=False, ok=True, online=False, curl_code=0, tty_input=None):
        env = dict(self.env, QN_FAULT=fault, QN_RECOVERY_FAULT=recovery_fault)
        if dns:
            env['QN_DNS_FAIL'] = '1'
        if curl_code:
            env['QN_CURL_CODE'] = str(curl_code)
        command = ['bash', str(self.installer), *args]
        if online:
            # Preserve the actual /dev/fd entry semantics used by bash <(curl ...).
            command = ['bash', '-c', 'exec bash <(cat "$1") "${@:2}"',
                       'qingnode-online-test', str(self.installer), *args]
        if tty_input is None:
            p = subprocess.run(command, env=env,
                               stdin=subprocess.DEVNULL, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=35)
            output = p.stdout
        else:
            # Bash/Go see a real terminal while output remains bounded/captured.
            # Ctrl-D on the empty canonical input line models terminal EOF.
            master, slave = pty.openpty()
            try:
                p = subprocess.Popen(command, env=env, stdin=slave, text=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                os.close(slave); slave = -1
                os.write(master, tty_input.encode())
                try:
                    output, _ = p.communicate(timeout=35)
                except subprocess.TimeoutExpired:
                    p.kill(); output, _ = p.communicate()
                    raise AssertionError('interactive installer did not finish:\n'+output)
            finally:
                os.close(master)
                if slave >= 0: os.close(slave)
        if (p.returncode == 0) != ok:
            raise AssertionError(f'installer returned {p.returncode}:\n{output}')
        return output

    def install(self, **kw):
        return self.run('--server', '203.0.113.7', '--sni', 'example.com', **kw)

    def download(self, limit, size, lower_hard_limit=False):
        # Exercise the production function without the installation entry point.
        # Small limits keep the kernel boundary test fast; integrated tests below
        # also exercise the two actual production limits.
        self.remote_release()
        log = self.root/'download.log'
        log.write_bytes(b'previous log\n'*limit)
        code = (SOURCE/'install.sh').read_text()
        functions = code[code.index('logged() {'):code.index('step 2 "')]
        guard = code[code.index('qn_guard_transaction() {'):code.index('qn_remove_new_lib() {')]
        # The real download phase precedes candidate/old-file admission. Include
        # the unchanged production guard; it is not activated at that phase.
        script = 'set -Eeuo pipefail\nLOG=$1; REDACTOR=""; QN_GUARD_READY=0\n'+guard+functions
        if lower_hard_limit:
            script += 'ulimit -f 1\n'
        script += ('printf "parent-before=%s\\n" "$(ulimit -f)"\n'
                   'if download_release "$2" "$3" 5 "$4" fixture; then rc=0; else rc=$?; fi\n'
                   'printf "parent-after=%s\\n" "$(ulimit -f)"\nexit "$rc"\n')
        env = dict(self.env, QN_STREAM_ASSET=RELEASE_ASSET, QN_STREAM_BYTES=str(size))
        dest = self.root/'downloaded'
        result = subprocess.run(['bash', '-c', script, 'bounded-download-test', str(log),
                                 f'https://github.com/124aAA/openai/releases/download/{RELEASE_TAG}/{RELEASE_ASSET}',
                                 str(dest), str(limit)], env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
        return result, dest, log

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
    def assert_private_completion(self, fixture, ordinary, node, scheme):
        """Ordinary output is public; explicit export still matches this identity."""
        self.assertNotIn(scheme, ordinary)
        self.assertNotIn('分享链接：', ordinary)
        for user in node['users']:
            for field in ('uuid', 'password'):
                if user.get(field):
                    self.assertNotIn(user[field], ordinary)
        if node.get('reality', {}).get('private_key'):
            self.assertNotIn(node['reality']['private_key'], ordinary)
        if node.get('shadowsocks', {}).get('server_key'):
            self.assertNotIn(node['shadowsocks']['server_key'], ordinary)
        before = fixture.data()
        selected = node['users'][0]['id']
        exported = subprocess.run([str(fixture.bin), 'export', '--id', node['id'], '--user', selected, '--format', 'uri'],
                                  env=fixture.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(0, exported.returncode, exported.stderr)
        self.assertEqual(1, exported.stdout.count(scheme))
        explicit = subprocess.run([str(fixture.bin), 'info', '--id', node['id'], '--show-secrets'],
                                  env=fixture.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(0, explicit.returncode, explicit.stderr)
        self.assertIn(exported.stdout.strip(), explicit.stdout)
        for field in ('uuid', 'password'):
            if node['users'][0].get(field):
                self.assertIn(node['users'][0][field], explicit.stdout)
        self.assertEqual(before, fixture.data(), 'explicit export changed identity or State')
        return explicit.stdout

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='qingnode-bootstrap-test-')
        self.addCleanup(self.tmp.cleanup)

    def fixture(self, *args):
        return Fixture(self.tmp.name, *args)

    def assert_untouched(self, f):
        self.assertEqual(dict(active=False, enabled=False), f.host())
        for path in (f.state, f.bin, f.unit, f.lib, f.root/'commands.log'):
            self.assertFalse(path.exists(), str(path))
        self.assertEqual([], list((f.root/'tmp').iterdir()))
        self.assertEqual([], list((f.root/'system/var/log').iterdir()))

    def test_first_screen_cancel_and_eof_precede_every_host_operation(self):
        for answer, args in [('0\n', ()), ('\x04', ()),
                             ('\n9\n0\n', ('--reinstall', '--repo', '124aAA/openai',
                                           '--version', RELEASE_TAG, '--core-archive', '/unused.tar.gz'))]:
            with self.subTest(answer=repr(answer), args=args):
                f = self.fixture(); f.remote_release()
                out = f.run(*args, online=True, tty_input=answer)
                self.assertNotIn('[1/8]', out)
                self.assertNotIn('安装完成', out)
                self.assert_untouched(f)

    def test_fresh_nonterminal_entry_needs_explicit_intent_before_mutation(self):
        for args in [(), ('--reinstall',), ('--repo', '124aAA/openai'),
                     ('--version', RELEASE_TAG), ('--core-archive', '/unused.tar.gz')]:
            with self.subTest(args=args):
                f = self.fixture(); f.remote_release()
                out = f.run(*args, online=True, ok=False)
                self.assertIn('交互', out)
                self.assertIn('--auto', out)
                self.assert_untouched(f)

    def test_first_screen_protocol_selection_and_invalid_input_retry(self):
        for answer, protocol, scheme, args in [
                ('1\n', 'reality', 'vless://', ()),
                ('\n9\n2\n', 'ss2022', 'ss://',
                 ('--reinstall', '--repo', '124aAA/openai', '--version', RELEASE_TAG))]:
            with self.subTest(protocol=protocol):
                f = self.fixture(); f.remote_release()
                out = f.run(*args, online=True, tty_input=answer)
                n = json.loads(f.data())['nodes'][0]
                self.assertEqual(protocol, n['protocol'])
                calls = (f.root/'commands.log').read_text().splitlines()
                init = [c.split() for c in calls if c.startswith('qingnode init ')]
                self.assertEqual(1, len(init))
                self.assertIn('--auto', init[0])
                self.assertEqual(protocol, init[0][init[0].index('--protocol')+1])
                self.assertNotIn('qingnode wizard', '\n'.join(calls))
                self.assertTrue(f.host()['active'])
                self.assertTrue(f.host()['enabled'])
                explicit = self.assert_private_completion(f, out, n, scheme)
                self.assertEqual(1, explicit.count(scheme))
                self.assertGreater(out.index('节点：'), out.index('[8/8]'))
                self.assertIn(f'qingnode export --id {n["id"]} --format uri', out)

    def test_hysteria_selection_reaches_quiet_wizard_with_selected_protocol(self):
        f = self.fixture()
        out = f.run(tty_input='3\nHY2-test\n203.0.113.7\n8443\nexample.com\nacme\nadmin@example.com\n')
        state = json.loads(f.data())
        n = state['nodes'][0]
        self.assertEqual(('hysteria2', 'HY2-test', 8443), (n['protocol'], n['name'], n['port']))
        self.assertNotIn('certificate', n, 'schema6 must persist the stable resource reference, not an inline copy')
        self.assertRegex(n['certificate_id'], r'^[0-9a-f]{16}$')
        resources = [r for r in state['certificates'] if r['id'] == n['certificate_id']]
        self.assertEqual(1, len(resources), 'wizard node must reference exactly one saved certificate resource')
        self.assertEqual('acme', resources[0]['certificate']['mode'])
        self.assertEqual('example.com', resources[0]['certificate']['server_name'])
        self.assertEqual('admin@example.com', resources[0]['certificate']['email'])
        calls = (f.root/'commands.log').read_text().splitlines()
        wizard = [c.split() for c in calls if c.startswith('qingnode wizard ')]
        self.assertEqual(1, len(wizard))
        self.assertEqual('hysteria2', wizard[0][wizard[0].index('--protocol')+1])
        self.assertIn('--quiet', wizard[0])
        self.assertIn('--fields-file', wizard[0])
        self.assertLess(out.index('节点名称'), out.index('[3/8]'))
        self.assertTrue(f.host()['active'])
        self.assertTrue(f.host()['enabled'])
        explicit = self.assert_private_completion(f, out, n, 'hysteria2://')
        self.assertEqual(1, explicit.count('hysteria2://'))
        completion_marker = '[8/8] 安装完成，以下为节点摘要（认证信息已隐藏）'
        self.assertEqual(1, out.count(completion_marker))
        before_completion, completed = out.split(completion_marker)
        preview_marker = '本次实际影响（校验后统一应用）：'
        preview_node = f'节点：{n["name"]}（{n["id"]}）'
        summary_node = f'节点：{n["name"]}\nID：{n["id"]}\n协议：hysteria2\n'
        # The wizard previews the one saved candidate before installation
        # completes; --quiet must defer its actual node summary to step 8.
        self.assertEqual(1, before_completion.count(preview_marker))
        self.assertEqual(1, before_completion.count(preview_node))
        self.assertNotIn(summary_node, before_completion)
        self.assertNotIn(preview_marker, completed)
        self.assertNotIn(preview_node, completed)
        self.assertEqual(1, completed.count(summary_node))
        self.assertGreater(out.index(summary_node), out.index(completion_marker))
        for phase, section in (('candidate preview', before_completion), ('final summary', completed)):
            with self.subTest(output_phase=phase):
                for sensitive_label in ('Password：', 'UUID：', '分享链接：', 'hysteria2://'):
                    self.assertNotIn(sensitive_label, section)
                for user in n['users']:
                    for field in ('uuid', 'password'):
                        if user.get(field):
                            self.assertNotIn(user[field], section)

    def test_tls_form_cancel_eof_and_invalid_input_precede_host_changes(self):
        for answer, success in [('3\n:cancel\n', True), ('3\n\x04', False),
                                ('3\nmain\nbad host\n', False),
                                ('3\nmain\n203.0.113.7\n443\nexample.com\npem\n/no-cert\n/no-key\n', False)]:
            with self.subTest(answer=repr(answer)):
                f = self.fixture()
                f.require_packages()
                output = f.run(tty_input=answer, ok=success)
                self.assertNotIn('[3/8]', output)
                self.assertNotIn('[8/8]', output)
                for path in (f.state, f.bin, f.unit, f.lib):
                    self.assertFalse(path.exists(), str(path))
                self.assertFalse(f.host().get('passwd', False))
                self.assertEqual([], list((f.root/'tmp').iterdir()))
                self.assertEqual([], list((f.root/'system/var/log').iterdir()))
                calls = (f.root/'commands.log').read_text()
                for forbidden in ('apt-get ', 'dnf ', 'apk add ', 'useradd ', 'adduser ',
                                  'qingnode core install', 'systemctl restart', 'rc-service qingnode restart'):
                    self.assertNotIn(forbidden, calls)

    def test_init_and_wizard_do_not_inherit_bootstrap_lease_or_stderr_tee_pipe(self):
        # OpenRC creates the supervisor under this process tree, unlike a
        # systemd PID1 spawn. A leaked descriptor can outlive the installer and
        # retain either its bootstrap flock or a redaction pipe writer.
        self.assertNotIn('2> >(tee', (SOURCE/'install.sh').read_text())
        for operation in ('init', 'wizard'):
            with self.subTest(operation=operation):
                f = self.fixture()
                f.env['QN_RECORD_INIT_FDS'] = '1'
                if operation == 'init':
                    output = f.run('--protocol', 'ss2022', '--name', 'fd-safe',
                                   '--server', '203.0.113.7', '--port', '8443')
                    expected = ('ss2022', 'fd-safe')
                else:
                    output = f.run(tty_input='3\nfd-safe-hy2\n203.0.113.7\n8443\nexample.com\nacme\nadmin@example.com\n')
                    expected = ('hysteria2', 'fd-safe-hy2')
                snapshots = list(f.root.glob('init-fds-*.json'))
                self.assertEqual(1, len(snapshots), 'the actual command boundary was not observed')
                observed = json.loads(snapshots[0].read_text())
                self.assertEqual(operation, observed['operation'])
                descriptors = observed['descriptors']
                self.assertNotIn('qingnode-bootstrap.lock', descriptors.get('9', ''))
                self.assertFalse(descriptors.get('63', '').startswith('pipe:['),
                                 'an asynchronous stderr writer may be inherited by a supervisor')
                node = json.loads(f.data())['nodes'][0]
                self.assertEqual(expected, (node['protocol'], node['name']))
                self.assertTrue(node['id'])
                self.assertTrue(node['users'])
                self.assertTrue(f.host()['active'])
                self.assertTrue(f.host()['enabled'])
                self.assertIn('[8/8]', output)
                original = f.data()
                f.install()
                self.assertEqual(original, f.data(), 'reinstall rotated identity while checking descriptor safety')

    def test_online_entry_fetches_bound_release_and_repeated_entry_opens_menu(self):
        f = self.fixture(); f.remote_release()
        self.assertIn('[8/8]', f.install(online=True))
        before = f.data()
        calls = (f.root/'commands.log').read_text()
        self.assertEqual(2, calls.count('\ncurl '))
        self.assertIn(f'124aAA/openai/releases/download/{RELEASE_TAG}/', calls)
        self.assertIn('菜单需要交互终端', f.run(online=True, ok=False))
        self.assertEqual(before, f.data())
        self.assertEqual(calls.count('\ncurl '), (f.root/'commands.log').read_text().count('\ncurl '))
        host = f.host()
        history = f.state/'observations.json'
        observed = history.read_bytes() if history.exists() else None
        out = f.run(online=True, tty_input='8\n0\n')
        self.assertIn('节点与用户', out)
        self.assertGreaterEqual(out.count('管理与说明'), 2)
        for label in ('配置核心', '待验证', '8 刷新总览', '9 检查更新', '4 测速与诊断'):
            self.assertIn(label, out)
        self.assertEqual(before, f.data())
        self.assertEqual(host, f.host())
        self.assertEqual(observed, history.read_bytes() if history.exists() else None)
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

    def test_download_limit_streaming_boundaries_and_parent_limits(self):
        limit = 4096
        for size in (limit, limit+1, limit*32):
            with self.subTest(size=size):
                f = self.fixture()
                result, dest, log = f.download(limit, size)
                parent = [line.split('=', 1)[1] for line in result.stdout.splitlines()
                          if line.startswith(('parent-before=', 'parent-after='))]
                self.assertEqual(2, len(parent))
                self.assertEqual(parent[0], parent[1], 'child limit changed the parent shell')
                self.assertGreater(log.stat().st_size, limit)
                self.assertIn('without Content-Length', log.read_text())
                if size == limit:
                    self.assertEqual(0, result.returncode, result.stdout)
                    self.assertEqual(limit, dest.stat().st_size)
                    self.assertTrue((f.root/'stream-complete').exists())
                else:
                    self.assertEqual(153, result.returncode, result.stdout)
                    self.assertIn('超过下载上限', result.stdout)
                    self.assertFalse(dest.exists(), 'partial response was retained')
                    self.assertFalse((f.root/'stream-complete').exists())
                self.assertEqual(limit, int((f.root/'stream-progress').read_text()))

    def test_download_limit_setup_failure_refuses_transfer(self):
        f = self.fixture()
        result, dest, _ = f.download(4096, 1, lower_hard_limit=True)
        self.assertEqual(125, result.returncode, result.stdout)
        self.assertIn('无法建立下载文件大小限制', result.stdout)
        self.assertFalse(dest.exists())
        self.assertFalse((f.root/'stream-progress').exists())
        self.assertFalse((f.root/'commands.log').exists(), 'curl ran without its limit')

    def test_oversized_release_downloads_stop_before_host_changes(self):
        for asset, limit, label in [(RELEASE_ASSET, 64*1024*1024, '管理器归档'),
                                     ('SHA256SUMS', 1024*1024, '发行摘要清单')]:
            with self.subTest(asset=asset):
                f = self.fixture(); f.remote_release()
                f.env.update(QN_STREAM_ASSET=asset, QN_STREAM_BYTES=str(limit+1))
                out = f.install(online=True, ok=False)
                self.assertIn(label+'超过下载上限', out)
                self.assertIn(str(limit)+' 字节', out)
                self.assertIn('已校验的完整本地发行包', out)
                self.assertNotIn('[4/8]', out)
                self.assertFalse(f.state.exists())
                self.assertFalse(f.bin.exists())
                self.assertFalse(f.unit.exists())
                self.assertFalse(f.lib.exists())
                self.assertFalse(f.host().get('passwd', False))
                self.assertFalse(f.host()['active'])
                self.assertEqual([], list((f.root/'tmp').iterdir()))
                self.assertEqual(limit, int((f.root/'stream-progress').read_text()))
                self.assertFalse((f.root/'stream-complete').exists())

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

    def published_older_release(self):
        f = self.fixture()
        standalone = f.root/'standalone-install.sh'
        standalone.write_bytes(f.installer.read_bytes())
        # The new main script is already visible, but only the older Release
        # and its complete assets are public. No production files are used.
        older = 'v0.2.8'
        self.assertNotEqual(older, RELEASE_TAG)
        f.installer.write_text(f.installer.read_text().replace('VERSION='+RELEASE_TAG+' ', 'VERSION='+older+' ', 1))
        f.env['QN_RELEASE_TAG'] = older
        f.sums(); f.remote_release(tag=older)
        f.installer = standalone
        return f, older

    def test_latest_release_cutover_pins_public_assets_before_new_release_exists(self):
        f, older = self.published_older_release()
        out = f.install()
        self.assertIn('[8/8]', out)
        self.assertIn('下载已公开 QingNode '+older, out)
        calls = (f.root/'commands.log').read_text()
        self.assertEqual(1, calls.count('https://github.com/124aAA/openai/releases/latest/download/SHA256SUMS'))
        self.assertIn('/releases/download/'+older+'/qingnode-'+older[1:]+'-linux-amd64.tar.gz', calls)
        self.assertNotIn('/releases/download/'+RELEASE_TAG+'/', calls)
        self.assertIsNotNone(f.data())

    def test_explicit_unpublished_version_does_not_fall_back_to_latest(self):
        f, _ = self.published_older_release()
        f.run('--version', RELEASE_TAG, '--server', '203.0.113.7', '--sni', 'example.com', ok=False)
        calls = (f.root/'commands.log').read_text()
        self.assertIn('/releases/download/'+RELEASE_TAG+'/SHA256SUMS', calls)
        self.assertNotIn('/releases/latest/', calls)
        self.assertFalse((f.state/'current/state.json').exists())
        self.assertFalse(f.bin.exists())

    def test_latest_release_rejects_duplicate_digest_and_nonrelease_filename(self):
        for kind in ('duplicate', 'prerelease', 'malformed'):
            with self.subTest(kind=kind):
                f = self.fixture(); f.remote_release()
                sums = f.root/'release/SHA256SUMS'
                raw = sums.read_text()
                if kind == 'duplicate': raw += raw
                elif kind == 'prerelease': raw = raw.replace(RELEASE_TAG[1:]+'-linux', RELEASE_TAG[1:]+'-rc1-linux')
                else: raw = raw.replace(raw.split()[0], 'not-a-sha256')
                sums.write_text(raw)
                standalone = f.root/'standalone-install.sh'
                standalone.write_bytes(f.installer.read_bytes()); f.installer = standalone
                out = f.install(ok=False)
                self.assertIn('最新正式发行摘要无效', out)
                self.assertFalse((f.state/'current/state.json').exists())
                self.assertFalse(f.bin.exists())

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
        actual = Path('/etc/os-release').read_bytes()
        (f.root/'os-release').write_bytes(actual)
        if re.search(rb'^ID=["\']?alpine["\']?$', actual, re.M):
            f.env['QN_PID1'] = 'init'; f.unit = f.openrc_unit
        self.assertIn('[8/8]', f.install(online=True))

    def test_explicit_release_tag_survives_os_detection(self):
        f = self.fixture(); f.env['QN_RELEASE_TAG'] = 'v0.1.0'
        f.remote_release(tag='v0.1.0')
        # Serve the pinned old manifest but omit its archive. The checksum-first
        # path must still request exactly that archive and must never fall back.
        (f.root/'release/qingnode-0.1.0-linux-amd64.tar.gz').unlink()
        f.run('--auto', '--repo', '124aAA/openai', '--version', 'v0.1.0', online=True, ok=False)
        calls = (f.root/'commands.log').read_text()
        self.assertIn('/releases/download/v0.1.0/SHA256SUMS', calls)
        self.assertIn('/releases/download/v0.1.0/qingnode-0.1.0-linux-amd64.tar.gz', calls)
        self.assertNotIn('/releases/latest/', calls)
        self.assertFalse(f.state.exists())
        self.assertFalse(f.bin.exists())
        self.assertFalse(f.state.exists())

    def test_invalid_repository_and_tag_are_still_rejected(self):
        for args, message in [(('--repo', '../bad'), '仓库名无效'),
                              (('--repo', 'owner/..'), '仓库名无效'),
                              (('--repo', 'owner/.'), '仓库名无效'),
                              (('--version', 'v1.2.3; exit 0'), '管理器版本号无效')]:
            with self.subTest(args=args):
                f = self.fixture(); f.remote_release()
                self.assertIn(message, f.run('--auto', *args, online=True, ok=False))
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

    def test_release_accepts_named_new_docs_and_rejects_unknown_docs_or_links(self):
        names = ('GETTING_STARTED.md', 'FAQ.md', 'DEVELOPMENT.md', 'CAPABILITIES.md',
                 'BATCH_01.md', 'NETWORK_TESTS.md', 'BATCH_02.md', 'NETWORK_PERFORMANCE.md', 'BATCH_03.md',
                 'ENDPOINTS.md', 'BATCH04.md', 'TOPOLOGY.md', 'BATCH05.md', 'SUBSCRIPTIONS.md', 'BATCH06.md', 'CERTIFICATES.md', 'MIGRATION.md', 'BATCH07.md', 'MONITORING.md', 'BATCH08.md', 'PROTOCOLS.md', 'BATCH09.md', 'PLATFORMS.md', 'BATCH10.md', 'WORKFLOWS.md', 'BATCH11.md')
        for online in (False, True):
            for invalid in ('', 'unknown', 'near-name', 'symlink'):
                with self.subTest(online=online, invalid=invalid):
                    f = self.fixture()
                    docs = f.bundle/'docs'; docs.mkdir()
                    for name in names:
                        (docs/name).write_text('# '+name+'\n')
                    if invalid in ('unknown', 'near-name'):
                        (docs/('OTHER.md' if invalid == 'unknown' else 'FAQXmd')).write_text('unexpected\n')
                    elif invalid == 'symlink':
                        original = f.root/'original-doc'; original.write_text('linked\n')
                        (docs/'FAQ.md').unlink(); (docs/'FAQ.md').symlink_to(original)
                    f.sums()
                    if online:
                        f.remote_release()
                    out = f.install(online=online, ok=not invalid)
                    if invalid:
                        self.assertNotIn('[8/8]', out)
                        self.assertFalse(f.state.exists())
                        self.assertFalse(f.bin.exists())
                        self.assertFalse(f.host().get('passwd', False))
                    else:
                        self.assertIn('[8/8]', out)
                        self.assertTrue(f.host()['active'])

    def test_invalid_ports_fail_before_host_changes(self):
        for port in ('0', '65536', '-1', '443x', '000443', '443; exit 0'):
            with self.subTest(port=port):
                f = self.fixture()
                self.assertIn('端口无效', f.run('--port', port, ok=False))
                self.assertFalse(f.state.exists())
                self.assertFalse(f.bin.exists())
                self.assertNotIn('apt-get ', (f.root/'commands.log').read_text())

    def test_semantic_invalid_first_install_rejected_before_dependencies_or_host_changes(self):
        # Both adjacent and downloaded bundles exercise the real manager's
        # preflight through the fixture adapter, not a copy of the validators.
        cases = (
            ('--protocol', 'invented', '--server', '203.0.113.7'),
            ('--protocol', 'ss2022', '--server', 'bad host'),
            ('--protocol', 'ss2022', '--server', '203.0.113.7', '--sni', 'example.com'),
            ('--protocol', 'ss2022', '--server', '203.0.113.7', '--listen', 'not-an-ip'),
            ('--protocol', 'ss2022', '--server', '203.0.113.7', '--port', '443', '--random-port'),
            ('--protocol', 'ss-aead', '--server', '203.0.113.7', '--method', 'invalid'),
            ('--protocol', 'hysteria2', '--server', '203.0.113.7', '--certificate-id', 'aaaaaaaaaaaaaaaa'),
            ('--protocol', 'hysteria2', '--server', '203.0.113.7', '--sni', 'example.com',
             '--cert', '/no-such-certificate.pem', '--key', '/no-such-key.pem'),
        )
        for online in (False, True):
            for args in cases:
                with self.subTest(online=online, args=args):
                    f = self.fixture()
                    f.require_packages()
                    if online:
                        f.remote_release()
                    f.run(*args, online=online, ok=False)
                    for path in (f.state, f.bin, f.unit, f.lib):
                        self.assertFalse(path.exists(), str(path))
                    self.assertFalse(f.host().get('passwd', False))
                    self.assertEqual([], list((f.root/'tmp').iterdir()))
                    self.assertEqual([], list((f.root/'system/var/log').iterdir()))
                    calls = (f.root/'commands.log').read_text() if (f.root/'commands.log').exists() else ''
                    for forbidden in ('apt-get ', 'dnf ', 'apk add ', 'useradd ', 'adduser ',
                                      'qingnode core install', 'systemctl restart', 'rc-service qingnode restart'):
                        self.assertNotIn(forbidden, calls)

    def test_legacy_cli_fallback_isolated_and_never_swallows_semantic_errors(self):
        # The adapter emulates only the old unknown-command response. Full
        # historical binary compatibility requires the separate Linux gate.
        for online in (False, True):
            for args in (('--protocol', 'ss2022', '--server', '203.0.113.7'),
                         ('--auto', '--protocol', 'reality')):
                with self.subTest(online=online, args=args):
                    f = self.fixture()
                    f.env['QN_LEGACY_FIXTURE'] = '1'
                    if online: f.remote_release()
                    output = f.run(*args, online=online)
                    self.assertIn('旧版管理器隔离校验', output)
                    self.assertEqual(1, len(json.loads(f.data())['nodes']))
                    self.assertEqual([], list((f.root/'tmp').iterdir()))
            for args in (('--protocol', 'invented', '--server', '203.0.113.7'),
                         ('--protocol', 'ss2022', '--server', 'bad host'),
                         ('--auto', '--protocol', 'reality', '--target', 'example.com:443'),
                         ('--protocol', 'reality', '--server', '203.0.113.7',
                          '--sni', 'example.com', '--port', '443', '--random-port')):
                with self.subTest(online=online, invalid=args):
                    f = self.fixture(); f.require_packages()
                    f.env['QN_LEGACY_FIXTURE'] = '1'
                    if online: f.remote_release()
                    f.run(*args, online=online, ok=False)
                    self.assertFalse(f.state.exists())
                    self.assertFalse(f.bin.exists())
                    self.assertFalse(f.host().get('passwd', False))
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

    def test_new_platform_candidate_boundaries_and_state_preservation(self):
        for distro, version in [('rocky', '9.7'), ('alpine', '3.24.2')]:
            with self.subTest(distro=distro):
                f = self.fixture(distro, version)
                out = f.install()
                before = f.data()
                self.assertTrue(f.host()['active']); self.assertTrue(f.host()['enabled'])
                f.host(active=False, enabled=False)
                f.run('--reinstall')
                self.assertEqual(before, f.data())
                self.assertFalse(f.host()['active']); self.assertFalse(f.host()['enabled'])
                calls = (f.root/'commands.log').read_text()
                if distro == 'alpine':
                    self.assertTrue(f.unit.read_text().startswith('#!/sbin/openrc-run\n# Managed by QingNode\n'))
                    self.assertEqual(0o755, f.unit.stat().st_mode & 0o777)
                    self.assertIn('rc-service qingnode restart', calls)
                    self.assertNotIn('systemctl ', calls)
                    self.assertNotIn('setcap cap_net_bind_service=ep '+str(f.bin), calls)
                    self.assertIn('adduser -S -D -H ', calls)
                    self.assertIn('copytruncate', f.rotation.read_text())
                    self.assertIn('未开启或改动全局cron', out)
                else:
                    self.assertTrue(f.unit.read_text().startswith('# Managed by QingNode\n'))
                    self.assertIn('SELinux enforcing 保持启用', out)
                    self.assertIn('restorecon ', calls)
                    self.assertNotIn('setenforce ', calls)
                self.assertNotIn('firewall-cmd ', calls)

    def test_init_tools_without_real_controller_are_rejected_before_changes(self):
        for distro, version, pid, unavailable, marker in [
                ('ubuntu', '24.04', 'init', False, True),
                ('ubuntu', '24.04', 'systemd', True, True),
                ('alpine', '3.24.2', 'systemd', False, True),
                ('alpine', '3.24.2', 'init', True, True),
                ('alpine', '3.24.2', 'init', False, False)]:
            with self.subTest(distro=distro, pid=pid, unavailable=unavailable, marker=marker):
                f = self.fixture(distro, version); f.env['QN_PID1'] = pid
                if unavailable: f.env['QN_INIT_UNAVAILABLE'] = '1'
                if not marker: (f.root/'system/run/openrc/softlevel').unlink()
                f.install(ok=False)
                for path in (f.state, f.bin, f.unit, f.lib): self.assertFalse(path.exists(), str(path))
                # PID1 and missing-runlevel checks can now finish using only
                # procfs/local metadata, before any mocked command is invoked.
                command_log = f.root/'commands.log'
                calls = command_log.read_text() if command_log.exists() else ''
                self.assertNotIn('apt-get ', calls); self.assertNotIn('apk --wait', calls); self.assertNotIn('dnf -y', calls)

    def test_package_boundaries_have_locks_no_system_upgrade_and_abort_before_mutation(self):
        for distro, version, fault, expected in [
                ('ubuntu', '24.04', 'apt', 'apt-get -o DPkg::Lock::Timeout=30'),
                ('rocky', '9.7', 'dnf', 'dnf -y --setopt=exit_on_lock=True'),
                ('alpine', '3.24.2', 'apk', 'apk --wait 30 add --no-cache')]:
            with self.subTest(distro=distro):
                f = self.fixture(distro, version); f.require_packages()
                out = f.install(fault=fault, ok=False)
                self.assertTrue((f.root/'fault-fired').exists())
                self.assertIn(expected, (f.root/'commands.log').read_text())
                self.assertNotIn('[4/8]', out)
                for path in (f.state, f.bin, f.unit): self.assertFalse(path.exists(), str(path))
                calls = (f.root/'commands.log').read_text()
                self.assertNotRegex(calls, r'(?m)^(?:apk|dnf|apt-get).*\bupgrade\b')
                if fault == 'apt':
                    self.assertNotRegex(calls, r'(?m)^apt-get.*\binstall\b', 'repository update failure must not continue to package installation')

    def test_uncertain_service_snapshot_aborts_without_rewriting_existing_install(self):
        cases = [('ubuntu', '24.04', 'snapshot-query'), ('ubuntu', '24.04', 'activating'),
                 ('ubuntu', '24.04', 'deactivating'), ('ubuntu', '24.04', 'missing-state'),
                 ('ubuntu', '24.04', 'runtime-enabled'), ('ubuntu', '24.04', 'masked'),
                 ('alpine', '3.24.2', 'unknown-openrc')]
        for distro, version, condition in cases:
            with self.subTest(condition=condition):
                f = self.fixture(distro, version); f.install()
                before = (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host())
                if condition in ('activating', 'deactivating'):
                    f.env['QN_SERVICE_ACTIVE_STATE'] = condition
                elif condition == 'missing-state': f.env['QN_SERVICE_ACTIVE_STATE'] = ''
                elif condition == 'runtime-enabled': f.env['QN_SERVICE_UNIT_STATE'] = 'enabled-runtime'
                elif condition == 'masked': f.env['QN_SERVICE_UNIT_STATE'] = 'masked'
                elif condition == 'unknown-openrc': f.env['QN_BAD_OPENRC_STATUS'] = '1'
                output = f.run('--reinstall', fault='service-snapshot' if condition == 'snapshot-query' else '', ok=False)
                self.assertNotIn('[4/8]', output)
                self.assertEqual(before, (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host()))

    def test_alpine_glibc_bridge_is_explicit_and_core_failure_rolls_back(self):
        f = self.fixture('alpine', '3.24.2'); f.env['QN_MISSING_ABI'] = '1'
        f.install()
        calls = (f.root/'commands.log').read_text()
        self.assertIn('apk --wait 30 add --no-cache gcompat libgcc libstdc++ coreutils tar gzip', calls)
        f = self.fixture('alpine', '3.24.2')
        f.install(fault='core', ok=False)
        for path in (f.state, f.bin, f.unit, f.rotation): self.assertFalse(path.exists(), str(path))
        self.assertFalse(f.host().get('passwd', False))

    def test_dependency_install_uses_required_tools_without_unused_packages_or_system_upgrade(self):
        for distro, version in [('ubuntu', '24.04'), ('rocky', '9.8'), ('alpine', '3.24.2')]:
            with self.subTest(distro=distro):
                f = self.fixture(distro, version); f.require_packages()
                f.install()
                calls = (f.root/'commands.log').read_text().splitlines()
                installs = [line for line in calls if re.match(r'^(?:apt-get|dnf|apk)\s', line)
                            and re.search(r'\b(?:install|add)\b', line)]
                self.assertEqual(1, len(installs), installs)
                self.assertRegex(installs[0], r'\bcurl\b')
                for line in installs:
                    self.assertNotRegex(line, r'\b(?:wget|jq|unzip|upgrade|dist-upgrade|full-upgrade|autoremove|erase)\b')
                if distro == 'rocky':
                    self.assertIn('--setopt=install_weak_deps=False', installs[0])

    def test_openrc_upgrade_failure_restores_service_rotation_and_selected_status(self):
        for active, enabled in [(True, True), (False, False), (True, False), (False, True)]:
            with self.subTest(active=active, enabled=enabled):
                f = self.fixture('alpine', '3.24.2'); f.install()
                f.host(active=active, enabled=enabled)
                before = (f.bin.read_bytes(), f.unit.read_bytes(), f.rotation.read_bytes(), f.data())
                f.manager.write_text(MOCK+'\n# changed candidate\n'); f.sums()
                f.run('--reinstall', fault='core', ok=False)
                self.assertEqual(before, (f.bin.read_bytes(), f.unit.read_bytes(), f.rotation.read_bytes(), f.data()))
                self.assertEqual((active, enabled), (f.host()['active'], f.host()['enabled']))
                self.assertNotIn('filecap', f.host(), 'manager must not acquire a low-port file capability')

    def test_openrc_external_rotation_and_service_are_never_adopted(self):
        for kind in ('rotation', 'service', 'symlink'):
            with self.subTest(kind=kind):
                f = self.fixture('alpine', '3.24.2')
                if kind == 'rotation': f.rotation.write_text('external rotation\n')
                elif kind == 'service': f.unit.write_text('#!/sbin/openrc-run\n# external\n')
                else:
                    target = f.root/'external'; target.write_text('# Managed by QingNode\n')
                    f.rotation.symlink_to(target)
                f.install(ok=False)
                self.assertFalse(f.state.exists()); self.assertFalse(f.bin.exists())
                if kind == 'rotation': self.assertEqual('external rotation\n', f.rotation.read_text())
                if kind == 'service': self.assertIn('# external', f.unit.read_text())
                if kind == 'symlink': self.assertTrue(f.rotation.is_symlink())

    def test_service_marker_does_not_authorize_modified_command_or_unsafe_permissions(self):
        for distro, version in [('ubuntu', '24.04'), ('alpine', '3.24.2')]:
            for kind in ('command', 'mode', 'hardlink', 'symlink'):
                with self.subTest(distro=distro, kind=kind):
                    f = self.fixture(distro, version); f.install()
                    if kind == 'command':
                        original = f.unit.read_text()
                        field = 'ExecStart=' if distro == 'ubuntu' else 'command='
                        self.assertIn(field, original)
                        f.unit.write_text(original.replace(field, field+'EXTERNAL-'))
                    elif kind == 'mode': f.unit.chmod(0o666)
                    elif kind == 'hardlink': os.link(f.unit, f.root/'external-service-copy')
                    else:
                        saved = f.root/'external-service-copy'
                        f.unit.rename(saved); f.unit.symlink_to(saved)
                    before = (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host())
                    output = f.run('--reinstall', ok=False)
                    self.assertNotIn('[4/8]', output)
                    self.assertEqual(before, (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host()))
                    if kind == 'symlink': self.assertTrue(f.unit.is_symlink())

    def test_external_service_overrides_are_retained_without_mutation(self):
        for distro, version, kind in [('ubuntu', '24.04', 'dropin'),
                                      ('ubuntu', '24.04', 'loaded-dropin'),
                                      ('alpine', '3.24.2', 'conf')]:
            with self.subTest(kind=kind):
                f = self.fixture(distro, version); f.install()
                if kind == 'dropin':
                    override = Path(str(f.unit)+'.d')/'override.conf'
                    override.parent.mkdir(); override.write_text('[Service]\nExecStart=/foreign\n')
                elif kind == 'loaded-dropin':
                    override = f.root/'vendor-override.conf'; override.write_text('[Service]\nUser=root\n')
                    f.env['QN_LOADED_DROPINS'] = str(override)
                else:
                    override = f.root/'system/etc/conf.d/qingnode'
                    override.parent.mkdir(); override.write_text('command=/foreign\n')
                before = (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host(), override.read_bytes())
                output = f.run('--reinstall', ok=False)
                self.assertNotIn('[4/8]', output)
                self.assertEqual(before, (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host(), override.read_bytes()))

    def test_openrc_custom_runlevels_survive_success_and_failed_upgrade(self):
        f = self.fixture('alpine', '3.24.2'); f.install()
        f.host(enabled=True, runlevels=['custom', 'nonetwork'])
        before = f.data()
        f.run('--reinstall')
        self.assertEqual(['custom', 'nonetwork'], f.host()['runlevels'])
        f.run('--reinstall', fault='core', ok=False)
        self.assertEqual(['custom', 'nonetwork'], f.host()['runlevels'])
        self.assertEqual(before, f.data())

    def test_openrc_already_disabled_is_noop_for_upgrade_and_failure_restore(self):
        for fault in ('', 'core'):
            with self.subTest(fault=fault):
                f = self.fixture('alpine', '3.24.2'); f.install()
                f.host(active=False, enabled=False, runlevels=[])
                before = (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host())
                (f.root/'commands.log').write_text('')
                output = f.run('--reinstall', fault=fault, ok=not fault)
                self.assertNotIn('恢复未完成', output)
                self.assertEqual(before, (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host()))
                self.assertNotIn('rc-update del', (f.root/'commands.log').read_text())

    def test_architecture_selection_and_unknown_platform_fail_before_install(self):
        f = self.fixture('rocky', '9.7'); f.env['QN_ARCH'] = 'riscv64'
        f.install(ok=False); self.assertFalse(f.state.exists())
        for distro, version in [('rocky', '8.10'), ('alpine', '3.20.0'), ('alpine', '3.25.0')]:
            f = self.fixture(distro, version)
            self.assertIn('未适配的系统', f.install(ok=False))
            self.assertFalse(f.state.exists())

    def test_ss2022_and_ipv6_argument_forwarding(self):
        f = self.fixture()
        f.run('--protocol','ss2022','--name','SS-01','--server','2001:db8::7','--random-port')
        n = json.loads(f.data())['nodes'][0]
        self.assertEqual(('ss2022', 'SS-01', '::'), (n['protocol'], n['name'], n['listen']))
        self.assertGreaterEqual(n['port'], 10000)
        before = f.data(); f.run('--reinstall'); self.assertEqual(before, f.data())

    def test_nat_connection_port_forwarding_and_invalid_early_refusal(self):
        f = self.fixture()
        f.run('--protocol', 'ss2022', '--name', 'NAT-01', '--server', '203.0.113.8',
              '--listen', '127.0.0.1', '--port', '443', '--connect-port', '30000')
        n = json.loads(f.data())['nodes'][0]
        self.assertEqual(('127.0.0.1', 443, 30000), (n['listen'], n['port'], n['connect_port']))
        before = f.data(); f.run('--reinstall'); self.assertEqual(before, f.data())
        for value in ('', '0', '-1', '65536', '1e3', '0000001'):
            with self.subTest(value=value):
                f = self.fixture()
                self.assertIn('外部连接端口无效', f.run('--connect-port', value, ok=False))
                self.assertFalse(f.state.exists())

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

    def test_fresh_failure_before_unit_creation_does_not_report_false_recovery_failure(self):
        for fault in ('useradd', 'unit-write'):
            with self.subTest(fault=fault):
                f = self.fixture()
                # A real systemctl rejects disable on a service that never existed.
                # If rollback calls it, this persistent fault must make the test fail.
                out = f.install(fault=fault, recovery_fault='disable', ok=False)
                self.assertTrue((f.root/'fault-fired').exists(), 'forward fault was not reached')
                self.assertIn('安装失败，日志', out)
                self.assertNotIn('恢复未完成', out)
                self.assertNotIn('保留恢复文件', out)
                calls = (f.root/'commands.log').read_text()
                self.assertNotIn('systemctl disable', calls)
                self.assertEqual([], list((f.root/'tmp').iterdir()))
                for path in (f.bin, f.unit, f.lib, f.state):
                    self.assertFalse(path.exists(), str(path))
                self.assertFalse(f.host().get('passwd', False))
                self.assertFalse(f.host()['active'])
                self.assertFalse(f.host()['enabled'])

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
                self.assertEqual([], list((f.root/'tmp').iterdir()))

    def test_waiting_install_commands_preserve_external_edits_and_stop_recovery_controls(self):
        for distro, version, override in [('ubuntu','24.04','dropin'), ('alpine','3.24.2','confd')]:
            points = ('daemon-reload','core','check','restart') if distro=='ubuntu' else ('core','check','restart')
            for point in points:
                for kind in ('unit','manager','installer','unit-mode','unit-symlink','unit-hardlink',override, *(['rotation'] if distro=='alpine' else [])):
                    with self.subTest(distro=distro, point=point, kind=kind):
                        f = self.fixture(distro,version); f.install()
                        original = (f.bin.read_bytes(), f.unit.read_bytes(), (f.lib/'install.sh').read_bytes(), f.data())
                        f.manager.write_text(MOCK+'\n# distinct new candidate\n'); f.sums()
                        f.env.update(QN_MUTATE_POINT=point, QN_MUTATE_KIND=kind)
                        before_calls = len((f.root/'commands.log').read_text().splitlines())
                        out = f.run('--reinstall', ok=False)
                        self.assertTrue((f.root/'mutation-fired').exists(), 'callback was not reached')
                        self.assertIn('保留恢复文件', out)
                        self.assertIn('停止后续服务控制', out)
                        target = {'unit':f.unit,'manager':f.bin,'installer':f.lib/'install.sh','rotation':f.rotation}.get(kind)
                        if target:
                            self.assertEqual(b'# External administrator fixture; preserve this exact content\n',target.read_bytes())
                        elif kind=='unit-mode': self.assertEqual(0o600,f.unit.stat().st_mode&0o777)
                        elif kind=='unit-symlink': self.assertTrue(f.unit.is_symlink())
                        elif kind=='unit-hardlink': self.assertEqual(2,f.unit.stat().st_nlink)
                        else:
                            target = f.unit.with_name(f.unit.name+'.d')/'administrator.conf' if kind=='dropin' else f.root/'system/etc/conf.d/qingnode'
                            self.assertEqual(b'# External administrator override; preserve\n',target.read_bytes())
                        self.assertEqual(original[3],f.data())
                        retained = list((f.root/'tmp').iterdir()); self.assertEqual(1,len(retained))
                        for name,contents in zip(('old-bin','old-unit','old-installer'), original[:3]):
                            self.assertEqual(contents,(retained[0]/name).read_bytes())
                        calls=(f.root/'commands.log').read_text().splitlines()[before_calls:]
                        # The failed command is the final mutating native call;
                        # ownership/status observations after it remain read-only.
                        boundary = next(i for i,line in enumerate(calls) if
                                        (line.startswith('qingnode core install') if point=='core' else
                                         line=='qingnode check' if point=='check' else
                                         line=='systemctl daemon-reload' if point=='daemon-reload' else
                                         line in ('systemctl restart qingnode.service','rc-service qingnode restart')))
                        controls=[line for line in calls[boundary+1:] if re.match(r'(systemctl (daemon-reload|start|stop|restart|enable|disable)|rc-service qingnode (start|stop|restart)|rc-update (add|del))\b',line)]
                        self.assertEqual([],controls)

    def test_recovery_native_wait_edit_stops_following_restore_and_service_actions(self):
        for kind in ('unit','manager','dropin'):
            with self.subTest(kind=kind):
                f=self.fixture(); f.install()
                original=(f.bin.read_bytes(),f.unit.read_bytes(),f.data())
                f.manager.write_text(MOCK+'\n# distinct recovery candidate\n'); f.sums()
                f.env.update(QN_MUTATE_RECOVERY_POINT='daemon-reload',QN_MUTATE_KIND=kind)
                out=f.run('--reinstall',fault='core',ok=False)
                self.assertTrue((f.root/'mutation-fired').exists())
                self.assertIn('保留恢复文件',out)
                self.assertEqual(original[2],f.data())
                calls=(f.root/'commands.log').read_text().splitlines()
                boundary=max(i for i,line in enumerate(calls) if line=='systemctl daemon-reload')
                self.assertFalse(any(re.match(r'systemctl (start|stop|restart|enable|disable)\b',line)for line in calls[boundary+1:]))
                if kind in ('unit','manager'):
                    self.assertEqual(b'# External administrator fixture; preserve this exact content\n',(f.unit if kind=='unit'else f.bin).read_bytes())

    def test_sigterm_interrupt_after_candidate_install_restores_original_transaction(self):
        # This is an actual process interruption, not a mocked nonzero exit.
        # SIGKILL/power loss cannot run Bash's recovery trap and is deliberately
        # not covered by or claimed from this SIGTERM assertion.
        for distro, version in [('ubuntu', '24.04'), ('rocky', '9.8'), ('alpine', '3.24.2')]:
            for active, enabled in [(True, True), (False, False)]:
                with self.subTest(distro=distro, active=active, enabled=enabled):
                    f = self.fixture(distro, version); f.install()
                    f.host(active=active, enabled=enabled,
                           **({'runlevels': ['custom', 'nonetwork'] if enabled else []} if distro == 'alpine' else {}))
                    before = (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host(),
                              (f.lib/'install.sh').read_bytes(),
                              f.rotation.read_bytes() if f.rotation.exists() else None)
                    candidate = MOCK+'\n# distinct candidate to prove old manager restoration after SIGTERM\n'
                    f.manager.write_text(candidate); f.sums()
                    log = f.root/'interrupted-installer-private.log'
                    marker = f.root/'pause-point.json'
                    env = dict(f.env, QN_PAUSE_POINT='core')
                    worker = None
                    with log.open('xb') as output:
                        log.chmod(0o600)
                        process = subprocess.Popen(['bash', str(f.installer), '--reinstall'],
                                                   stdin=subprocess.DEVNULL, stdout=output,
                                                   stderr=subprocess.STDOUT, env=env,
                                                   start_new_session=True)
                        try:
                            deadline = time.monotonic()+30
                            observed = None
                            while time.monotonic() < deadline:
                                if marker.exists():
                                    try:
                                        observed = json.loads(marker.read_text())
                                    except json.JSONDecodeError:
                                        time.sleep(.02); continue
                                    break
                                self.assertIsNone(process.poll(), 'installer exited before the explicit pause; private fixture log retained')
                                time.sleep(.02)
                            self.assertIsNotNone(observed, 'installer did not reach its controlled core-install interruption point')
                            self.assertEqual(('core', 1), (observed['point'], observed['version']))
                            worker = int(observed['pid'])
                            self.assertGreater(worker, 1)
                            self.assertEqual(process.pid, os.getpgid(process.pid), 'installer must own a new process group')
                            self.assertEqual(process.pid, os.getpgid(worker), 'only our own installer session may be signalled')
                            self.assertNotEqual(before[0], f.bin.read_bytes(), 'candidate manager was not actually installed before interruption')
                            self.assertEqual(candidate.encode(), f.bin.read_bytes())
                            os.killpg(process.pid, signal.SIGTERM)
                            result = process.wait(timeout=30)
                            self.assertNotEqual(0, result, 'interrupted installation was incorrectly reported successful')
                        finally:
                            if process.poll() is None:
                                # No process enumeration or borrowed PID: this
                                # exact Popen created the only signalled session.
                                if os.getpgid(process.pid) == process.pid:
                                    os.killpg(process.pid, signal.SIGKILL)
                                process.wait(timeout=10)
                    # Wait for init to reap the terminated fixture child. A
                    # zombie cannot execute or hold the production service lock.
                    if worker:
                        deadline = time.monotonic()+5
                        while time.monotonic() < deadline:
                            try:
                                child_state = Path('/proc', str(worker), 'stat').read_text().rsplit(')', 1)[1].split()[0]
                            except FileNotFoundError:
                                break
                            if child_state == 'Z':
                                break
                            time.sleep(.02)
                        else:
                            self.fail('interrupted mock core process remained live')
                    actual = (f.bin.read_bytes(), f.unit.read_bytes(), f.data(), f.host(),
                              (f.lib/'install.sh').read_bytes(),
                              f.rotation.read_bytes() if f.rotation.exists() else None)
                    self.assertEqual(before, actual, 'SIGTERM did not restore exact manager/unit/State/host/helper/rotation')
                    text = log.read_text(errors='replace')
                    self.assertIn('安装未完成，正在恢复原管理器与服务', text)
                    self.assertNotIn('恢复未完成', text)
                    self.assertNotIn('保留恢复文件', text)
                    self.assertEqual([], list((f.root/'tmp').iterdir()), 'successful trap recovery retained unexpected temporary files')
    def test_persistent_recovery_failure_keeps_private_original_files(self):
        for point, message in [('restore-bin', '管理器二进制'),
                               ('restore-unit', '服务文件'),
                               ('restore-installer', '安装辅助脚本'),
                               ('daemon-reload', '重新加载服务定义'),
                               ('restart', '恢复原服务运行状态')]:
            with self.subTest(point=point):
                f = self.fixture(); f.install()
                original = (f.bin.read_bytes(), f.unit.read_bytes(), f.data(),
                            (f.lib/'install.sh').read_bytes())
                f.manager.write_text(MOCK+'\n# candidate update\n'); f.sums()
                out = f.run('--reinstall', fault='core', recovery_fault=point, ok=False)
                self.assertIn('恢复未完成', out)
                self.assertIn(message, out)
                self.assertIn('保留恢复文件', out)
                retained = list((f.root/'tmp').iterdir())
                self.assertEqual(1, len(retained))
                saved = retained[0]
                self.assertEqual(0o700, saved.stat().st_mode & 0o777)
                self.assertEqual(original[0], (saved/'old-bin').read_bytes())
                self.assertEqual(original[1], (saved/'old-unit').read_bytes())
                self.assertEqual(original[3], (saved/'old-installer').read_bytes())
                self.assertEqual(original[2], f.data())
                self.assertIn(str(saved), out)
                self.assertIn('qingnode-install-', out)

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
