#!/usr/bin/env python3
"""Explicit local PTY acceptance: no production State, services or network.

This emulates narrow SSH terminal sizes. It is not a physical phone/GUI test.
Only fixed offline commands run against newly-created private directories.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
try:
    import fcntl
    import pty
    import termios
except ImportError:
    fcntl = pty = termios = None

MAX_OUTPUT = 256 * 1024

def checked_binary(path, expected):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('explicit regular binary and SHA256 required')
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError('binary digest mismatch')
    return path

class Session:
    def __init__(self, command, width, env):
        self.master, self.slave = pty.openpty()
        self.before = termios.tcgetattr(self.slave)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, width, 0, 0))
        def own_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.process = subprocess.Popen(command, stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                        env=env, preexec_fn=own_terminal, close_fds=True)
        self.output = bytearray()
        self.search_from = 0
    def read(self, marker=None, timeout=10):
        deadline = time.monotonic() + timeout
        marker = marker.encode() if marker is not None else None
        while time.monotonic() < deadline:
            if marker is not None:
                found = self.output.find(marker, self.search_from)
                if found >= 0:
                    self.search_from = found + len(marker)
                    return
            ready, _, _ = select.select([self.master], [], [], .05)
            if ready:
                try: chunk = os.read(self.master, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO: break
                    raise
                self.output.extend(chunk)
                if len(self.output) > MAX_OUTPUT: raise RuntimeError('PTY output budget exceeded')
            elif self.process.poll() is not None:
                break
        if marker is not None and self.output.find(marker, self.search_from) < 0:
            raise RuntimeError('expected fixed prompt was not reached')
        if marker is not None:
            self.search_from = self.output.find(marker, self.search_from) + len(marker)
    def send(self, value): os.write(self.master, value.encode())
    def finish(self, expected=0):
        self.read(timeout=10)
        code = self.process.wait(timeout=5)
        if code != expected: raise RuntimeError('unexpected CLI exit code: '+str(code))
        text = self.output.decode('utf-8')
        if termios.tcgetattr(self.slave) != self.before: raise RuntimeError('terminal attributes not restored')
        return text
    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
        os.close(self.master)
        os.close(self.slave)

def session_case(binary, root, args, width, env, inputs, expected=0):
    session = Session([str(binary), '--offline', '--root', str(root), *args], width, env)
    try:
        for prompt, answer in inputs:
            session.read(prompt)
            session.send(answer)
        text = session.finish(expected)
        if (env.get('NO_COLOR') or env.get('TERM') == 'dumb') and '\x1b[' in text:
            raise RuntimeError('ANSI output in plain terminal mode')
        return text
    finally: session.close()

def check_public_output(text, width, secrets):
    # Independent terminal-cell check for this fixture's Chinese, ASCII and
    # simple emoji. No raw capture or secret value is included in failures.
    if any(value and value in text for value in secrets):
        raise RuntimeError('ordinary human output exposed fixture credentials')
    for char in text:
        if (unicodedata.bidirectional(char) in ('LRE','RLE','LRO','RLO','PDF','LRI','RLI','FSI','PDI')
                or unicodedata.category(char) == 'Cc' and char not in '\r\n'):
            raise RuntimeError('ordinary human output retained display controls')
    for line in text.replace('\r\n','\n').split('\n'):
        columns = sum(0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in ('W','F') else 1
                      for char in line)
        if columns > width:
            raise RuntimeError('ordinary human output exceeded actual PTY width')

def human_query_cases(binary, work, env):
    # This isolated, valid State models existing names admitted by the data
    # model, including Bidi format characters which a new form now refuses.
    root = work / ('人类\u202e' + '长'*32 + '😀')
    base = [str(binary),'--offline','--root',str(root)]
    def command(args):
        result = subprocess.run([*base,*args],stdin=subprocess.DEVNULL,capture_output=True,timeout=15,env=env)
        if result.returncode or len(result.stdout)+len(result.stderr)>MAX_OUTPUT:
            raise RuntimeError('isolated human-query fixture command failed')
        return result.stdout.decode('utf-8')
    command(['add','--protocol','ss2022','--server','2001:db8:1234:5678:90ab:cdef:1234:5678',
             '--listen','::1','--port','24443','--name','legacy-ss','--quiet'])
    long_domain = '.'.join(['server-'+'a'*24]*5)+'.example.net'
    command(['add','--protocol','reality','--server',long_domain,'--listen','127.0.0.1',
             '--port','24444','--sni','example.com','--name','legacy-reality','--quiet'])
    path = root/'current/state.json'
    state = json.loads(path.read_bytes())
    ss = next(node for node in state['nodes'] if node['protocol']=='ss2022')
    reality = next(node for node in state['nodes'] if node['protocol']=='reality')
    ss['name'] = '旧名\u202e'+'长中文'*12+'😀'
    ss['users'][0]['name'] = '设备\u2066'+ss['users'][0]['password']
    reality['name'] = '域名\u2066'+'查询'*16+'😀'
    path.write_text(json.dumps(state,ensure_ascii=False),encoding='utf-8')
    command(['validate-state','--file',str(path)])
    before = path.read_bytes()
    ss_password = ss['shadowsocks']['server_key']+':'+ss['users'][0]['password']
    secrets = [ss['users'][0]['password'],ss['shadowsocks']['server_key'],ss_password,
               reality['users'][0]['uuid'],reality['reality']['private_key'],reality['reality']['short_id']]
    uris = [command(['export','--id',node['id'],'--user',node['users'][0]['id'],'--format','uri']).strip()
            for node in (ss,reality)]
    private_lines = [*uris,'Password：'+ss_password,'UUID：'+reality['users'][0]['uuid'],
                     'Short ID：'+reality['reality']['short_id'],
                     'Reality Private Key：'+reality['reality']['private_key']]
    for width in (32,40,80):
        for name in ('list','info','status'):
            text = session_case(binary,root,[name],width,env,[])
            check_public_output(text,width,secrets)
            if '😀' not in text or name!='status' and '旧名' not in text:
                raise RuntimeError('human query lost Unicode display content')
            if before != path.read_bytes():
                raise RuntimeError('human query changed saved legacy State')
        error_text = session_case(binary,root,['edit','--id',ss['id'],'--port','not-a-port'],width,env,[],1)
        check_public_output(error_text,width,secrets)
        private = session_case(binary,root,['info','--show-secrets','--show-private'],width,env,[])
        lines = private.replace('\r\n','\n').split('\n')
        if any(lines.count(line)!=1 for line in private_lines):
            raise RuntimeError('explicit URI or credential bytes were wrapped, redacted or duplicated')
        if before != path.read_bytes():
            raise RuntimeError('explicit private query changed saved legacy State')
    return ['pty-public-human-queries-32-40-80-width-sanitized-readonly']

def run_suite(binary, work):
    checks = []
    for width, terminal, no_color in [(32,'xterm-256color',False),(40,'xterm-256color',True),(80,'dumb',False)]:
        env = {**os.environ, 'TERM':terminal}
        if no_color: env['NO_COLOR']='1'
        else: env.pop('NO_COLOR',None)
        root = work/('cancel-'+str(width))
        session_case(binary,root,[],width,env,[('选择','wrong\n0\n')])
        if root.exists(): raise RuntimeError('menu cancel initialized State')
        for label,answer,code in [('cancel',':cancel\n',0),('eof','\x04',1)]:
            target=work/(label+'-'+str(width))
            session_case(binary,target,['wizard','--protocol','ss2022','--quiet'],width,env,[('节点名称',answer)],code)
            if target.exists(): raise RuntimeError('cancelled wizard wrote State')
        checks.append('pty-'+str(width)+'-invalid-menu-cancel-eof-plain-mode')
    env = {**os.environ,'TERM':'dumb','NO_COLOR':'1'}
    root = work/'configured'
    session_case(binary,root,['wizard','--protocol','ss2022','--quiet'],40,env,
                 [('节点名称','终端😀node\n'),('客户端连接','[2001:db8::1]\n'),('端口','24443\n')])
    before=(root/'current/state.json').read_bytes()
    checks.append('pty-complete-offline-node-unicode-ipv6-real-impact')
    for command in [('status','--json'),('overview','--json'),('list','--json'),('info','--json')]:
        completed=subprocess.run([str(binary),'--offline','--root',str(root),*command],stdin=subprocess.DEVNULL,
                                 capture_output=True,timeout=10,env=env)
        if completed.returncode or len(completed.stdout)>MAX_OUTPUT: raise RuntimeError('machine query failed or exceeded budget')
        value=json.loads(completed.stdout)
        if value.get('version') != 1: raise RuntimeError('unversioned machine query')
    if before != (root/'current/state.json').read_bytes(): raise RuntimeError('queries modified State')
    checks.append('non-tty-single-json-documents-state-unchanged')
    # Real hidden input, actual signal and actual termios comparison after exit.
    for sig,code in [(signal.SIGINT,130),(signal.SIGTERM,143)]:
        session=Session([str(binary),'--offline','--root',str(root),'backup'],40,env)
        try:
            session.read('备份口令')
            deadline=time.monotonic()+3
            while termios.tcgetattr(session.slave)[3]&termios.ECHO and time.monotonic()<deadline: time.sleep(.01)
            if termios.tcgetattr(session.slave)[3]&termios.ECHO: raise RuntimeError('secret-input echo was not disabled')
            os.kill(session.process.pid,sig)
            session.finish(code)
        finally: session.close()
        if before != (root/'current/state.json').read_bytes(): raise RuntimeError('interrupted password changed node')
    checks.append('secret-input-sigint-sigterm-real-termios-restored')
    checks.extend(human_query_cases(binary,work,env))
    return checks

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable',action='store_true',required=True)
    parser.add_argument('--bin',type=Path,required=True)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(argv)
    if sys.platform!='linux' or pty is None: parser.error('requires a Linux POSIX PTY; physical phone is a separate test')
    binary=checked_binary(args.bin,args.sha256)
    if not args.out.is_absolute() or args.out.exists() or args.out.is_symlink(): parser.error('new absolute report path required')
    with tempfile.TemporaryDirectory(prefix='qingnode-final-terminal-') as temporary:
        checks=run_suite(binary,Path(temporary))
    report=dict(version=1,status='passed',source='actual-linux-posix-pty',binary_sha256=args.sha256,
                widths=[32,40,80],checks=checks,physical_phone_ssh='not-tested',client_GUI='not-tested',
                production_state_or_services_changed=False,raw_terminal_capture_included=False)
    fd=os.open(args.out,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as out: json.dump(report,out,indent=2);out.write('\n')
    print('PASS bounded PTY workflow; physical phone and public client remain untested')

if __name__=='__main__': main()
