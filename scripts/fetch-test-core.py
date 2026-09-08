#!/usr/bin/env python3
"""Download a pinned official core for CI; verifies archive before extraction."""
import hashlib, io, os, pathlib, platform, tarfile, urllib.request

arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
sums={'amd64':'2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63','arm64':'04d9b40bc98dc55b6f509ce3292145c65478f65866bea64826ebb2f382385088'}
root=pathlib.Path('artifacts/test-core').resolve()
root.mkdir(parents=True,exist_ok=True)
name=f'sing-box-1.14.0-linux-{arch}.tar.gz'
data=urllib.request.urlopen(f'https://github.com/SagerNet/sing-box/releases/download/v1.14.0/{name}',timeout=120).read()
assert hashlib.sha256(data).hexdigest()==sums[arch], 'official archive checksum mismatch'
(root/name).write_bytes(data)
with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
 members=[m for m in archive.getmembers() if pathlib.PurePosixPath(m.name).name=='sing-box']
 assert len(members)==1 and members[0].isfile()
 executable=root/'sing-box'
 executable.write_bytes(archive.extractfile(members[0]).read())
 executable.chmod(0o755)
print(executable)
if os.environ.get('GITHUB_ENV'):
 with open(os.environ['GITHUB_ENV'],'a') as out:
  out.write(f'SING_BOX_BIN={executable}\nSING_BOX_ARCHIVE={root/name}\n')
