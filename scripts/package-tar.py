#!/usr/bin/env python3
"""Create the same archive permissions on Unix and Windows build hosts."""
import datetime
import gzip
import pathlib
import sys
import tarfile

source = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
timestamp = int(datetime.datetime.strptime(sys.argv[3], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc).timestamp())
executables = set(sys.argv[4:])
with output.open("wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(source.rglob("*")):
                if path.is_symlink():
                    raise ValueError("packaging refuses symbolic links")
                name = path.relative_to(source).as_posix()
                member = tarfile.TarInfo(name)
                member.uid = member.gid = 0
                member.mtime = timestamp
                if path.is_dir():
                    member.type = tarfile.DIRTYPE
                    member.mode = 0o755
                    archive.addfile(member)
                elif path.is_file():
                    member.mode = 0o755 if name in executables else 0o644
                    member.size = path.stat().st_size
                    with path.open("rb") as data:
                        archive.addfile(member, data)
                else:
                    raise ValueError("packaging requires regular files")
