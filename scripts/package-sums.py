#!/usr/bin/env python3
"""Write the raw-byte checksum contract without platform-dependent '*' modes."""
import hashlib
import pathlib
import sys

for name in sys.argv[1:]:
    path = pathlib.Path(name)
    if not path.is_file() or path.is_symlink():
        raise ValueError("checksums require regular files")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    # stdout's text layer translates LF to CRLF on Windows. The installed
    # Linux awk/sha256sum contract needs the same bytes on every build host.
    sys.stdout.buffer.write((digest.hexdigest() + "  " + path.as_posix() + "\n").encode("utf-8"))
