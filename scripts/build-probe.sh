#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
VERSION=${1:-0.3.0}
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo '需要三段数字版本号' >&2; exit 2; }
REVISION=$(git rev-parse --short=12 HEAD 2>/dev/null || printf source)
command -v go >/dev/null || { echo '构建需要 Go 1.25 或更新版本。' >&2; exit 1; }
command -v python3 >/dev/null || { echo '构建需要 Python 3。' >&2; exit 1; }
[[ -d vendor ]] || go mod vendor
mkdir -p artifacts/probe
TEMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEMP_DIR"' EXIT
for TARGET in linux-amd64 linux-arm64 windows-amd64; do
  TARGET_OS=${TARGET%-*}
  TARGET_ARCH=${TARGET#*-}
  DEST=$TEMP_DIR/$TARGET
  mkdir -p "$DEST/docs"
  BINARY=qingprobe
  [[ $TARGET_OS != windows ]] || BINARY=qingprobe.exe
  CGO_ENABLED=0 GOOS=$TARGET_OS GOARCH=$TARGET_ARCH go build -mod=vendor -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$VERSION -X main.revision=$REVISION" -o "$DEST/$BINARY" ./cmd/qingprobe
  cp LICENSE THIRD_PARTY.md "$DEST/"
  cp docs/NETWORK_TESTS.md docs/BATCH_02.md docs/NETWORK_PERFORMANCE.md docs/BATCH_03.md docs/ENDPOINTS.md docs/BATCH04.md docs/TOPOLOGY.md docs/BATCH05.md docs/SUBSCRIPTIONS.md docs/BATCH06.md docs/CERTIFICATES.md docs/MIGRATION.md docs/BATCH07.md docs/MONITORING.md docs/BATCH08.md docs/PROTOCOLS.md docs/BATCH09.md docs/PLATFORMS.md docs/BATCH10.md docs/WORKFLOWS.md docs/BATCH11.md "$DEST/docs/"
  python3 - "$DEST/THIRD_PARTY.md" "$(go env GOROOT)/LICENSE" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
with p.open('a', encoding='utf-8', newline='\n') as out:
    out.write('\n\n---\n\n## Go runtime and standard library\n\n```text\n' + pathlib.Path(sys.argv[2]).read_text() + '\n```\n')
    for f in sorted(pathlib.Path('vendor').rglob('*')):
        if f.is_file() and f.name.lower() in ('license', 'license.txt', 'license.md', 'copyright', 'notice'):
            out.write('\n\n---\n\n## ' + str(f) + '\n\n```text\n' + f.read_text(errors='replace') + '\n```\n')
PY
  chmod 755 "$DEST/$BINARY"
  (cd "$DEST" && python3 "$OLDPWD/scripts/package-sums.py" "$BINARY" LICENSE THIRD_PARTY.md docs/*.md > SHA256SUMS)
  ARCHIVE=artifacts/probe/qingprobe-$VERSION-$TARGET
  if [[ $TARGET_OS == windows ]]; then
    python3 - "$DEST" "$ARCHIVE.zip" <<'PY'
import pathlib, stat, sys, zipfile
root = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for source in sorted(root.rglob('*')):
        if source.is_file():
            name = source.relative_to(root).as_posix()
            entry = zipfile.ZipInfo(name, date_time=(2026, 10, 13, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            entry.external_attr = ((stat.S_IFREG | (0o755 if name.endswith('.exe') else 0o644)) << 16)
            archive.writestr(entry, source.read_bytes())
PY
  else
    python3 scripts/package-tar.py "$DEST" "$ARCHIVE.tar.gz" 2026-10-13 "$BINARY"
  fi
done
(cd artifacts/probe && python3 "$OLDPWD/scripts/package-sums.py" "qingprobe-$VERSION-linux-amd64.tar.gz" "qingprobe-$VERSION-linux-arm64.tar.gz" "qingprobe-$VERSION-windows-amd64.zip" > SHA256SUMS)
echo "已构建 qingprobe Linux amd64/arm64 与 Windows amd64，版本 $VERSION，源码修订 $REVISION；输出 artifacts/probe/"
