#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
VERSION=${1:-0.2.3}
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo '需要三段数字版本号' >&2; exit 2; }
REVISION=$(git rev-parse --short=12 HEAD 2>/dev/null || printf source)
command -v go >/dev/null || { echo '构建需要 Go 1.25 或更新版本。' >&2; exit 1; }
[[ -d vendor ]] || go mod vendor
mkdir -p dist
TEMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEMP_DIR"' EXIT
for ARCH in amd64 arm64; do
  DEST=$TEMP_DIR/$ARCH
  mkdir -p "$DEST"
  CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -mod=vendor -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$VERSION -X main.revision=$REVISION" -o "$DEST/qingnode" ./cmd/qingnode
  cp install.sh README.md LICENSE THIRD_PARTY.md "$DEST/"
  sed -i -E "s/VERSION=v[0-9]+\.[0-9]+\.[0-9]+/VERSION=v$VERSION/" "$DEST/install.sh"
  mkdir -p "$DEST/docs"
  cp docs/ARCHITECTURE.md docs/TEST_REPORT.md docs/RELEASE_NOTES.md docs/AUDIT_STAGE2.md "$DEST/docs/"
  python3 - "$DEST/THIRD_PARTY.md" "$(go env GOROOT)/LICENSE" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1])
with p.open('a') as out:
 out.write('\n\n---\n\n## Go runtime and standard library\n\n```text\n'+pathlib.Path(sys.argv[2]).read_text()+'\n```\n')
 for f in sorted(pathlib.Path('vendor').rglob('*')):
  if f.is_file() and f.name.lower() in ('license','license.txt','license.md','copyright','notice'):
   out.write('\n\n---\n\n## '+str(f)+'\n\n```text\n'+f.read_text(errors='replace')+'\n```\n')
PY
  chmod 755 "$DEST/qingnode" "$DEST/install.sh"
  (cd "$DEST" && sha256sum qingnode install.sh README.md LICENSE THIRD_PARTY.md docs/*.md > SHA256SUMS)
  tar --sort=name --mtime='UTC 2026-09-08' --owner=0 --group=0 --numeric-owner -czf "dist/qingnode-$VERSION-linux-$ARCH.tar.gz" -C "$DEST" qingnode install.sh README.md LICENSE THIRD_PARTY.md SHA256SUMS docs
done
(cd dist && sha256sum "qingnode-$VERSION-linux-amd64.tar.gz" "qingnode-$VERSION-linux-arm64.tar.gz" > SHA256SUMS)
echo "已构建两个架构，版本 $VERSION，源码修订 $REVISION"
