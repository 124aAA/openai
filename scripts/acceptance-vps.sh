#!/usr/bin/env bash
# Explicit acceptance entry for a disposable, clean systemd VPS. No firewall/sysctl changes.
set -Eeuo pipefail
umask 077
if [[ ${1:-} != --disposable || $# -lt 2 ]]; then
  echo '仅在可重建的空白 VPS 上执行：sudo bash scripts/acceptance-vps.sh --disposable /绝对路径/解压发行包 [--core-archive 官方归档]'
  echo '将安装两个本机测试节点，测试管理生命周期；成功后卸载。公网/移动端验收需要另行进行。'
  exit 2
fi
[[ $EUID == 0 && $(ps -p 1 -o comm=) == systemd ]] || { echo '未验证：需要 root 与真实 systemd VPS。' >&2; exit 1; }
BUNDLE=$2
shift 2
INSTALL_EXTRA=() CORE_EXTRA=()
if (($#)); then
  [[ $# == 2 && $1 == --core-archive ]] || { echo '仅接受 --core-archive 官方归档。' >&2; exit 2; }
  INSTALL_EXTRA=(--core-archive "$2")
  CORE_EXTRA=(--archive "$2")
fi
[[ $BUNDLE == /* && -f $BUNDLE/install.sh ]] || { echo '请提供绝对路径的完整发行包。' >&2; exit 2; }
[[ ! -e /var/lib/qingnode && ! -e /usr/local/bin/qingnode && ! -e /etc/systemd/system/qingnode.service ]] || { echo '发现已有 QingNode；拒绝在非空主机运行验收。' >&2; exit 1; }
TEMP_DIR=$(mktemp -d)
cleanup() {
  rc=$?
  trap - EXIT
  rm -rf -- "$TEMP_DIR"
  if ((rc)); then echo '验收失败：保留项目安装现场，请检查 qingnode diagnose；未自动删除节点。' >&2; fi
  exit "$rc"
}
trap cleanup EXIT
bash "$BUNDLE/install.sh" --auto --protocol ss2022 --name acceptance-ss --server 127.0.0.1 --listen 127.0.0.1 --random-port "${INSTALL_EXTRA[@]}"
cp /var/lib/qingnode/current/state.json "$TEMP_DIR/original.json"
bash "$BUNDLE/install.sh" --reinstall "${INSTALL_EXTRA[@]}"
cmp /var/lib/qingnode/current/state.json "$TEMP_DIR/original.json"
qingnode check
qingnode status
qingnode service disable
qingnode restart
if systemctl is-enabled --quiet qingnode.service; then echo '重启错误地重新启用了自启。' >&2; exit 1; fi
qingnode stop
bash "$BUNDLE/install.sh" --reinstall "${INSTALL_EXTRA[@]}"
if systemctl is-active --quiet qingnode.service; then echo '重复安装改变了停止状态。' >&2; exit 1; fi
qingnode start
qingnode service enable
qingnode add --auto --protocol reality --name acceptance-reality --server 127.0.0.1 --listen 127.0.0.1 --random-port --quiet
qingnode export --id acceptance-ss --format sing-box --out "$TEMP_DIR/client.json"
qingnode export --id acceptance-reality --format uri --out "$TEMP_DIR/client.uri"
openssl rand -base64 32 > "$TEMP_DIR/pass"
qingnode backup --file "$TEMP_DIR/backup.qnbak" --password-file "$TEMP_DIR/pass"
qingnode edit --id acceptance-ss --random-port
qingnode restore --file "$TEMP_DIR/backup.qnbak" --password-file "$TEMP_DIR/pass" --yes
qingnode disable --id acceptance-reality
qingnode enable --id acceptance-reality
before=$(sha256sum /var/lib/qingnode/current/state.json)
if qingnode edit --id acceptance-ss --port 0; then echo '非法端口被接受。' >&2; exit 1; fi
[[ $(sha256sum /var/lib/qingnode/current/state.json) == "$before" ]]
qingnode delete --id acceptance-reality --yes
qingnode info --id acceptance-ss
qingnode uninstall --yes
qingnode core install "${CORE_EXTRA[@]}"
qingnode start
qingnode check
qingnode uninstall --purge --yes
[[ ! -e /var/lib/qingnode && ! -e /usr/local/bin/qingnode && ! -e /etc/systemd/system/qingnode.service ]]
# Exercise the default REALITY installer on a clean host too, including retained account reuse.
bash "$BUNDLE/install.sh" --auto --server 127.0.0.1 --listen 127.0.0.1 "${INSTALL_EXTRA[@]}"
qingnode check
qingnode uninstall --purge --yes
[[ ! -e /var/lib/qingnode && ! -e /usr/local/bin/qingnode && ! -e /etc/systemd/system/qingnode.service ]]
echo '本机安装/重复执行/服务/节点/备份恢复/卸载验收通过。公网传输、ACME、BBR、防火墙、ARM64 与跨版本升级仍须单独验收。'
