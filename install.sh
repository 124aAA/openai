#!/usr/bin/env bash
# QingNode bootstrap. No remote shell fragments are evaluated.
set -Eeuo pipefail
umask 077

ROOT=/var/lib/qingnode
BIN=/usr/local/bin/qingnode
UNIT=/etc/systemd/system/qingnode.service
OWNER='QingNode managed directory v1'
BUNDLE=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEFAULT_REPO=124aAA/openai
REPO='' VERSION=v0.2.5 PORT=443 CORE_ARCHIVE='' DEBUG=0 REINSTALL=0 HAS_ARGS=$#
INIT_ARGS=()
WIZARD_PROTOCOL=''
LIB=/usr/local/lib/qingnode
ACCOUNT_RECORD=/var/backups/qingnode/.qingnode-account
step() { printf '[%s/8] %s\n' "$1" "$2"; }
while (($#)); do
  case "$1" in
    --repo|--version|--server|--sni|--port|--core-archive|--name|--protocol|--listen|--target|--fingerprint|--cert|--key|--acme-email|--user)
      (($# >= 2)) || { echo '参数缺少值' >&2; exit 2; }
      case "$1" in
        --repo) REPO=$2;; --version) VERSION=$2;;
        --port) PORT=$2;; --core-archive) CORE_ARCHIVE=$2;;
      esac
      case "$1" in --repo|--version|--core-archive) ;; *) INIT_ARGS+=("$1" "$2");; esac
      shift 2;;
    --auto|--random-port) INIT_ARGS+=("$1"); shift;;
    --debug) DEBUG=1; shift;;
    --reinstall) REINSTALL=1; shift;;
    install) REINSTALL=1; shift;;
    --help)
      echo '一键安装：sudo bash install.sh（先选择协议，再搭建并显示连接信息）'
      echo '自动安装：sudo bash install.sh --auto（跳过选择，自动搭建 REALITY）'
      echo '本地安装：sudo bash install.sh [--server 公网IP --sni 目标域名 --port 443]'
      echo 'SS2022：sudo bash install.sh --protocol ss2022 --server 公网IP --random-port'
      echo '在线安装：sudo bash install.sh（自动从 124aAA/openai 下载已校验发行包）'
      echo '指定版本：sudo bash install.sh --repo 124aAA/openai --version v0.2.5 [初始化参数]'
      echo '可加 --core-archive 官方 sing-box 1.14.0 的本架构 tar.gz，使用内置摘要校验。'
      exit 0;;
    *) echo "未知参数：$1" >&2; exit 2;;
  esac
done
[[ $EUID == 0 ]] || { echo '请使用 sudo 或 root 运行。' >&2; exit 1; }
if ((HAS_ARGS==0 && REINSTALL==0)) && [[ -x $BIN && -f $ROOT/.qingnode-owner && $(cat "$ROOT/.qingnode-owner") == "$OWNER" ]]; then exec "$BIN"; fi
if ((${#INIT_ARGS[@]}==0)) && [[ ! -e $ROOT/current ]]; then
  [[ -t 0 ]] || { echo '首次安装需要交互终端选择协议；无人值守请加 --auto，或提供完整初始化参数。' >&2; exit 2; }
  printf '\nQingNode 青节点 — 请选择要搭建的节点\n1. VLESS REALITY / Vision（无需自己的域名，自动筛选伪装目标）\n2. Shadowsocks 2022（无需域名，客户端需支持 SS2022）\n3. Hysteria2（UDP，需要域名及证书）\n0. 退出，不安装\n'
  while :; do
    printf '选择 [1/2/3/0]：'
    if ! read -r choice; then echo '已取消，未开始安装。'; exit 0; fi
    case "$choice" in
      1) INIT_ARGS=(--auto --protocol reality); break;;
      2) INIT_ARGS=(--auto --protocol ss2022); break;;
      3) WIZARD_PROTOCOL=hysteria2; break;;
      0) echo '已取消，未开始安装。'; exit 0;;
      *) echo '请输入 1、2、3 或 0；尚未开始安装。';;
    esac
  done
fi
step 1 "检测系统、权限与架构"
[[ $(ps -p 1 -o comm=) == systemd ]] || { echo '需要以 systemd 启动的 Debian/Ubuntu 主机。' >&2; exit 1; }
[[ -r /etc/os-release ]] || exit 1
# Isolate all os-release assignments: its VERSION must not replace our tag.
QN_OS_INFO=$(
  # os-release is a local root-owned operating-system file.
  # shellcheck source=/dev/null
  . /etc/os-release || exit 1
  printf '%s %s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}"
)
read -r QN_OS_ID QN_OS_VERSION_ID <<< "$QN_OS_INFO"
case "$QN_OS_ID:$QN_OS_VERSION_ID" in debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;; *) echo "未验收的系统：$QN_OS_ID $QN_OS_VERSION_ID" >&2; exit 1;; esac
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo '仅支持 x86_64 和 ARM64。' >&2; exit 1;; esac
if [[ ! $PORT =~ ^[0-9]+$ || ${#PORT} -gt 5 ]]; then
  echo '端口无效。' >&2; exit 1
fi
PORT=$((10#$PORT))
if ((PORT < 1 || PORT > 65535)); then
  echo '端口无效。' >&2; exit 1
fi
check_owned_paths() {
if [[ -e $ROOT || -L $ROOT ]]; then
  [[ -d $ROOT && ! -L $ROOT && -f $ROOT/.qingnode-owner && $(cat "$ROOT/.qingnode-owner") == "$OWNER" ]] || { echo '状态目录已有其他内容，拒绝接管。' >&2; exit 1; }
fi
if [[ -e $UNIT || -L $UNIT ]]; then
  [[ -f $UNIT && ! -L $UNIT && $(head -n 1 "$UNIT") == '# Managed by QingNode' ]] || { echo '同名服务不属于 QingNode。' >&2; exit 1; }
fi
if [[ -e $BIN || -L $BIN ]]; then
  [[ -f $ROOT/.qingnode-owner && ! -L $BIN ]] || { echo '同名可执行文件已存在，拒绝覆盖。' >&2; exit 1; }
fi
for path in "$ROOT/generations" "$ROOT/cores" "$ROOT/acme" "$LIB"; do
  [[ ! -L $path ]] || { echo '管理目录不允许符号链接。' >&2; exit 1; }
done
if [[ -e $LIB ]]; then
  [[ -f $LIB/.qingnode-owner && $(cat "$LIB/.qingnode-owner") == "$OWNER" ]] || { echo '管理器辅助目录已有其他内容，拒绝接管。' >&2; exit 1; }
fi
}
check_owned_paths
LOG=$(mktemp /var/log/qingnode-install-XXXXXXXX.log)
chmod 600 "$LOG"
TEMP_DIR=$(mktemp -d)
old_active=0 old_bin=0 old_unit=0 changed=0 root_existed=0 created_user=0 lib_existed=0 retained_account=0
NEW_BIN='' NEW_UNIT='' REDACTOR=''
finish() {
  rc=$?
  trap - EXIT
  set +e
  exec 8>&-
  if ((rc != 0 && changed)); then
    echo '[ERROR] 安装未完成，恢复原管理器与服务。' >&2
    if ((old_bin)); then install -m 755 "$TEMP_DIR/old-bin" "$BIN.recover" && mv -f "$BIN.recover" "$BIN"; else rm -f "$BIN"; fi
    if ((old_unit)); then install -m 644 "$TEMP_DIR/old-unit" "$UNIT"; else systemctl disable --now qingnode.service >>"$LOG" 2>&1; rm -f "$UNIT"; fi
    if [[ -f $TEMP_DIR/old-installer ]]; then install -m 755 "$TEMP_DIR/old-installer" "$LIB/install.sh"; elif ((!lib_existed)); then rm -rf -- "$LIB"; fi
    systemctl daemon-reload >>"$LOG" 2>&1
    if ((old_active)); then systemctl restart qingnode.service >>"$LOG" 2>&1; fi
    if ((!root_existed)); then
      if ((created_user)); then userdel qingnode >>"$LOG" 2>&1; fi
      if ((!created_user)) || ! getent passwd qingnode >/dev/null; then rm -rf -- "$ROOT"; else echo '[WARN] 专用账户未能清理，保留有标记的状态目录供重试。' >&2; fi
    fi
  fi
  if ((rc != 0)); then
    echo "[ERROR] 安装失败，日志：$LOG" >&2
    if [[ -n $REDACTOR && -x $REDACTOR ]]; then tail -n 40 "$LOG" | "$REDACTOR" redact-log >&2; else tail -n 40 "$LOG" >&2; fi
  elif ((DEBUG)); then echo "[DEBUG] 安装日志：$LOG"; fi
  [[ -z $NEW_BIN ]] || rm -f -- "$NEW_BIN"
  [[ -z $NEW_UNIT ]] || rm -f -- "$NEW_UNIT"
  rm -rf -- "$TEMP_DIR"
  exit "$rc"
}
trap finish EXIT
logged() {
  if [[ -n $REDACTOR ]]; then "$@" 2>&1 | "$REDACTOR" redact-log >>"$LOG"; else "$@" >>"$LOG" 2>&1; fi
}
download_release() {
  local rc hint
  if logged curl -sS --proto '=https' --proto-redir '=https' -fL --retry 3 --connect-timeout 15 --max-time "$3" "$1" -o "$2"; then
    return 0
  else
    rc=$?
  fi
  case "$rc" in
    6) hint='DNS 解析失败：检查 github.com 的解析和服务器 DNS';;
    7) hint='无法连接下载服务器：检查出站 HTTPS 网络';;
    18) hint='下载内容不完整：检查网络稳定性后重试';;
    22) hint='HTTP 请求失败：查看日志中的状态码，确认该版本已发布';;
    23) hint='无法写入下载文件：检查磁盘空间及临时目录权限';;
    28) hint='下载超时：检查网络后重试，或使用完整本地发行包';;
    35|51|60) hint='TLS 或证书验证失败：检查系统时间、CA 证书与网络';;
    *) hint="下载失败（curl 退出码 $rc）：查看安装日志";;
  esac
  printf '[ERROR] %s。也可上传已校验的完整发行包运行 install.sh。\n' "$hint" >&2
  return "$rc"
}
step 2 "检测并安装基础依赖"
missing=0
for tool in curl wget jq openssl tar unzip sha256sum flock getent useradd ss; do command -v "$tool" >/dev/null || missing=1; done
if ((missing)); then
  logged apt-get update -qq
  logged env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ca-certificates curl wget jq openssl tar unzip coreutils util-linux passwd iproute2
fi
exec 9>/run/lock/qingnode-bootstrap.lock
flock -n 9 || { echo '另一个安装操作正在进行。' >&2; exit 1; }
check_owned_paths
[[ ! -d $ROOT ]] || root_existed=1
[[ ! -d $LIB ]] || lib_existed=1
systemctl is-active --quiet qingnode.service && old_active=1
if [[ -f $BIN ]]; then cp -p "$BIN" "$TEMP_DIR/old-bin"; old_bin=1; fi
if [[ -f $UNIT ]]; then cp -p "$UNIT" "$TEMP_DIR/old-unit"; old_unit=1; fi
if [[ -f $LIB/install.sh ]]; then cp -p "$LIB/install.sh" "$TEMP_DIR/old-installer"; fi
printf '[INFO] %s %s / %s；该系统的实机验收情况见 TEST_REPORT.md。\n' "$QN_OS_ID" "$QN_OS_VERSION_ID" "$ARCH"
if command -v sing-box >/dev/null; then echo '[INFO] 检测到已有 sing-box；本项目使用自己的目录，不接管其他安装。'; fi
if ! getent ahosts github.com >"$TEMP_DIR/dns"; then echo '[WARN] GitHub DNS 查询失败；在线下载可能失败，可使用完整本地包和 --core-archive。' >&2; fi
ss -H -lntup >>"$LOG" 2>&1 || true
step 3 "校验管理器发行包"
# A standalone download or Bash process substitution has no adjacent bundle.
# A partial local bundle must fail validation, never silently switch sources.
if [[ -z $REPO && ! -e $BUNDLE/qingnode && ! -L $BUNDLE/qingnode && ! -e $BUNDLE/SHA256SUMS && ! -L $BUNDLE/SHA256SUMS ]]; then
  REPO=$DEFAULT_REPO
fi
if [[ -n $REPO ]]; then
  [[ $REPO =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9_.-]+$ && ${REPO##*/} != . && ${REPO##*/} != .. ]] || { echo '仓库名无效，格式应为 owner/repo。' >&2; exit 1; }
  [[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo '管理器版本号无效，格式应为 v数字.数字.数字。' >&2; exit 1; }
  asset="qingnode-${VERSION#v}-linux-$ARCH.tar.gz"
  base="https://github.com/$REPO/releases/download/$VERSION"
  printf '[INFO] 下载 QingNode %s（%s，%s）\n' "$VERSION" "$ARCH" "$REPO"
  download_release "$base/$asset" "$TEMP_DIR/$asset" 300
  download_release "$base/SHA256SUMS" "$TEMP_DIR/release-sums" 60
  expected=$(awk -v f="$asset" '$2==f {print $1}' "$TEMP_DIR/release-sums")
  [[ $expected =~ ^[a-fA-F0-9]{64}$ ]] || { echo '缺少唯一的发行包摘要。' >&2; exit 1; }
  actual=$(sha256sum "$TEMP_DIR/$asset"); actual=${actual%% *}
  [[ $actual == "${expected,,}" ]] || { echo '发行包摘要不匹配。' >&2; exit 1; }
  tar -tzf "$TEMP_DIR/$asset" > "$TEMP_DIR/members"
  if grep -Ev '^(qingnode|install.sh|SHA256SUMS|README.md|LICENSE|THIRD_PARTY.md|docs/?|docs/(ARCHITECTURE|TEST_REPORT|RELEASE_NOTES|AUDIT_STAGE2).md)$' "$TEMP_DIR/members" >/dev/null; then echo '发行包包含未知路径。' >&2; exit 1; fi
  tar -tvzf "$TEMP_DIR/$asset" | awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" {bad=1} END {exit bad}' || { echo '发行包包含不允许的链接或特殊文件。' >&2; exit 1; }
  mkdir "$TEMP_DIR/bundle"
  tar --no-same-owner --no-same-permissions -xzf "$TEMP_DIR/$asset" -C "$TEMP_DIR/bundle"
  BUNDLE=$TEMP_DIR/bundle
fi
[[ -f $BUNDLE/qingnode && ! -L $BUNDLE/qingnode && -f $BUNDLE/SHA256SUMS ]] || { echo '请在本架构发行包中运行安装器，或指定已发布的 --repo 与 --version。' >&2; exit 1; }
awk 'NF!=2 || length($1)!=64 || $1 !~ /^[a-fA-F0-9]+$/ {bad=1}
  $2 !~ /^(qingnode|install.sh|README.md|LICENSE|THIRD_PARTY.md|docs\/(ARCHITECTURE|TEST_REPORT|RELEASE_NOTES|AUDIT_STAGE2).md)$/ {bad=1}
  {if (seen[$2]++) bad=1} END {exit bad || !seen["qingnode"] || !seen["install.sh"]}' "$BUNDLE/SHA256SUMS" || { echo '摘要清单无效或缺少必要文件。' >&2; exit 1; }
while read -r _ member; do [[ -f $BUNDLE/$member && ! -L $BUNDLE/$member ]] || { echo '发行包成员必须是普通文件。' >&2; exit 1; }; done < "$BUNDLE/SHA256SUMS"
[[ ! -L $BUNDLE/docs ]] || { echo '发行包文档目录不允许链接。' >&2; exit 1; }
(cd "$BUNDLE" && sha256sum --strict -c SHA256SUMS) >>"$LOG" 2>&1
REDACTOR=$BUNDLE/qingnode
if [[ -f $ROOT/uninstall.json ]]; then
  logged "$BUNDLE/qingnode" recover
  systemctl is-active --quiet qingnode.service && old_active=1
  if [[ -f $BIN ]]; then cp -p "$BIN" "$TEMP_DIR/old-bin"; old_bin=1; fi
  if [[ -f $UNIT ]]; then cp -p "$UNIT" "$TEMP_DIR/old-unit"; old_unit=1; fi
  if [[ -f $LIB/install.sh ]]; then cp -p "$LIB/install.sh" "$TEMP_DIR/old-installer"; lib_existed=1; fi
fi
if [[ -f $ROOT/current/state.json ]]; then "$BUNDLE/qingnode" validate-state --file "$ROOT/current/state.json"; fi
step 4 "准备独立账户与配置目录"
if ((!root_existed)) && getent passwd qingnode >/dev/null; then
  [[ -f $ACCOUNT_RECORD && ! -L $ACCOUNT_RECORD && $(stat -c '%u:%a' "$ACCOUNT_RECORD") == 0:600 ]] || { echo '已有同名用户，拒绝自动接管。' >&2; exit 1; }
  { printf 'QingNode retained account v1\n'; getent passwd qingnode; getent group qingnode; } > "$TEMP_DIR/account"
  cmp -s "$ACCOUNT_RECORD" "$TEMP_DIR/account" || { echo '保留账户的身份已变化，拒绝自动接管。' >&2; exit 1; }
  retained_account=1
fi
changed=1
if ((!root_existed)); then
  install -d -m 700 "$ROOT"
  printf '%s\n' "$OWNER" > "$ROOT/.qingnode-owner"
fi
if ! getent passwd qingnode >/dev/null; then
  getent group qingnode >/dev/null && { echo '已有同名组，拒绝自动接管。' >&2; exit 1; }
  useradd --system --user-group --home-dir "$ROOT/acme" --no-create-home --shell /usr/sbin/nologin qingnode
  created_user=1
elif ((!root_existed && !retained_account)); then
  echo '已有同名用户，拒绝自动接管。' >&2; exit 1
fi
install -d -m 750 -o root -g qingnode "$ROOT" "$ROOT/generations" "$ROOT/cores"
if [[ ! -f $ROOT/.qingnode-owner ]]; then printf '%s\n' "$OWNER" > "$ROOT/.qingnode-owner"; fi
install -d -m 750 -o qingnode -g qingnode "$ROOT/acme"
step 5 "安装管理器与 systemd 服务"
[[ ! -L $ROOT/.lock ]] || { echo '状态锁不允许符号链接。' >&2; exit 1; }
exec 8>"$ROOT/.lock"
flock -n 8 || { changed=0; echo '另一个节点管理操作正在运行，请稍后重试。' >&2; exit 1; }
if [[ -f $ROOT/current/state.json ]]; then "$BUNDLE/qingnode" validate-state --file "$ROOT/current/state.json"; fi
NEW_BIN=$(mktemp "$BIN.new.XXXXXXXX")
install -m 755 "$BUNDLE/qingnode" "$NEW_BIN"
mv -f "$NEW_BIN" "$BIN"
"$BIN" service unit > "$TEMP_DIR/qingnode.service"
NEW_UNIT=$(mktemp "$UNIT.new.XXXXXXXX")
install -m 644 "$TEMP_DIR/qingnode.service" "$NEW_UNIT"
mv -f "$NEW_UNIT" "$UNIT"
install -d -m 755 "$LIB"
printf '%s\n' "$OWNER" > "$LIB/.qingnode-owner"
install -m 755 "$BUNDLE/install.sh" "$LIB/install.sh"
logged systemctl daemon-reload
exec 8>&-
step 6 "安装或校验官方 sing-box"
if [[ -e $ROOT/current ]]; then
  if [[ -n $CORE_ARCHIVE ]]; then logged "$BIN" core install --archive "$CORE_ARCHIVE"; else logged "$BIN" core install; fi
  step 7 "校验已有配置并保持运行状态"
  logged "$BIN" check
  if ((old_active)); then logged "$BIN" restart; fi
  echo '管理程序已更新，原节点及运行/停止状态已保留。'
else
  if [[ -n $CORE_ARCHIVE ]]; then logged "$BIN" core install --archive "$CORE_ARCHIVE"; else logged "$BIN" core install; fi
  step 7 "创建首个节点并校验配置"
  if [[ -n $WIZARD_PROTOCOL ]]; then
    "$BIN" wizard --protocol "$WIZARD_PROTOCOL" --quiet 2> >(tee -a "$LOG" >&2)
  else
    "$BIN" init "${INIT_ARGS[@]}" --quiet 2> >(tee -a "$LOG" >&2)
  fi
  logged systemctl enable qingnode.service
fi
changed=0
step 8 "安装完成，以下为客户端连接信息"
"$BIN" info --show-secrets
echo '安装完成。运行 qingnode 打开菜单；对应节点的链接和导出命令见上方。'
echo '请在已启用的防火墙和云安全组放行上方实际监听端口及协议，再用客户端验证；故障时运行 qingnode diagnose。'
