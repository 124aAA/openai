#!/usr/bin/env bash
# QingNode bootstrap. No remote shell fragments are evaluated.
set -Eeuo pipefail
umask 077

ROOT=/var/lib/qingnode
BIN=/usr/local/bin/qingnode
UNIT=/etc/systemd/system/qingnode.service
QN_INIT=systemd QN_PACKAGE_MANAGER=apt UNIT_MODE=644
ROTATION=/etc/logrotate.d/qingnode
OWNER='QingNode managed directory v1'
BUNDLE=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEFAULT_REPO=124aAA/openai
REPO='' VERSION=v0.3.0 PORT=443 CONNECT_PORT='' CONNECT_PORT_SET=0 CORE_ARCHIVE='' DEBUG=0 REINSTALL=0 HAS_ARGS=$#
VERSION_EXPLICIT=0
INIT_ARGS=()
QN_RECOVERING=0
WIZARD_PROTOCOL=''
LIB=/usr/local/lib/qingnode
ACCOUNT_RECORD=/var/backups/qingnode/.qingnode-account
step() { printf '[%s/8] %s\n' "$1" "$2"; }
while (($#)); do
  case "$1" in
    --repo|--version|--server|--sni|--port|--connect-port|--core-archive|--name|--protocol|--listen|--target|--fingerprint|--cert|--key|--acme-email|--user|--certificate-id|--method)
      (($# >= 2)) || { echo '参数缺少值' >&2; exit 2; }
      case "$1" in
        --repo) REPO=$2;; --version) VERSION=$2; VERSION_EXPLICIT=1;;
        --port) PORT=$2;; --connect-port) CONNECT_PORT=$2; CONNECT_PORT_SET=1;; --core-archive) CORE_ARCHIVE=$2;;
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
      echo 'NAT：--listen 本地IP --port 本地端口 --connect-port 外部端口；仅声明，不修改云NAT。'
      echo '在线安装：sudo bash install.sh（自动从 124aAA/openai 下载已校验发行包）'
      echo '默认在线入口选择已公开的最新正式发行；完整本地包不联网选择版本。'
      echo '指定版本：sudo bash install.sh --repo 124aAA/openai --version v0.3.0 [初始化参数]'
      echo '可加 --core-archive 官方 sing-box 1.14.0 的本架构 tar.gz，使用内置摘要校验。'
      exit 0;;
    *) echo "未知参数：$1" >&2; exit 2;;
  esac
done
if ((CONNECT_PORT_SET)); then
  if [[ ! $CONNECT_PORT =~ ^[0-9]+$ || ${#CONNECT_PORT} -gt 5 ]] || ((10#$CONNECT_PORT < 1 || 10#$CONNECT_PORT > 65535)); then
    echo '外部连接端口无效。' >&2; exit 2
  fi
fi
[[ $EUID == 0 ]] || { echo '请使用 sudo 或 root 运行。' >&2; exit 1; }
if ((HAS_ARGS==0 && REINSTALL==0)) && [[ -x $BIN && -f $ROOT/.qingnode-owner && $(cat "$ROOT/.qingnode-owner") == "$OWNER" ]]; then exec "$BIN"; fi
if ((${#INIT_ARGS[@]}==0)) && [[ ! -e $ROOT/current ]]; then
  [[ -t 0 ]] || { echo '首次安装需要交互终端选择协议；无人值守请加 --auto，或提供完整初始化参数。' >&2; exit 2; }
  printf '\nQingNode 青节点 — 请选择要搭建的节点\n1. VLESS REALITY / Vision（无需自己的域名，自动筛选伪装目标）\n2. Shadowsocks 2022（无需域名，客户端需支持 SS2022）\n3. Hysteria2（UDP，需要域名及证书）\n4. AnyTLS（TCP监听，需要证书）\n5. Trojan（标准TLS，需要证书）\n6. 传统 SS AEAD（默认AES-256-GCM）\n7. TUIC v5（UDP/QUIC，需要证书）\n0. 退出，不安装\n'
  while :; do
    printf '选择 [1至7，或0]：'
    if ! read -r choice; then echo '已取消，未开始安装。'; exit 0; fi
    case "$choice" in
      1) INIT_ARGS=(--auto --protocol reality); break;;
      2) INIT_ARGS=(--auto --protocol ss2022); break;;
      3) WIZARD_PROTOCOL=hysteria2; break;;
      4) WIZARD_PROTOCOL=anytls; break;;
      5) WIZARD_PROTOCOL=trojan; break;;
      6) INIT_ARGS=(--auto --protocol ss-aead); break;;
      7) WIZARD_PROTOCOL=tuic; break;;
      0) echo '已取消，未开始安装。'; exit 0;;
      *) echo '请输入 1 至 7，或 0；尚未开始安装。';;
    esac
  done
fi
step 1 "检测系统、权限与架构"
[[ -r /etc/os-release ]] || exit 1
# Isolate all os-release assignments: its VERSION must not replace our tag.
QN_OS_INFO=$(
  # os-release is a local root-owned operating-system file.
  # shellcheck source=/dev/null
  . /etc/os-release || exit 1
  printf '%s %s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}"
)
read -r QN_OS_ID QN_OS_VERSION_ID <<< "$QN_OS_INFO"
case "$QN_OS_ID:$QN_OS_VERSION_ID" in
  debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;;
  rocky:9|rocky:9.*) QN_PACKAGE_MANAGER=dnf;;
  alpine:3.24|alpine:3.24.*) QN_INIT=openrc; QN_PACKAGE_MANAGER=apk; UNIT=/etc/init.d/qingnode; UNIT_MODE=755;;
  *) echo "未适配的系统：$QN_OS_ID $QN_OS_VERSION_ID；目标与实际验收分列在平台矩阵。" >&2; exit 1;;
esac
# A command installed in a container is not proof that its init controls PID 1.
QN_PID1=$(cat /proc/1/comm)
if [[ $QN_INIT == systemd ]]; then
  if ! { [[ $QN_PID1 == systemd ]] && command -v systemctl >/dev/null &&
    systemctl show --property=Version --value >/dev/null 2>&1; }; then
      echo 'systemctl 存在不等于 systemd 正在管理此主机；需要可连接的 PID 1 systemd。' >&2; exit 1;
  fi
else
  if ! { [[ $QN_PID1 == init || $QN_PID1 == openrc-init ]] && [[ -f /run/openrc/softlevel ]] &&
    command -v rc-service >/dev/null && command -v rc-update >/dev/null && command -v supervise-daemon >/dev/null &&
    rc-status --runlevel >/dev/null 2>&1; }; then
      echo '需要实际运行的 Alpine OpenRC、有效 runlevel 和 supervise-daemon；普通容器中仅有命令不算可托管服务。' >&2; exit 1;
  fi
fi
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo '仅支持 x86_64 和 ARM64。' >&2; exit 1;; esac
if [[ ! $PORT =~ ^[0-9]+$ || ${#PORT} -gt 5 ]]; then
  echo '端口无效。' >&2; exit 1
fi
PORT=$((10#$PORT))
if ((PORT < 1 || PORT > 65535)); then
  echo '端口无效。' >&2; exit 1
fi
# Keep host-specific operations at the bootstrap boundary. Business changes are
# delegated to the manager's matching service backend.
qn_service() {
  local action=$1
  if [[ $QN_INIT == systemd ]]; then
    case "$action" in
      active) qn_guarded_native systemctl is-active --quiet qingnode.service;;
      enabled) qn_guarded_native systemctl is-enabled --quiet qingnode.service;;
      reload) qn_guarded_native systemctl daemon-reload;;
      *) qn_guarded_native systemctl "$action" qingnode.service;;
    esac
  else
    case "$action" in
      active) qn_guarded_native rc-service qingnode status >/dev/null 2>&1;;
      enabled) [[ -n $(qn_openrc_runlevels) ]];;
      enable) qn_guarded_native rc-update add qingnode default;;
      disable) qn_openrc_disable;;
      reload) return 0;; # OpenRC reads the owned script per action; no reload signal.
      *) qn_guarded_native rc-service qingnode "$action";;
    esac
  fi
}
qn_guarded_native() {
  local result=0
  if ((QN_RECOVERING)); then qn_guard_transaction || { QN_RECOVERY_BLOCKED=1; return 1; }; fi
  "$@" || result=$?
  if ((QN_RECOVERING)); then qn_guard_transaction || { QN_RECOVERY_BLOCKED=1; return 1; }; fi
  return "$result"
}
qn_openrc_runlevels() {
  local levels level
  levels=$(rc-update -q show | awk '$1=="qingnode" {for(i=3;i<=NF;i++) print $i}') || return 1
  while IFS= read -r level; do
    [[ -z $level || $level =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$ ]] || { echo '服务runlevel输出无效，拒绝猜测自启动状态。' >&2; return 1; }
  done <<< "$levels"
  printf '%s' "$levels"
}
qn_openrc_disable() {
  local levels level remaining
  levels=$(qn_openrc_runlevels) || return 1
  [[ -n $levels ]] || return 0
  while IFS= read -r level; do
    [[ -z $level ]] || qn_guarded_native rc-update del qingnode "$level" || return 1
  done <<< "$levels"
  remaining=$(qn_openrc_runlevels) || return 1
  [[ -z $remaining ]] || { echo 'OpenRC自启动项禁用后读回仍存在，未宣称成功。' >&2; return 1; }
}
qn_snapshot_service() {
  local properties key value load='' active='' enabled='' fragment='' rc=0
  local load_seen=0 active_seen=0 enabled_seen=0 fragment_seen=0
  old_active=0 old_enabled=0 old_runlevels=''
  if [[ $QN_INIT == openrc ]]; then
    if [[ -e $UNIT || -L $UNIT ]]; then
      properties=$(rc-service qingnode status 2>&1) || rc=$?
      if ((rc==0)) && [[ $properties == *'status: started'* ]]; then old_active=1
      elif ((rc!=0)) && [[ $properties == *'status: stopped'* ]]; then old_active=0
      else echo 'OpenRC服务状态未知或正在转换，未保存虚假的停止状态。' >&2; return 1; fi
    fi
    old_runlevels=$(qn_openrc_runlevels) || return 1
    [[ -z $old_runlevels ]] || old_enabled=1
  else
    properties=$(systemctl show qingnode.service --no-pager --property=LoadState,ActiveState,UnitFileState,FragmentPath) || rc=$?
    while IFS='=' read -r key value; do
      case "$key" in
        LoadState) ((load_seen==0)) || return 1; load=$value; load_seen=1;;
        ActiveState) ((active_seen==0)) || return 1; active=$value; active_seen=1;;
        UnitFileState) ((enabled_seen==0)) || return 1; enabled=$value; enabled_seen=1;;
        FragmentPath) ((fragment_seen==0)) || return 1; fragment=$value; fragment_seen=1;;
        *) echo '服务状态查询不完整，未保存虚假的停止或禁用状态。' >&2; return 1;;
      esac
    done <<< "$properties"
    if ((load_seen!=1 || active_seen!=1 || enabled_seen!=1 || fragment_seen!=1)); then
      echo '服务状态缺少必要字段，未开始安装变更。' >&2; return 1
    fi
    if [[ $load == not-found && ! -e $UNIT && ! -L $UNIT && -z $fragment && $active == inactive && ( -z $enabled || $enabled == disabled ) ]]; then
      return 0 # Proven absent definition on a fresh installation, not a bus error.
    fi
    if ((rc!=0)) || [[ $load != loaded || $fragment != "$UNIT" ]]; then
      echo '无法确认本项目服务的已加载状态和来源，未开始安装变更。' >&2; return 1
    fi
    case "$active" in active) old_active=1;; inactive|failed) old_active=0;;
      *) echo '服务正在转换或状态未知，稍后重试；未把未知当作停止。' >&2; return 1;; esac
    case "$enabled" in enabled) old_enabled=1;; disabled) old_enabled=0;;
      *) echo '自启动状态不能无损映射为启用/禁用，保留原设置并停止安装。' >&2; return 1;; esac
  fi
  return 0
}
qn_restore_boot() {
  local level
  if [[ $QN_INIT == systemd ]]; then
    if ((old_enabled)); then qn_service enable; else qn_service disable; fi
  else
    qn_service disable || return 1
    while IFS= read -r level; do
      [[ -z $level ]] || qn_guarded_native rc-update add qingnode "$level" || return 1
    done <<< "$old_runlevels"
  fi
}
qn_remove_service() {
  qn_service stop || return
  qn_service disable
}
qn_remove_account() {
  if [[ $QN_PACKAGE_MANAGER == apk ]]; then deluser qingnode; else userdel qingnode; fi
}
qn_create_account() {
  if [[ $QN_PACKAGE_MANAGER == apk ]]; then
    addgroup -S qingnode
    if ! adduser -S -D -H -h "$ROOT/acme" -s /sbin/nologin -G qingnode qingnode; then
      delgroup qingnode
      return 1
    fi
  else
    useradd --system --user-group --home-dir "$ROOT/acme" --no-create-home --shell /usr/sbin/nologin qingnode
  fi
}
qn_dependencies() {
  local pair tool package
  local -a packages=() tools=(curl openssl tar gzip sha256sum flock getent ss)
  local -a pairs=(curl:curl openssl:openssl tar:tar gzip:gzip sha256sum:coreutils flock:util-linux)
  case "$QN_PACKAGE_MANAGER" in
    apt) pairs+=(getent:libc-bin ss:iproute2 useradd:passwd userdel:passwd); tools+=(useradd userdel);;
    dnf) pairs+=(getent:glibc-common ss:iproute useradd:shadow-utils userdel:shadow-utils restorecon:policycoreutils getenforce:libselinux-utils); tools+=(useradd userdel restorecon getenforce);;
    apk) pairs+=(getent:musl-utils ss:iproute2 adduser:busybox addgroup:busybox deluser:busybox delgroup:busybox setcap:libcap-utils getcap:libcap-utils logrotate:logrotate); tools+=(adduser addgroup deluser delgroup setcap getcap logrotate)
      # Official pinned Linux builds have a glibc loader. musl alone is not
      # assumed compatible: install the limited ABI bridge and test execution.
      # coreutils/tar are required for strict checksum and archive flags;
      # BusyBox command presence alone is insufficient for those semantics.
      for package in gcompat libgcc libstdc++ coreutils tar gzip; do
        apk info -e "$package" >/dev/null 2>&1 || packages+=("$package")
      done;;
  esac
  for pair in "${pairs[@]}"; do
    tool=${pair%%:*}; package=${pair#*:}
    command -v "$tool" >/dev/null || packages+=("$package")
  done
  [[ -s /etc/ssl/certs/ca-certificates.crt || -s /etc/pki/tls/certs/ca-bundle.crt ]] || packages+=(ca-certificates)
  ((${#packages[@]})) || return 0
  case "$QN_PACKAGE_MANAGER" in
    apt)
      logged apt-get -o DPkg::Lock::Timeout=30 -o Acquire::Retries=2 -o Acquire::http::Timeout=30 update -qq &&
      logged env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=30 install -y -qq --no-install-recommends "${packages[@]}";;
    dnf) logged dnf -y --setopt=exit_on_lock=True --setopt=timeout=30 --setopt=retries=2 --setopt=install_weak_deps=False install "${packages[@]}";;
    apk) logged apk --wait 30 add --no-cache "${packages[@]}";;
  esac || { echo '依赖安装失败：检查软件仓库、包管理锁和出站网络；没有执行系统升级。' >&2; return 1; }
  for tool in "${tools[@]}"; do command -v "$tool" >/dev/null || { echo "安装后仍缺少依赖：$tool" >&2; return 1; }; done
}
qn_manager_permissions() {
  # The manager never binds a proxy port. Only the verified sing-box executable
  # receives the low-port file capability inside InstallCore's staged commit.
  if [[ $QN_PACKAGE_MANAGER == dnf ]]; then
    # Restore the distribution's labels only. No permissive mode, guessed policy,
    # broad relabel, or automatic change to the global firewall is performed.
    logged restorecon "$BIN" "$UNIT" "$LIB/install.sh"
    if [[ $(getenforce) == Enforcing ]]; then
      echo '[INFO] SELinux enforcing 保持启用；实际服务检查失败会回滚，请按 AVC 证据处理所需最小策略。'
    fi
  fi
}
qn_log_rotation() {
  [[ $QN_INIT == openrc ]] || return 0
  install -d -m 755 /etc/logrotate.d
  cat > "$TEMP_DIR/logrotate" <<'QINGNODE_LOGROTATE'
# Managed by QingNode
/var/log/qingnode/qingnode.log /var/log/qingnode/qingnode-subscription.log /var/log/qingnode/qingnode-monitor.log {
    size 1M
    rotate 3
    missingok
    notifempty
    copytruncate
}
QINGNODE_LOGROTATE
  NEW_ROTATION=$(mktemp "$ROTATION.new.XXXXXXXX")
  install -m 644 "$TEMP_DIR/logrotate" "$NEW_ROTATION"
  qn_guard_transaction
  mv -f "$NEW_ROTATION" "$ROTATION"
  QN_ROTATION_COMMITTED=1
  qn_guard_transaction
  echo '[INFO] OpenRC日志保留3份、每份约1MiB；依赖宿主已有logrotate调度，未开启或改动全局cron。copytruncate有并发写入缺口，日志不作计费依据。'
}
check_owned_paths() {
if [[ -e $ROOT || -L $ROOT ]]; then
  [[ -d $ROOT && ! -L $ROOT && -f $ROOT/.qingnode-owner && $(cat "$ROOT/.qingnode-owner") == "$OWNER" ]] || { echo '状态目录已有其他内容，拒绝接管。' >&2; exit 1; }
fi
if [[ $QN_INIT == openrc && ( -e $ROTATION || -L $ROTATION ) ]]; then
  [[ -f $ROTATION && ! -L $ROTATION && $(head -n 1 "$ROTATION") == '# Managed by QingNode' ]] || { echo '同名日志轮换文件不属于 QingNode。' >&2; exit 1; }
fi
if [[ -e $UNIT || -L $UNIT ]]; then
  if ! { [[ -f $UNIT && ! -L $UNIT ]] &&
    { [[ $QN_INIT == systemd && $(head -n 1 "$UNIT") == '# Managed by QingNode' ]] ||
      [[ $QN_INIT == openrc && $(head -n 1 "$UNIT") == '#!/sbin/openrc-run' && $(sed -n '2p' "$UNIT") == '# Managed by QingNode' ]]; }; }; then
    echo '同名服务不属于 QingNode。' >&2; exit 1;
  fi
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
# A marker is only an admission check. Before a verified candidate may replace
# an installed definition, compare its complete local rendering and loaded
# source. Administrator overrides remain administrator-owned, even with a marker.
qn_check_service_definition() {
  local metadata properties key value fragment='' dropins='' fragment_seen=0 dropins_seen=0
  if [[ -e $UNIT || -L $UNIT ]]; then
    [[ -f $UNIT && ! -L $UNIT ]] || { echo '服务定义不是普通文件，拒绝覆盖。' >&2; return 1; }
    metadata=$(stat -c '%u:%h:%a' -- "$UNIT") || return 1
    [[ $metadata == "0:1:$UNIT_MODE" ]] || { echo '服务定义属主、链接数或权限已变化，拒绝覆盖。' >&2; return 1; }
    cmp -s "$UNIT" "$TEMP_DIR/qingnode.service" || { echo '服务定义已由外部修改，拒绝覆盖；请保留并审查原文件。' >&2; return 1; }
  fi
  if [[ $QN_INIT == openrc ]]; then
    if [[ -e /etc/conf.d/qingnode || -L /etc/conf.d/qingnode ]]; then
      echo '存在外部 OpenRC conf.d 覆盖，拒绝接管。' >&2; return 1
    fi
  else
    if [[ -e $UNIT.d || -L $UNIT.d ]]; then
      echo '存在外部 systemd drop-in，拒绝接管。' >&2; return 1
    fi
    properties=$(systemctl show qingnode.service --no-pager --property=FragmentPath,DropInPaths) || return 1
    while IFS='=' read -r key value; do
      case "$key" in
        FragmentPath) ((fragment_seen==0)) || return 1; fragment=$value; fragment_seen=1;;
        DropInPaths) ((dropins_seen==0)) || return 1; dropins=$value; dropins_seen=1;;
        *) echo '无法核对服务加载来源，拒绝覆盖。' >&2; return 1;;
      esac
    done <<< "$properties"
    if ((fragment_seen!=1 || dropins_seen!=1)) || [[ -n $dropins || ( -n $fragment && $fragment != "$UNIT" ) ]]; then
      echo '服务加载来源或附加配置不属于 QingNode，拒绝接管。' >&2; return 1
    fi
  fi
}
# Compare the original and this install's private candidate, not a marker alone.
# Native service/core operations can wait while an administrator edits files.
# Checks cannot make a final check + rename atomic against another root writer.
qn_guard_file() {
  local path=$1 old=$2 candidate=$3 mode=$4 required=$5 metadata expected
  if [[ ! -e $path && ! -L $path ]]; then
    [[ ! -f $old && $required == 0 ]] || { echo '原受管文件或本轮已写文件已被外部移除，未覆盖。' >&2; return 1; }
    return 0
  fi
  [[ -f $path && ! -L $path ]] || { echo '受管文件变成链接或非普通文件，未覆盖。' >&2; return 1; }
  metadata=$(stat -c '%u:%g:%h:%a' -- "$path") || return 1
  if [[ -f $old ]]; then
    expected=$(stat -c '%u:%g:1:%a' -- "$old") || return 1
    if [[ $metadata == "$expected" && $metadata == 0:* ]] && cmp -s "$path" "$old"; then return 0; fi
  fi
  expected="0:$(id -g):1:$mode"
  if [[ $required == 1 && -f $candidate && $metadata == "$expected" ]] && cmp -s "$path" "$candidate"; then return 0; fi
  echo '受管文件的字节、属主、链接数或权限已由外部修改，保留外部内容。' >&2
  return 1
}
qn_guard_transaction() {
  ((QN_GUARD_READY)) || return 0
  ((QN_RECOVERY_BLOCKED==0)) || return 1
  local path properties key value fragment='' dropins='' seen_fragment=0 seen_dropins=0
  for path in "$ROOT" "$ROOT/generations" "$ROOT/cores" "$ROOT/acme" "$LIB"; do
    [[ ! -L $path ]] || { echo '受管目录已变成外部链接，停止恢复。' >&2; return 1; }
  done
  qn_guard_file "$BIN" "$TEMP_DIR/old-bin" "$TEMP_DIR/candidate-bin" 755 "$QN_BIN_COMMITTED" || return 1
  qn_guard_file "$UNIT" "$TEMP_DIR/old-unit" "$TEMP_DIR/qingnode.service" "$UNIT_MODE" "$QN_UNIT_COMMITTED" || return 1
  qn_guard_file "$LIB/install.sh" "$TEMP_DIR/old-installer" "$TEMP_DIR/candidate-installer" 755 "$QN_INSTALLER_COMMITTED" || return 1
  if [[ $QN_INIT == openrc ]]; then
    qn_guard_file "$ROTATION" "$TEMP_DIR/old-rotation" "$TEMP_DIR/logrotate" 644 "$QN_ROTATION_COMMITTED" || return 1
    [[ ! -e /etc/conf.d/qingnode && ! -L /etc/conf.d/qingnode ]] || { echo '出现外部OpenRC conf.d覆盖，停止恢复。' >&2; return 1; }
  else
    [[ ! -e $UNIT.d && ! -L $UNIT.d ]] || { echo '出现外部systemd drop-in，停止恢复。' >&2; return 1; }
    properties=$(systemctl show qingnode.service --no-pager --property=FragmentPath,DropInPaths) || return 1
    while IFS='=' read -r key value; do
      case "$key" in
        FragmentPath) ((seen_fragment==0)) || return 1; fragment=$value; seen_fragment=1;;
        DropInPaths) ((seen_dropins==0)) || return 1; dropins=$value; seen_dropins=1;;
        *) return 1;;
      esac
    done <<< "$properties"
    ((seen_fragment==1 && seen_dropins==1)) && [[ -z $dropins && ( -z $fragment || $fragment == "$UNIT" ) ]] || {
      echo '服务加载来源已由外部修改，停止恢复。' >&2; return 1;
    }
  fi
}
qn_remove_new_lib() {
  [[ ! -e $LIB && ! -L $LIB ]] && return 0
  [[ -d $LIB && ! -L $LIB && -f $LIB/.qingnode-owner && ! -L $LIB/.qingnode-owner && $(cat "$LIB/.qingnode-owner") == "$OWNER" ]] || return 1
  rm -f -- "$LIB/install.sh" "$LIB/.qingnode-owner" || return 1
  QN_INSTALLER_COMMITTED=0
  rmdir -- "$LIB"
}
qn_remove_new_file() {
  rm -f -- "$1" || return 1
  case "$1" in
    "$BIN") QN_BIN_COMMITTED=0;; "$UNIT") QN_UNIT_COMMITTED=0;; "$ROTATION") QN_ROTATION_COMMITTED=0;;
    *) return 1;;
  esac
}
qn_restore_binary() {
  [[ ! -e $BIN.recover && ! -L $BIN.recover ]] || { echo '恢复暂存路径已有内容，未覆盖。' >&2; return 1; }
  install -m "$(stat -c '%a' "$TEMP_DIR/old-bin")" -g "$(stat -c '%g' "$TEMP_DIR/old-bin")" "$TEMP_DIR/old-bin" "$BIN.recover"
}
qn_commit_restored_binary() {
  qn_guard_file "$BIN.recover" "$TEMP_DIR/old-bin" "$TEMP_DIR/old-bin" "$(stat -c '%a' "$TEMP_DIR/old-bin")" 1 || return 1
  mv -f "$BIN.recover" "$BIN"
}
check_owned_paths
TEMP_DIR=$(mktemp -d)
LOG=$TEMP_DIR/preflight.log
: > "$LOG"
old_active=0 old_enabled=0 old_runlevels='' old_bin=0 old_unit=0 old_rotation=0 changed=0 root_existed=0 created_user=0 lib_existed=0 retained_account=0
NEW_BIN='' NEW_UNIT='' NEW_ROTATION='' REDACTOR=''
QN_GUARD_READY=0 QN_RECOVERY_BLOCKED=0
QN_BIN_COMMITTED=0 QN_UNIT_COMMITTED=0 QN_INSTALLER_COMMITTED=0 QN_ROTATION_COMMITTED=0
finish() {
  rc=$?
  recovery_failed=0
  trap - EXIT
  set +e
  exec 8>&-
  recover_step() {
    local label=$1
    shift
    ((QN_RECOVERY_BLOCKED==0)) || return 1
    if ! qn_guard_transaction >>"$LOG" 2>&1; then
      QN_RECOVERY_BLOCKED=1 recovery_failed=1
      echo '[ERROR] 恢复前发现外部变更；保留外部内容与私有原件，停止后续服务控制。' >&2
      return 1
    fi
    local result=0
    "$@" >>"$LOG" 2>&1 || result=$?
    if ! qn_guard_transaction >>"$LOG" 2>&1; then
      QN_RECOVERY_BLOCKED=1 recovery_failed=1
      echo '[ERROR] 恢复等待期间发现外部变更；保留外部内容与私有原件，停止后续服务控制。' >&2
      return 1
    fi
    ((result==0)) && return 0
    recovery_failed=1
    printf '[ERROR] 恢复未完成：%s；详情见安装日志。\n' "$label" >&2
    return 1
  }
  if ((rc != 0 && changed)); then
    QN_RECOVERING=1
    echo '[ERROR] 安装未完成，正在恢复原管理器与服务。' >&2
    if ((old_bin)); then
      recover_step '管理器二进制' qn_restore_binary &&
        recover_step '替换原管理器' qn_commit_restored_binary
    else recover_step '清理新增管理器' qn_remove_new_file "$BIN"; fi
    if ((old_unit)); then recover_step '服务文件' install -m "$(stat -c '%a' "$TEMP_DIR/old-unit")" -g "$(stat -c '%g' "$TEMP_DIR/old-unit")" "$TEMP_DIR/old-unit" "$UNIT"
    else
      if [[ -f $UNIT ]]; then recover_step '停止并禁用新增服务' qn_remove_service; fi
      recover_step '清理新增服务文件' qn_remove_new_file "$UNIT"
    fi
    if [[ -f $TEMP_DIR/old-installer ]]; then recover_step '安装辅助脚本' install -m "$(stat -c '%a' "$TEMP_DIR/old-installer")" -g "$(stat -c '%g' "$TEMP_DIR/old-installer")" "$TEMP_DIR/old-installer" "$LIB/install.sh"
    elif ((!lib_existed)); then recover_step '清理新增辅助目录' qn_remove_new_lib; fi
    if [[ $QN_INIT == openrc ]]; then
      if ((old_rotation)); then recover_step '日志轮换文件' install -m "$(stat -c '%a' "$TEMP_DIR/old-rotation")" -g "$(stat -c '%g' "$TEMP_DIR/old-rotation")" "$TEMP_DIR/old-rotation" "$ROTATION"
      else recover_step '清理新增日志轮换文件' qn_remove_new_file "$ROTATION"; fi
    fi
    recover_step '重新加载服务定义' qn_service reload
    if ((old_unit)); then
      recover_step '恢复原服务自启动状态' qn_restore_boot
      if ((old_active)); then recover_step '恢复原服务运行状态' qn_service restart
      else recover_step '保持原服务停止状态' qn_service stop; fi
    fi
    if ((!root_existed && !QN_RECOVERY_BLOCKED)); then
      if ((created_user)); then recover_step '清理新增专用账户' qn_remove_account; fi
      if ((!created_user)) || ! getent passwd qingnode >/dev/null; then recover_step '清理新增状态目录' rm -rf -- "$ROOT"
      else echo '[WARN] 专用账户未能清理，保留有标记的状态目录供重试。' >&2; fi
    fi
  fi
  if ((rc != 0)); then
    if [[ $LOG == "$TEMP_DIR/preflight.log" ]]; then echo '[ERROR] 安装预检失败，尚未安装依赖或修改受管服务。' >&2
    else echo "[ERROR] 安装失败，日志：$LOG" >&2; fi
    if [[ -n $REDACTOR && -x $REDACTOR ]]; then tail -n 40 "$LOG" | "$REDACTOR" redact-log >&2; else tail -n 40 "$LOG" >&2; fi
  elif ((DEBUG)); then echo "[DEBUG] 安装日志：$LOG"; fi
  [[ -z $NEW_BIN ]] || rm -f -- "$NEW_BIN"
  [[ -z $NEW_UNIT ]] || rm -f -- "$NEW_UNIT"
  [[ -z $NEW_ROTATION ]] || rm -f -- "$NEW_ROTATION"
  if ((recovery_failed)); then
    printf '[ERROR] 保留恢复文件：%s（目录仅 root 可读）。先排除恢复错误，再恢复原文件；请保留此目录和安装日志。\n' "$TEMP_DIR" >&2
    if [[ -f $TEMP_DIR/old-bin ]]; then printf '[INFO] 原管理器恢复命令：install -m 755 %q %q\n' "$TEMP_DIR/old-bin" "$BIN" >&2; fi
    if [[ -f $TEMP_DIR/old-unit ]]; then printf '[INFO] 原服务文件恢复命令：install -m %s %q %q\n' "$UNIT_MODE" "$TEMP_DIR/old-unit" "$UNIT" >&2; fi
    if [[ -f $TEMP_DIR/old-installer ]]; then printf '[INFO] 原辅助脚本恢复命令：install -m 755 %q %q\n' "$TEMP_DIR/old-installer" "$LIB/install.sh" >&2; fi
    if [[ -f $TEMP_DIR/old-rotation ]]; then printf '[INFO] 原日志轮换恢复命令：install -m 644 %q %q\n' "$TEMP_DIR/old-rotation" "$ROTATION" >&2; fi
    if [[ $QN_INIT == systemd ]]; then echo '[INFO] 原文件恢复后运行：systemctl daemon-reload' >&2; fi
    if ((old_active)); then
      if [[ $QN_INIT == systemd ]]; then echo '[INFO] 原服务此前运行，文件恢复后运行：systemctl restart qingnode.service' >&2
      else echo '[INFO] 原服务此前运行，恢复文件和文件权限后运行：rc-service qingnode restart' >&2; fi
    fi
    echo '[INFO] 如需协助，请提供脱敏日志；不要删除状态目录或重新生成节点凭据。' >&2
    ((rc != 0)) || rc=1
  else rm -rf -- "$TEMP_DIR"; fi
  exit "$rc"
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
logged() {
  # Native OpenRC supervisors fork from this process tree. Keep the bootstrap
  # lease in this shell, never in the long-running supervisor or core.
  local result=0
  qn_guard_transaction || return 1
  if [[ -n $REDACTOR ]]; then "$@" 9>&- 2>&1 | "$REDACTOR" redact-log 9>&- >>"$LOG" || result=$?; else "$@" 9>&- >>"$LOG" 2>&1 || result=$?; fi
  qn_guard_transaction || return 1
  return "$result"
}
download_release() {
  local rc=0 hint size limit=$4
  # curl before 8.4 cannot enforce unknown response sizes. Limit file writes in
  # its child only; the separate log writer keeps the parent's resource limits.
  if (
    set -o posix # ulimit -f uses 512-byte units in POSIX mode.
    ulimit -S -c 0 && ulimit -S -f "$((limit / 512))" || exit 125
    exec curl -sS --proto '=https' --proto-redir '=https' -fL --retry 3 --connect-timeout 15 --max-time "$3" --max-filesize "$limit" "$1" -o "$2"
  ) 2>&1 | logged cat; then
    :
  else
    rc=${PIPESTATUS[0]}
    ((rc != 0)) || rc=23
  fi
  size=$(stat -c '%s' -- "$2" 2>/dev/null) || size=0
  if ((size > limit)); then rc=63; fi
  if ((rc == 0)); then return 0; fi
  rm -f -- "$2"
  case "$rc" in
    6) hint='DNS 解析失败：检查 github.com 的解析和服务器 DNS';;
    7) hint='无法连接下载服务器：检查出站 HTTPS 网络';;
    18) hint='下载内容不完整：检查网络稳定性后重试';;
    22) hint='HTTP 请求失败：查看日志中的状态码，确认该版本已发布';;
    23) hint='无法写入下载文件：检查磁盘空间及临时目录权限';;
    28) hint='下载超时：检查网络后重试，或使用完整本地发行包';;
    35|51|60) hint='TLS 或证书验证失败：检查系统时间、CA 证书与网络';;
    63|153) hint="$5超过下载上限（$limit 字节）：确认指定版本及官方发行资产，或上传已校验的完整本地发行包；不要关闭校验";;
    125) hint='无法建立下载文件大小限制：检查当前 shell 的资源限制，未继续下载';;
    *) hint="下载失败（curl 退出码 $rc）：查看安装日志";;
  esac
  printf '[ERROR] %s。也可上传已校验的完整发行包运行 install.sh。\n' "$hint" >&2
  return "$rc"
}
step 2 "校验管理器发行包并预检输入"
# A standalone download or Bash process substitution has no adjacent bundle.
# A partial local bundle must fail validation, never silently switch sources.
if [[ -z $REPO && ! -e $BUNDLE/qingnode && ! -L $BUNDLE/qingnode && ! -e $BUNDLE/SHA256SUMS && ! -L $BUNDLE/SHA256SUMS ]]; then
  REPO=$DEFAULT_REPO
fi
for tool in sha256sum awk grep; do
  command -v "$tool" >/dev/null || { echo "预检需要已有的 $tool；尚未安装任何依赖，请使用受信的完整本地包并先准备校验工具。" >&2; exit 1; }
done
if [[ -n $REPO ]]; then
  for tool in curl tar gzip; do
    command -v "$tool" >/dev/null || { echo "下载并预检需要已有的 $tool；尚未安装任何依赖，可改用受信的完整本地包。" >&2; exit 1; }
  done
  [[ $REPO =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9_.-]+$ && ${REPO##*/} != . && ${REPO##*/} != .. ]] || { echo '仓库名无效，格式应为 owner/repo。' >&2; exit 1; }
  [[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo '管理器版本号无效，格式应为 v数字.数字.数字。' >&2; exit 1; }
  if ((VERSION_EXPLICIT)); then
    base="https://github.com/$REPO/releases/download/$VERSION"
  else
    # Only a public formal Release becomes latest. Read its completed checksum
    # set once, then pin all remaining requests to the selected tag. This also
    # covers a new main installer arriving before its new assets are published.
    base="https://github.com/$REPO/releases/latest/download"
  fi
  download_release "$base/SHA256SUMS" "$TEMP_DIR/release-sums" 60 1048576 '发行摘要清单'
  if ((VERSION_EXPLICIT==0)); then
    asset=$(awk -v arch="$ARCH" '
      NF!=2 || length($1)!=64 || $1 !~ /^[a-fA-F0-9]+$/ {bad=1}
      {if (seen[$2]++) bad=1}
      $2 ~ ("^qingnode-[0-9]+[.][0-9]+[.][0-9]+-linux-" arch "[.]tar[.]gz$") {
        if (length($2)>128) bad=1; selected=$2; count++
      }
      END {if (bad || count!=1) exit 1; print selected}
    ' "$TEMP_DIR/release-sums") || { echo '最新正式发行摘要无效或缺少唯一的本架构管理器。' >&2; exit 1; }
    [[ $asset =~ ^qingnode-([0-9]+\.[0-9]+\.[0-9]+)-linux-(amd64|arm64)\.tar\.gz$ ]] || exit 1
    VERSION=v${BASH_REMATCH[1]}
  else
    asset="qingnode-${VERSION#v}-linux-$ARCH.tar.gz"
  fi
  base="https://github.com/$REPO/releases/download/$VERSION"
  printf '[INFO] 下载已公开 QingNode %s（%s，%s）；后续请求固定此版本。\n' "$VERSION" "$ARCH" "$REPO"
  expected=$(awk -v f="$asset" '$2==f {print $1}' "$TEMP_DIR/release-sums")
  [[ $expected =~ ^[a-fA-F0-9]{64}$ ]] || { echo '缺少唯一的发行包摘要。' >&2; exit 1; }
  download_release "$base/$asset" "$TEMP_DIR/$asset" 300 67108864 '管理器归档'
  actual=$(sha256sum "$TEMP_DIR/$asset"); actual=${actual%% *}
  [[ $actual == "${expected,,}" ]] || { echo '发行包摘要不匹配。' >&2; exit 1; }
  tar -tzf "$TEMP_DIR/$asset" > "$TEMP_DIR/members"
  if grep -Ev '^(qingnode|install[.]sh|SHA256SUMS|README[.]md|LICENSE|THIRD_PARTY[.]md|docs/?|docs/(ARCHITECTURE|TEST_REPORT|RELEASE_NOTES|AUDIT_STAGE2|GETTING_STARTED|FAQ|DEVELOPMENT|CAPABILITIES|BATCH_01|NETWORK_TESTS|BATCH_02|NETWORK_PERFORMANCE|BATCH_03|ENDPOINTS|BATCH04|TOPOLOGY|BATCH05|SUBSCRIPTIONS|BATCH06|CERTIFICATES|MIGRATION|BATCH07|MONITORING|BATCH08|PROTOCOLS|BATCH09|PLATFORMS|BATCH10|WORKFLOWS|BATCH11)[.]md)$' "$TEMP_DIR/members" >/dev/null; then echo '发行包包含未知路径。' >&2; exit 1; fi
  tar -tvzf "$TEMP_DIR/$asset" | awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" {bad=1} END {exit bad}' || { echo '发行包包含不允许的链接或特殊文件。' >&2; exit 1; }
  mkdir "$TEMP_DIR/bundle"
  tar --no-same-owner --no-same-permissions -xzf "$TEMP_DIR/$asset" -C "$TEMP_DIR/bundle"
  BUNDLE=$TEMP_DIR/bundle
fi
[[ -f $BUNDLE/qingnode && ! -L $BUNDLE/qingnode && -f $BUNDLE/SHA256SUMS ]] || { echo '请在本架构发行包中运行安装器，或指定已发布的 --repo 与 --version。' >&2; exit 1; }
awk 'NF!=2 || length($1)!=64 || $1 !~ /^[a-fA-F0-9]+$/ {bad=1}
  $2 !~ /^(qingnode|install[.]sh|README[.]md|LICENSE|THIRD_PARTY[.]md|docs\/(ARCHITECTURE|TEST_REPORT|RELEASE_NOTES|AUDIT_STAGE2|GETTING_STARTED|FAQ|DEVELOPMENT|CAPABILITIES|BATCH_01|NETWORK_TESTS|BATCH_02|NETWORK_PERFORMANCE|BATCH_03|ENDPOINTS|BATCH04|TOPOLOGY|BATCH05|SUBSCRIPTIONS|BATCH06|CERTIFICATES|MIGRATION|BATCH07|MONITORING|BATCH08|PROTOCOLS|BATCH09|PLATFORMS|BATCH10|WORKFLOWS|BATCH11)[.]md)$/ {bad=1}
  {if (seen[$2]++) bad=1} END {exit bad || !seen["qingnode"] || !seen["install.sh"]}' "$BUNDLE/SHA256SUMS" || { echo '摘要清单无效或缺少必要文件。' >&2; exit 1; }
while read -r _ member; do [[ -f $BUNDLE/$member && ! -L $BUNDLE/$member ]] || { echo '发行包成员必须是普通文件。' >&2; exit 1; }; done < "$BUNDLE/SHA256SUMS"
[[ ! -L $BUNDLE/docs ]] || { echo '发行包文档目录不允许链接。' >&2; exit 1; }
(cd "$BUNDLE" && sha256sum --strict -c SHA256SUMS) >>"$LOG" 2>&1
REDACTOR=$BUNDLE/qingnode
if [[ -n $WIZARD_PROTOCOL ]]; then
  if ! "$BUNDLE/qingnode" collect-install --help >"$TEMP_DIR/collect-help" 2>&1; then
    echo '首次TLS表单预检需要匹配的完整候选包；尚未安装依赖或核心。' >&2
    exit 1
  fi
  if ! "$BUNDLE/qingnode" collect-install --protocol "$WIZARD_PROTOCOL" --out "$TEMP_DIR/install-fields"; then
    exit 1
  fi
  if [[ ! -e $TEMP_DIR/install-fields ]]; then
    echo '已取消，未开始安装。'
    exit 0
  fi
  [[ -f $TEMP_DIR/install-fields && ! -L $TEMP_DIR/install-fields ]] || exit 1
fi
qn_legacy_install_preflight() {
  local argument value protocol=reality server='' sni='' target='' cert='' automatic=0 random=0 explicit_port=0 index
  local -a legacy=()
  for ((index=0; index<${#INIT_ARGS[@]}; index++)); do
    argument=${INIT_ARGS[index]}
    case "$argument" in
      --auto) automatic=1; continue;;
      --random-port) random=1; continue;;
    esac
    index=$((index+1)); value=${INIT_ARGS[index]}
    case "$argument" in
      --protocol) protocol=$value;; --server) server=$value;; --sni) sni=$value;; --target) target=$value;;
      --port) explicit_port=1;; --cert) cert=$value;;
    esac
    legacy+=("$argument" "$value")
  done
  if ((random && explicit_port)); then echo '--port 与 --random-port 不能同时使用。' >&2; return 1; fi
  if ((automatic)) && [[ $protocol == reality && -n $target && -z $sni ]]; then
    echo '显式 REALITY 目标必须搭配 --sni，不能推测目标证书名称。' >&2; return 1
  fi
  # Placeholders apply only to unspecified auto-discovered values, never to an
  # explicit argument. They do not prove DNS, TLS or incoming connectivity.
  if ((automatic)) && [[ -z $server ]]; then legacy+=(--server 203.0.113.1); fi
  if ((automatic)) && [[ $protocol == reality && -z $sni ]]; then legacy+=(--sni example.com); fi
  if ! "$BUNDLE/qingnode" --offline --root "$TEMP_DIR/legacy-state" init "${legacy[@]}" --quiet >"$TEMP_DIR/legacy-preflight" 2>&1; then
    echo '旧版管理器的隔离字段校验未通过；请核对协议、地址、端口及证书参数。' >&2
    return 1
  fi
  # The v0.2.8 offline backend does not inspect certificate dates. Preserve
  # that distinction and require a local trusted reader before touching host
  # configuration. The actual installation validates the certificate again.
  if [[ -n $cert ]]; then
    local not_before start now month year day hour minute second
    if ! command -v openssl >/dev/null || ! command -v date >/dev/null; then
      echo '旧版PEM预检需要已安装的openssl和date；尚未修改宿主。' >&2
      return 1
    fi
    [[ -f $cert ]] || { echo '证书文件不是可读取的普通文件。' >&2; return 1; }
    not_before=$(LC_ALL=C openssl x509 -in "$cert" -noout -startdate) || return 1
    if [[ ! $not_before =~ ^notBefore=([A-Za-z]{3})[[:space:]]+([0-9]{1,2})[[:space:]]+([0-9]{2}):([0-9]{2}):([0-9]{2})[[:space:]]+([0-9]{4})[[:space:]]+GMT$ ]]; then
      echo '无法验证证书开始时间；尚未修改宿主。' >&2; return 1
    fi
    case "${BASH_REMATCH[1]}" in Jan) month=1;; Feb) month=2;; Mar) month=3;; Apr) month=4;; May) month=5;; Jun) month=6;; Jul) month=7;; Aug) month=8;; Sep) month=9;; Oct) month=10;; Nov) month=11;; Dec) month=12;; *) return 1;; esac
    day=${BASH_REMATCH[2]} hour=${BASH_REMATCH[3]} minute=${BASH_REMATCH[4]} second=${BASH_REMATCH[5]} year=${BASH_REMATCH[6]}
    printf -v start '%04d%02d%02d%02d%02d%02d' "$((10#$year))" "$month" "$((10#$day))" "$((10#$hour))" "$((10#$minute))" "$((10#$second))"
    now=$(date -u +%Y%m%d%H%M%S) || return 1
    [[ $now =~ ^[0-9]{14}$ && ( $start < $now || $start == "$now" ) ]] || { echo '证书尚未生效或开始时间无效。' >&2; return 1; }
    openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 || { echo '证书已经过期或无法检查有效期。' >&2; return 1; }
  fi
  # Recovery material can survive a later failed install. Never leave these
  # temporary, unrelated test identities inside that retained directory.
  rm -rf -- "$TEMP_DIR/legacy-state"
  echo '[INFO] 已用旧版管理器隔离校验输入；占位地址、目标可达性与实际端口均未验证。' >&2
}
if [[ -z $WIZARD_PROTOCOL && ( ! -e $ROOT/current || ${#INIT_ARGS[@]} -gt 0 ) ]]; then
  for ((index=0; index<${#INIT_ARGS[@]}; index++)); do
    argument=${INIT_ARGS[index]}
    if [[ $argument == --certificate-id && ! -e $ROOT/current ]]; then
      echo '首次安装没有已保存证书资源；请提供PEM或ACME参数。' >&2
      exit 1
    fi
    case "$argument" in --auto|--random-port) ;; *) index=$((index+1));; esac
  done
  if "$BUNDLE/qingnode" --offline --root "$TEMP_DIR/probe-state" validate-install --help >"$TEMP_DIR/probe-output" 2>&1; then
    preflight_args=()
    [[ ! -e $ROOT/current ]] || preflight_args+=(--existing)
    if ! "$BUNDLE/qingnode" validate-install "${preflight_args[@]}" "${INIT_ARGS[@]}"; then
      echo '输入未通过预检；请核对实际参数。' >&2; exit 1
    fi
  elif grep -F '未知命令 "validate-install"' "$TEMP_DIR/probe-output" >/dev/null &&
       [[ $("$BUNDLE/qingnode" version) == 'QingNode 0.2.8 ('* ]] && [[ ! -e $ROOT/current ]]; then
    qn_legacy_install_preflight
  else
    echo '此发行管理器不支持可验证的预检；请使用与本安装器匹配的完整候选包。' >&2
    exit 1
  fi
fi
# Only validated input reaches package management, persistent logs and service
# ownership. An unavailable trusted verifier is a hard failure, never a guessed
# successful shell-only validation.
INSTALL_LOG=$(mktemp /var/log/qingnode-install-XXXXXXXX.log)
chmod 600 "$INSTALL_LOG"
cat "$LOG" > "$INSTALL_LOG"
LOG=$INSTALL_LOG
step 3 "检测并安装基础依赖"
qn_dependencies
install -d -m 755 /run/lock
exec 9>/run/lock/qingnode-bootstrap.lock
flock -n 9 || { echo '另一个安装操作正在进行。' >&2; exit 1; }
check_owned_paths
(cd "$BUNDLE" && sha256sum --strict -c SHA256SUMS) >>"$LOG" 2>&1
[[ ! -d $ROOT ]] || root_existed=1
[[ ! -d $LIB ]] || lib_existed=1
qn_snapshot_service
if [[ -f $BIN ]]; then cp -p "$BIN" "$TEMP_DIR/old-bin"; old_bin=1; fi
if [[ -f $UNIT ]]; then cp -p "$UNIT" "$TEMP_DIR/old-unit"; old_unit=1; fi
if [[ -f $LIB/install.sh ]]; then cp -p "$LIB/install.sh" "$TEMP_DIR/old-installer"; fi
if [[ $QN_INIT == openrc && -f $ROTATION ]]; then cp -p "$ROTATION" "$TEMP_DIR/old-rotation"; old_rotation=1; fi
printf '[INFO] %s %s / %s / %s；实现目标与实机证据分别见平台矩阵。\n' "$QN_OS_ID" "$QN_OS_VERSION_ID" "$ARCH" "$QN_INIT"
if command -v sing-box >/dev/null; then echo '[INFO] 检测到已有 sing-box；本项目使用自己的目录，不接管其他安装。'; fi
if ! getent ahosts github.com >"$TEMP_DIR/dns"; then echo '[WARN] GitHub DNS 查询失败；在线下载可能失败，可使用完整本地包和 --core-archive。' >&2; fi
ss -H -lntup >>"$LOG" 2>&1 || true
if [[ $QN_INIT == systemd ]]; then "$BUNDLE/qingnode" service unit > "$TEMP_DIR/qingnode.service"
else "$BUNDLE/qingnode" service unit --manager openrc > "$TEMP_DIR/qingnode.service"; fi
qn_check_service_definition
if [[ -f $ROOT/uninstall.json ]]; then
  logged "$BUNDLE/qingnode" recover
  qn_snapshot_service
  if [[ -f $BIN ]]; then cp -p "$BIN" "$TEMP_DIR/old-bin"; old_bin=1; fi
  if [[ -f $UNIT ]]; then cp -p "$UNIT" "$TEMP_DIR/old-unit"; old_unit=1; fi
  if [[ -f $LIB/install.sh ]]; then cp -p "$LIB/install.sh" "$TEMP_DIR/old-installer"; lib_existed=1; fi
fi
if [[ -f $ROOT/current/state.json ]]; then "$BUNDLE/qingnode" validate-state --file "$ROOT/current/state.json"; fi
qn_check_service_definition
step 4 "准备独立账户与配置目录"
cp -p "$BUNDLE/qingnode" "$TEMP_DIR/candidate-bin"
cp -p "$BUNDLE/install.sh" "$TEMP_DIR/candidate-installer"
QN_GUARD_READY=1
qn_guard_transaction
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
  qn_create_account
  created_user=1
elif ((!root_existed && !retained_account)); then
  echo '已有同名用户，拒绝自动接管。' >&2; exit 1
fi
install -d -m 750 -o root -g qingnode "$ROOT" "$ROOT/generations" "$ROOT/cores"
if [[ ! -f $ROOT/.qingnode-owner ]]; then printf '%s\n' "$OWNER" > "$ROOT/.qingnode-owner"; fi
install -d -m 750 -o qingnode -g qingnode "$ROOT/acme"
step 5 "安装管理器与 $QN_INIT 服务"
[[ ! -L $ROOT/.lock ]] || { echo '状态锁不允许符号链接。' >&2; exit 1; }
exec 8>"$ROOT/.lock"
flock -n 8 || { changed=0; echo '另一个节点管理操作正在运行，请稍后重试。' >&2; exit 1; }
if [[ -f $ROOT/current/state.json ]]; then "$BUNDLE/qingnode" validate-state --file "$ROOT/current/state.json"; fi
qn_guard_transaction
NEW_BIN=$(mktemp "$BIN.new.XXXXXXXX")
install -m 755 "$BUNDLE/qingnode" "$NEW_BIN"
qn_guard_transaction
mv -f "$NEW_BIN" "$BIN"
QN_BIN_COMMITTED=1
qn_guard_transaction
NEW_UNIT=$(mktemp "$UNIT.new.XXXXXXXX")
install -m "$UNIT_MODE" "$TEMP_DIR/qingnode.service" "$NEW_UNIT"
qn_guard_transaction
mv -f "$NEW_UNIT" "$UNIT"
QN_UNIT_COMMITTED=1
qn_guard_transaction
install -d -m 755 "$LIB"
printf '%s\n' "$OWNER" > "$LIB/.qingnode-owner"
install -m 755 "$BUNDLE/install.sh" "$LIB/install.sh"
QN_INSTALLER_COMMITTED=1
qn_guard_transaction
qn_log_rotation
qn_manager_permissions
logged qn_service reload
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
    # Interactive errors remain on the terminal. A process-substitution tee
    # leaks its FD63 into OpenRC's supervisor and can prevent installation EOF.
    "$BIN" wizard --protocol "$WIZARD_PROTOCOL" --quiet --fields-file "$TEMP_DIR/install-fields" 9>&-
  else
    logged "$BIN" init "${INIT_ARGS[@]}" --quiet
  fi
  logged qn_service enable
fi
changed=0
step 8 "安装完成，以下为节点摘要（认证信息已隐藏）"
"$BIN" info
echo '安装完成。运行 qingnode 打开菜单；需要客户端链接或配置时，请显式使用上方导出命令并妥善保存。'
echo '请在已启用的防火墙和云安全组放行上方实际监听端口及协议，再用客户端验证；故障时运行 qingnode diagnose。'
