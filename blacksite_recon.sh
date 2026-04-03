#!/usr/bin/env bash
set -euo pipefail

# Blacksite Recon: Host Hardening + Threat Surface Recon
# Usage:
#   bash blacksite_recon.sh
# Optional:
#   SUDO=1 bash blacksite_recon.sh   # attempt privileged checks where available

SUDO_MODE="${SUDO:-0}"
HOST="$(hostname 2>/dev/null || echo unknown)"
KERNEL="$(uname -r 2>/dev/null || echo unknown)"
ARCH="$(uname -m 2>/dev/null || echo unknown)"
TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo unknown)"

PASS=0
WARN=0
FAIL=0

line() { printf '%s\n' "------------------------------------------------------------"; }
section() { line; printf '[%s]\n' "$1"; line; }

ok()   { PASS=$((PASS+1)); printf '[PASS] %s\n' "$1"; }
warn() { WARN=$((WARN+1)); printf '[WARN] %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '[FAIL] %s\n' "$1"; }

exists() { command -v "$1" >/dev/null 2>&1; }
readable() { [[ -r "$1" ]]; }

read_sysctl() {
  local key="$1"
  if exists sysctl; then
    sysctl -n "$key" 2>/dev/null || true
  else
    local path="/proc/sys/${key//./\/}"
    [[ -r "$path" ]] && cat "$path" 2>/dev/null || true
  fi
}

bool_check() {
  local label="$1" got="$2" expect="$3"
  if [[ "$got" == "$expect" ]]; then
    ok "$label = $got"
  elif [[ -z "$got" ]]; then
    warn "$label unavailable"
  else
    fail "$label = $got (expected $expect)"
  fi
}

tri() {
  local sev="$1" msg="$2"
  printf '  - [%s] %s\n' "$sev" "$msg"
}

print_header() {
  section "SYSTEM"
  printf 'Host        : %s\n' "$HOST"
  printf 'Kernel      : %s\n' "$KERNEL"
  printf 'Arch        : %s\n' "$ARCH"
  printf 'UTC Time    : %s\n' "$TS"
  printf 'User        : %s\n' "$(id -un 2>/dev/null || echo unknown)"
  printf 'UID/GID     : %s/%s\n' "$(id -u 2>/dev/null || echo ? )" "$(id -g 2>/dev/null || echo ? )"
  printf 'SUDO mode   : %s\n' "$SUDO_MODE"
}

check_hardening() {
  section "KERNEL HARDENING"

  bool_check "ASLR (kernel.randomize_va_space)" "$(read_sysctl kernel.randomize_va_space)" "2"
  bool_check "ptrace_scope (kernel.yama.ptrace_scope)" "$(read_sysctl kernel.yama.ptrace_scope)" "1"
  bool_check "dmesg_restrict (kernel.dmesg_restrict)" "$(read_sysctl kernel.dmesg_restrict)" "1"
  bool_check "kptr_restrict (kernel.kptr_restrict)" "$(read_sysctl kernel.kptr_restrict)" "2"
  bool_check "unprivileged_bpf_disabled" "$(read_sysctl kernel.unprivileged_bpf_disabled)" "1"
  bool_check "unprivileged_userns_clone" "$(read_sysctl kernel.unprivileged_userns_clone)" "0"

  local lockdown=""
  if readable /sys/kernel/security/lockdown; then
    lockdown="$(cat /sys/kernel/security/lockdown 2>/dev/null || true)"
    if grep -qi '\[integrity\]\|\[confidentiality\]' <<<"$lockdown"; then
      ok "kernel lockdown active: $lockdown"
    elif [[ -n "$lockdown" ]]; then
      warn "kernel lockdown present but not enforcing: $lockdown"
    else
      warn "kernel lockdown status unreadable"
    fi
  else
    warn "kernel lockdown not exposed (/sys/kernel/security/lockdown missing)"
  fi
}

check_lsm() {
  section "LSM / MAC"

  if exists getenforce; then
    local se
    se="$(getenforce 2>/dev/null || true)"
    case "$se" in
      Enforcing) ok "SELinux enforcing" ;;
      Permissive) warn "SELinux permissive" ;;
      Disabled) fail "SELinux disabled" ;;
      *) warn "SELinux state unknown: $se" ;;
    esac
  else
    warn "SELinux tools not found"
  fi

  if exists aa-status; then
    local aaout
    aaout="$(aa-status 2>/dev/null || true)"
    if grep -qi 'profiles are in enforce mode' <<<"$aaout"; then
      ok "AppArmor enforce profiles active"
    elif [[ -n "$aaout" ]]; then
      warn "AppArmor present but unclear enforcement"
    else
      warn "AppArmor status unavailable"
    fi
  else
    warn "AppArmor tools not found"
  fi
}

check_surface() {
  section "ATTACK SURFACE"

  if exists ss; then
    local listening
    listening="$(ss -lntupH 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "${listening:-0}" -le 8 ]]; then
      ok "listening sockets: $listening"
    else
      warn "high listening socket count: $listening"
    fi

    printf 'Top listeners:\n'
    ss -lntup 2>/dev/null | head -n 10 || true
  else
    warn "ss not available"
  fi

  if exists systemctl; then
    local svc
    svc="$(systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -c '\.service' || true)"
    if [[ -n "$svc" ]]; then
      if [[ "$svc" -le 40 ]]; then ok "enabled services: $svc"; else warn "many enabled services: $svc"; fi
    else
      warn "could not enumerate enabled services"
    fi
  else
    warn "systemctl not available (container/minimal distro?)"
  fi

  if readable /proc/modules; then
    local modc
    modc="$(wc -l < /proc/modules | tr -d ' ')"
    if [[ "$modc" -le 150 ]]; then ok "loaded kernel modules: $modc"; else warn "high module count: $modc"; fi
  else
    warn "/proc/modules not readable"
  fi
}

check_identity() {
  section "IDENTITY / PRIVILEGE HYGIENE"

  if exists getent; then
    local uid0
    uid0="$(getent passwd 2>/dev/null | awk -F: '$3==0{print $1}' | tr '\n' ' ')"
    if [[ -z "${uid0// }" ]]; then
      warn "unable to enumerate UID 0 users"
    else
      local count
      count="$(wc -w <<<"$uid0" | tr -d ' ')"
      if [[ "$count" -eq 1 ]]; then
        ok "single UID 0 account: $uid0"
      else
        fail "multiple UID 0 accounts: $uid0"
      fi
    fi
  else
    warn "getent not available"
  fi

  if [[ -r /etc/sudoers ]] || [[ -d /etc/sudoers.d ]]; then
    ok "sudo policy files present"
  else
    warn "sudo policy files not readable"
  fi

  if exists find; then
    printf 'Potential world-writable dirs (top 12):\n'
    find / -xdev -type d -perm -0002 2>/dev/null | head -n 12 || true
  else
    warn "find not available"
  fi
}

check_process_guardrails() {
  section "PROCESS GUARDRAILS"

  if readable /proc/1/status; then
    local no_new_privs seccomp
    no_new_privs="$(awk -F:\t '/NoNewPrivs/{print $2}' /proc/1/status 2>/dev/null | tr -d ' ')"
    seccomp="$(awk -F:\t '/Seccomp/{print $2}' /proc/1/status 2>/dev/null | tr -d ' ')"

    case "$no_new_privs" in
      1) ok "PID1 NoNewPrivs enabled" ;;
      0) warn "PID1 NoNewPrivs disabled" ;;
      *) warn "PID1 NoNewPrivs unknown" ;;
    esac

    case "$seccomp" in
      2) ok "PID1 seccomp filtering active" ;;
      1) warn "PID1 seccomp strict mode" ;;
      0) fail "PID1 seccomp disabled" ;;
      *) warn "PID1 seccomp unknown" ;;
    esac
  else
    warn "cannot read /proc/1/status"
  fi

  if exists ps; then
    printf 'Highest RSS processes (top 8):\n'
    ps -eo pid,user,comm,%cpu,%mem,rss --sort=-rss 2>/dev/null | head -n 9 || true
  else
    warn "ps not available"
  fi
}

check_logs() {
  section "FAST INCIDENT TRIAGE SIGNALS"

  if exists journalctl; then
    printf 'Recent auth/service errors (last 50 lines):\n'
    journalctl -p err -n 50 --no-pager 2>/dev/null | tail -n 20 || true
    ok "journalctl queried"
  elif [[ -r /var/log/auth.log ]]; then
    printf 'Recent auth.log failed auth snippets:\n'
    grep -Ei 'fail|invalid|error|denied' /var/log/auth.log 2>/dev/null | tail -n 20 || true
    ok "auth.log queried"
  else
    warn "no journalctl/auth.log access"
  fi
}

risk_score() {
  section "RISK SCORE"
  local total=$((PASS + WARN + FAIL))
  local weighted=$((FAIL * 3 + WARN))
  local max=$(( (total > 0 ? total : 1) * 3 ))
  local pct=$((100 - (weighted * 100 / max)))
  if (( pct < 0 )); then pct=0; fi

  printf 'PASS=%d WARN=%d FAIL=%d\n' "$PASS" "$WARN" "$FAIL"
  printf 'Host Security Score: %d/100\n' "$pct"

  if (( pct >= 85 )); then
    tri "LOW" "Hardening posture strong; focus on drift monitoring and patch cadence."
  elif (( pct >= 65 )); then
    tri "MED" "Baseline acceptable; reduce warning backlog and close high-exposure services."
  else
    tri "HIGH" "Significant exposure; prioritize kernel hardening, service minimization, and MAC enforcement."
  fi
}

main() {
  print_header
  check_hardening
  check_lsm
  check_surface
  check_identity
  check_process_guardrails
  check_logs
  risk_score
}

main "$@"
