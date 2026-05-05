#!/usr/bin/env bash
#
# amnezia-installer.sh — AmneziaWG road-warrior VPN server installer for Linux.
#
# ─── Quick install ──────────────────────────────────────────────────────────
#   # One-liner, non-interactive (takes all defaults; override with AMNEZIA_* env):
#   curl -fsSL https://raw.githubusercontent.com/maciekish/amnezia-installer/main/amnezia-installer.sh | sudo bash
#
#   # Interactive (preserves the TTY so prompts work):
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/maciekish/amnezia-installer/main/amnezia-installer.sh)"
#
#   # Or: download once, then run with any subcommand:
#   curl -fsSL https://raw.githubusercontent.com/maciekish/amnezia-installer/main/amnezia-installer.sh -o amnezia-installer.sh
#   chmod +x amnezia-installer.sh && sudo ./amnezia-installer.sh
#
# The URLs above always resolve to the latest version on the `main` branch.
#
# ─── Subcommands ────────────────────────────────────────────────────────────
#   install                 Interactive install (default if no subcommand given)
#   add-client    <name>    Generate a new peer + client config
#   remove-client <name>    Revoke a peer
#   list-clients            List configured peers
#   show-client   <name>    Reprint a client's config + QR code
#   status                  Show interface state and peers
#   uninstall   [--purge]   Remove the service and rules (--purge also removes keys/configs)
#
# Goals:
#   * Latest AmneziaVPN server (AmneziaWG protocol, obfuscated WireGuard).
#   * Coexists with vanilla WireGuard or other VPNs:
#       - Uses a non-default UDP port (suggested by detection).
#       - Uses dedicated nftables tables prefixed "amnezia_" — never touches existing rules.
#       - Uses its own interface name and config path (/etc/amnezia/amneziawg/awg0.conf).
#   * Performs the unavoidable system tweaks (IPv4/IPv6 forwarding, NAT) but writes them
#     to a single dedicated sysctl drop-in and dedicated nft tables, so uninstall is clean.
#   * Full IPv4 + IPv6 support; IPv6 auto-skipped if the host has no global IPv6.
#   * Does NOT NAT/route the server's local LAN — RFC1918, CGNAT, link-local, ULA, multicast
#     and loopback destinations are excluded from masquerade.
#   * Sane defaults; can run fully non-interactive via env vars (see below).
#
# Tested distros: Debian 11/12, Ubuntu 20.04/22.04/24.04, Fedora 38+, Rocky/Alma 9, Arch.
#
# Non-interactive env overrides (any unset are prompted for):
#   AMNEZIA_NONINTERACTIVE=1     skip all prompts, take defaults
#   AMNEZIA_HOST=<ip-or-fqdn>    public endpoint clients dial
#   AMNEZIA_PORT=<udp-port>      listen port
#   AMNEZIA_OBFUSCATION=off|standard|aggressive
#   AMNEZIA_CLIENT_NAME=<name>   first client name (default: client1)
#   AMNEZIA_ENABLE_IPV6=auto|yes|no
#   AMNEZIA_NET4=10.66.66.0/24
#   AMNEZIA_NET6=fd86:ea04:1115::/64
#   AMNEZIA_DNS="1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001"
#   AMNEZIA_MTU=1280
#   AMNEZIA_NO_UPDATE_CHECK=1    skip the on-startup self-update check
#   AMNEZIA_FORCE_CLEANUP=1      auto-clean any existing AmneziaWG install before reinstalling
#
# Self-update: on every invocation the script compares its own SCRIPT_VERSION
# tag against the version found at the URL above; if newer it downloads,
# verifies syntax, replaces /var/lib/amnezia-installer/amnezia-installer.sh,
# and re-execs. Only the AmneziaWG installation is ever touched on cleanup —
# stock WireGuard interfaces (wg*), /etc/wireguard/, wg-quick@*.service, and
# any third-party VPN are left strictly alone.
#
# This script is intentionally bash-only (#!/usr/bin/env bash) so it runs identically whether
# the invoking user's login shell is bash or zsh.

set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.1.0"
readonly SCRIPT_NAME="amnezia-installer"
readonly IFACE="awg0"
readonly SVC="awg-quick@${IFACE}.service"
readonly AWG_DIR="/etc/amnezia/amneziawg"
readonly AWG_CONF="${AWG_DIR}/${IFACE}.conf"
readonly STATE_DIR="/var/lib/${SCRIPT_NAME}"
readonly CLIENTS_DIR="${STATE_DIR}/clients"
readonly META_FILE="${STATE_DIR}/server.env"
readonly INSTALLED_SELF="${STATE_DIR}/${SCRIPT_NAME}.sh"
readonly UPDATE_STAMP="${STATE_DIR}/.last-update-check"
readonly SYMLINK="/usr/local/bin/${SCRIPT_NAME}"
readonly SYSCTL_FILE="/etc/sysctl.d/99-${SCRIPT_NAME}.conf"
readonly HOOK_UP="${AWG_DIR}/${IFACE}.up.sh"
readonly HOOK_DOWN="${AWG_DIR}/${IFACE}.down.sh"
readonly NFT_T_FWD="amnezia_fwd"
readonly NFT_T_NAT4="amnezia_nat4"
readonly NFT_T_NAT6="amnezia_nat6"
readonly UPDATE_URL="https://raw.githubusercontent.com/maciekish/amnezia-installer/main/amnezia-installer.sh"
readonly UPDATE_CACHE_SECONDS=86400  # only hit the network once a day

# ---------------------------------------------------------------------------
# Logging / UX helpers
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
    C_RST=$'\033[0m'; C_BOLD=$'\033[1m'
    C_RED=$'\033[1;31m'; C_GRN=$'\033[1;32m'; C_YLW=$'\033[1;33m'; C_BLU=$'\033[1;34m'
else
    C_RST=''; C_BOLD=''; C_RED=''; C_GRN=''; C_YLW=''; C_BLU=''
fi

log()  { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
info() { printf '%s[i]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YLW" "$C_RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

on_err() {
    local rc=$? line=$1
    err "Aborted at line $line (exit $rc). Run with 'bash -x $0' for a trace."
    exit "$rc"
}
trap 'on_err $LINENO' ERR

# ---------------------------------------------------------------------------
# Prompt helpers — honour AMNEZIA_NONINTERACTIVE=1 and any AMNEZIA_* env override.
# ---------------------------------------------------------------------------
ask() {
    # ask "question" "default" -> echoes the answer
    local prompt="$1" default="${2-}" reply=""
    if [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ] || [ ! -t 0 ]; then
        printf '%s' "$default"; return
    fi
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " reply || reply=""
    else
        read -r -p "$prompt: " reply || reply=""
    fi
    printf '%s' "${reply:-$default}"
}

ask_yn() {
    # ask_yn "question" "y|n"
    local prompt="$1" default="${2:-y}" reply
    while :; do
        reply=$(ask "$prompt (y/n)" "$default")
        case "$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *)     warn "Please answer y or n." ;;
        esac
    done
}

ask_choice() {
    # ask_choice "Heading" default_index "opt1" "opt2" ...
    # Echoes the chosen option string.
    local heading="$1" default_idx="$2"; shift 2
    local opts=("$@") n=$# i reply=""
    if [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ] || [ ! -t 0 ]; then
        printf '%s' "${opts[$((default_idx-1))]}"; return
    fi
    printf '%s\n' "$heading" >&2
    for ((i=0; i<n; i++)); do printf '   %d) %s\n' $((i+1)) "${opts[$i]}" >&2; done
    while :; do
        reply=$(ask "Select 1-$n" "$default_idx")
        if [[ "$reply" =~ ^[0-9]+$ ]] && [ "$reply" -ge 1 ] && [ "$reply" -le "$n" ]; then
            printf '%s' "${opts[$((reply-1))]}"; return
        fi
        warn "Pick a number between 1 and $n."
    done
}

# ---------------------------------------------------------------------------
# System detection
# ---------------------------------------------------------------------------
need_root() {
    [ "$(id -u)" -eq 0 ] || die "Run as root (use sudo)."
}

detect_os() {
    [ -r /etc/os-release ] || die "Cannot read /etc/os-release; unsupported system."
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
}

is_debian_like() {
    case "$OS_ID" in debian|ubuntu|linuxmint|pop|elementary|kali|raspbian) return 0 ;; esac
    case " $OS_LIKE " in *" debian "*|*" ubuntu "*) return 0 ;; esac
    return 1
}
is_rhel_like() {
    case "$OS_ID" in fedora|rhel|centos|rocky|almalinux|ol) return 0 ;; esac
    case " $OS_LIKE " in *" fedora "*|*" rhel "*|*" centos "*) return 0 ;; esac
    return 1
}
is_arch_like() {
    case "$OS_ID" in arch|manjaro|endeavouros|cachyos|garuda) return 0 ;; esac
    case " $OS_LIKE " in *" arch "*) return 0 ;; esac
    return 1
}

detect_default_iface() {
    # Default route's egress interface — used as the "WAN" for masquerade.
    ip -4 -o route show default 2>/dev/null | awk '{print $5; exit}' \
        || ip -6 -o route show default 2>/dev/null | awk '{print $5; exit}'
}

detect_public_ip4() {
    local ip
    for url in https://api.ipify.org https://ifconfig.me https://ipv4.icanhazip.com; do
        ip=$(curl -fsS4 --max-time 4 "$url" 2>/dev/null || true)
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            printf '%s' "$ip"; return
        fi
    done
}

detect_public_ip6() {
    local ip
    for url in https://api6.ipify.org https://ifconfig.co https://ipv6.icanhazip.com; do
        ip=$(curl -fsS6 --max-time 4 "$url" 2>/dev/null || true)
        if [[ "$ip" == *:* ]]; then printf '%s' "$ip"; return; fi
    done
}

has_global_ipv6() {
    ip -6 -o addr show scope global 2>/dev/null \
        | awk '$3=="inet6" && $4 !~ /^f[cd]/ {found=1} END {exit found?0:1}'
}

is_port_in_use() {
    local port="$1"
    ss -Hlun "sport = :$port" 2>/dev/null | grep -q . && return 0
    ss -Hltn "sport = :$port" 2>/dev/null | grep -q . && return 0
    return 1
}

suggest_port() {
    # Try sensible defaults first, fall back to a random high UDP port.
    local p
    for p in 51820 51821 51822 41194 49152 33433; do
        if ! is_port_in_use "$p"; then printf '%s' "$p"; return; fi
    done
    for _ in {1..50}; do
        p=$(( (RANDOM % 15000) + 49152 ))
        if ! is_port_in_use "$p"; then printf '%s' "$p"; return; fi
    done
    printf '%s' 51820
}

# ---------------------------------------------------------------------------
# Self-update: compare the local SCRIPT_VERSION tag against the head of the
# canonical script on `main`, and re-exec ourselves on a new version. We never
# touch anything other than $INSTALLED_SELF, and a syntax check runs on the
# downloaded copy before we trust it.
# ---------------------------------------------------------------------------
version_gt() {
    # version_gt A B -> true if A > B (semver-ish, falls back to string compare)
    [ "$1" = "$2" ] && return 1
    local newer
    newer=$(printf '%s\n%s\n' "$1" "$2" | sort -V 2>/dev/null | tail -n1)
    [ "$newer" = "$1" ]
}

remote_version() {
    # Echoes the SCRIPT_VERSION found in the remote script (or empty on failure).
    curl -fsSL --max-time 6 "$UPDATE_URL" 2>/dev/null \
        | grep -m1 -E '^readonly[[:space:]]+SCRIPT_VERSION=' \
        | sed -E 's/.*"([^"]+)".*/\1/' \
        || true
}

update_check_cached() {
    # Returns 0 if we already checked within UPDATE_CACHE_SECONDS.
    [ -r "$UPDATE_STAMP" ] || return 1
    local now stamp
    now=$(date +%s)
    stamp=$(cat "$UPDATE_STAMP" 2>/dev/null || echo 0)
    [ -n "$stamp" ] && [ "$((now - stamp))" -lt "$UPDATE_CACHE_SECONDS" ]
}

stamp_update_check() {
    [ -d "$STATE_DIR" ] || return 0
    date +%s >"$UPDATE_STAMP" 2>/dev/null || true
}

self_update() {
    # self_update [--force] [originally-passed-args...]
    local force=0
    if [ "${1:-}" = "--force" ]; then force=1; shift; fi

    [ "${AMNEZIA_NO_UPDATE_CHECK:-0}" = "1" ] && return 0
    [ "${_AMNEZIA_UPDATED:-0}" = "1" ] && return 0          # already re-execed
    [ "$force" -eq 1 ] || ! update_check_cached || return 0  # cache hit

    command -v curl >/dev/null 2>&1 || return 0

    local rv
    rv=$(remote_version)
    stamp_update_check
    [ -n "$rv" ] || return 0

    if ! version_gt "$rv" "$SCRIPT_VERSION"; then
        return 0
    fi

    info "amnezia-installer update available: $SCRIPT_VERSION -> $rv"
    if [ "$force" -ne 1 ] && [ "${AMNEZIA_NONINTERACTIVE:-0}" != "1" ]; then
        if ! ask_yn "Update now and re-run?" "y"; then
            info "Update skipped. Use 'self-update --force' or unset AMNEZIA_NONINTERACTIVE later."
            return 0
        fi
    fi

    local tmp; tmp=$(mktemp)
    if ! curl -fsSL --max-time 30 "$UPDATE_URL" -o "$tmp"; then
        warn "Could not download update; continuing with $SCRIPT_VERSION."
        rm -f "$tmp"; return 0
    fi
    if ! bash -n "$tmp" 2>/dev/null; then
        warn "Downloaded update failed syntax check; ignoring."
        rm -f "$tmp"; return 0
    fi
    install -d -m 0755 "$STATE_DIR"
    install -m 0755 "$tmp" "$INSTALLED_SELF"
    ln -sf "$INSTALLED_SELF" "$SYMLINK" 2>/dev/null || true
    rm -f "$tmp"
    log "Updated to $rv. Re-executing..."
    export _AMNEZIA_UPDATED=1
    exec "$INSTALLED_SELF" "$@"
}

install_self_to_state() {
    # Drop the running script (or, if invoked via curl|bash where $0 isn't a
    # real file, the latest from $UPDATE_URL) into $INSTALLED_SELF and link it
    # onto $PATH so the user can call `amnezia-installer ...` directly.
    install -d -m 0755 "$STATE_DIR"
    if [ -f "$0" ] && [ -r "$0" ] && [ "$(realpath -m "$0" 2>/dev/null)" != "$INSTALLED_SELF" ]; then
        install -m 0755 "$0" "$INSTALLED_SELF"
    elif [ ! -f "$INSTALLED_SELF" ]; then
        if command -v curl >/dev/null 2>&1; then
            if curl -fsSL --max-time 30 "$UPDATE_URL" -o "$INSTALLED_SELF"; then
                chmod 0755 "$INSTALLED_SELF"
            else
                warn "Could not stage script copy at $INSTALLED_SELF."
                rm -f "$INSTALLED_SELF"
            fi
        fi
    fi
    if [ -f "$INSTALLED_SELF" ]; then
        ln -sf "$INSTALLED_SELF" "$SYMLINK" 2>/dev/null || true
        info "Installed script copy: $INSTALLED_SELF (symlinked at $SYMLINK)"
    fi
}

# ---------------------------------------------------------------------------
# Existing-install detection — finds AmneziaWG leftovers (active service,
# stale config, dangling interface, our nft tables, our sysctl drop-in, our
# state dir) and offers a *scoped* cleanup. Stock WireGuard interfaces and any
# unrelated VPN are NEVER touched: the matching is exact (awg0, awg-quick@awg0,
# /etc/amnezia/amneziawg/, amnezia_* nft tables, our sysctl filename).
# ---------------------------------------------------------------------------
detect_existing_awg() {
    # Echoes one finding per line; empty output == nothing found.
    local found=()

    if systemctl list-unit-files "$SVC" 2>/dev/null | grep -q "$SVC"; then
        local state
        state=$(systemctl is-active "$SVC" 2>/dev/null || true)
        case "$state" in
            active)         found+=("service '$SVC' is active") ;;
            failed)         found+=("service '$SVC' is in FAILED state") ;;
            activating)     found+=("service '$SVC' is starting") ;;
            inactive|"")    : ;;
            *)              found+=("service '$SVC' present (state: $state)") ;;
        esac
        if [ "$(systemctl is-enabled "$SVC" 2>/dev/null || true)" = "enabled" ]; then
            found+=("service '$SVC' is enabled at boot")
        fi
    fi

    [ -e "$AWG_CONF" ]                   && found+=("config file $AWG_CONF")
    [ -e "$HOOK_UP" ] || [ -e "$HOOK_DOWN" ] && found+=("hook scripts in $AWG_DIR")
    ip link show "$IFACE" >/dev/null 2>&1 && found+=("interface '$IFACE' is up")
    [ -e "$SYSCTL_FILE" ]                && found+=("sysctl drop-in $SYSCTL_FILE")
    [ -e "$META_FILE" ]                  && found+=("state file $META_FILE")

    local t
    for t in "$NFT_T_FWD" "$NFT_T_NAT4" "$NFT_T_NAT6"; do
        if nft list tables 2>/dev/null | grep -qE "table (inet|ip|ip6) ${t}\$"; then
            found+=("nftables table $t")
        fi
    done

    if [ "${#found[@]}" -gt 0 ]; then
        printf '%s\n' "${found[@]}"
    fi
}

cleanup_existing_awg() {
    # Same scope as the `uninstall` subcommand minus the user-facing prompts.
    # Only awg-named units, our config dir, our state dir, our sysctl file,
    # our hook scripts, and the amnezia_* nft tables are touched.
    log "Cleaning up existing AmneziaWG installation..."
    systemctl disable --now "$SVC" 2>/dev/null || true

    nft delete table inet "$NFT_T_FWD"  2>/dev/null || true
    nft delete table ip   "$NFT_T_NAT4" 2>/dev/null || true
    nft delete table ip6  "$NFT_T_NAT6" 2>/dev/null || true

    if ip link show "$IFACE" >/dev/null 2>&1; then
        # If the unit didn't manage to bring the link down (e.g. failed state),
        # bring the interface down ourselves — but only if it's named exactly
        # awg0, never any other interface.
        ip link set "$IFACE" down 2>/dev/null || true
        ip link delete "$IFACE" 2>/dev/null || true
    fi

    rm -f "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true

    rm -f "$HOOK_UP" "$HOOK_DOWN" "$AWG_CONF"
    rm -f "$AWG_DIR/server.key" "$AWG_DIR/server.pub"
    # Only remove $AWG_DIR if we created it and it's now empty — never recursive.
    rmdir "$AWG_DIR" 2>/dev/null || true
    rmdir "$(dirname "$AWG_DIR")" 2>/dev/null || true

    rm -rf "$STATE_DIR"
    log "Cleanup complete."
}

maybe_cleanup_existing() {
    local findings
    findings=$(detect_existing_awg || true)
    [ -z "$findings" ] && return 0

    warn "Existing AmneziaWG artefacts detected:"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        printf '  - %s\n' "$line" >&2
    done <<<"$findings"

    info "(Stock WireGuard, /etc/wireguard/, wg-quick@*, and any other VPNs will NOT be touched.)"

    local do_clean=0
    if [ "${AMNEZIA_FORCE_CLEANUP:-0}" = "1" ]; then
        do_clean=1
    elif [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ]; then
        warn "Non-interactive mode and AMNEZIA_FORCE_CLEANUP not set; aborting to avoid stomping."
        die "Set AMNEZIA_FORCE_CLEANUP=1 to auto-clean, or run '$0 uninstall --purge' first."
    elif ask_yn "Remove these AmneziaWG artefacts and reinstall fresh?" "y"; then
        do_clean=1
    fi

    [ "$do_clean" -eq 1 ] || die "Aborted; existing installation left untouched."
    cleanup_existing_awg
}

# ---------------------------------------------------------------------------
# Random number generation for obfuscation parameters
# ---------------------------------------------------------------------------
rand_in_range() {
    # rand_in_range MIN MAX  (inclusive)
    local min=$1 max=$2
    local span=$(( max - min + 1 ))
    local raw
    raw=$(od -An -N4 -tu4 /dev/urandom | tr -d ' \n')
    printf '%s' "$(( min + raw % span ))"
}

rand_h_quad() {
    # Generate four distinct values in [5, 2^31-1].
    local a b c d
    while :; do
        a=$(rand_in_range 5 2147483647)
        b=$(rand_in_range 5 2147483647)
        c=$(rand_in_range 5 2147483647)
        d=$(rand_in_range 5 2147483647)
        [ "$a" != "$b" ] && [ "$a" != "$c" ] && [ "$a" != "$d" ] \
            && [ "$b" != "$c" ] && [ "$b" != "$d" ] && [ "$c" != "$d" ] \
            && break
    done
    printf '%s %s %s %s' "$a" "$b" "$c" "$d"
}

# ---------------------------------------------------------------------------
# Package installation
# ---------------------------------------------------------------------------
install_prereqs() {
    log "Installing prerequisites..."
    if is_debian_like; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq \
            curl ca-certificates iproute2 nftables qrencode \
            software-properties-common gpg jq
    elif is_rhel_like; then
        local pm
        pm=$(command -v dnf || command -v yum)
        "$pm" install -y curl ca-certificates iproute nftables qrencode jq \
            'dnf-command(copr)' || "$pm" install -y curl iproute nftables qrencode jq
    elif is_arch_like; then
        pacman -Sy --noconfirm --needed curl ca-certificates iproute2 nftables qrencode jq
    else
        die "Unsupported distro: $OS_ID. Patches welcome."
    fi
}

install_amneziawg() {
    log "Installing AmneziaWG..."
    if is_debian_like; then
        install_amneziawg_apt
    elif is_rhel_like; then
        install_amneziawg_dnf
    elif is_arch_like; then
        install_amneziawg_arch
    else
        die "No AmneziaWG installation path for $OS_ID."
    fi

    if ! command -v awg >/dev/null 2>&1; then
        die "AmneziaWG installation failed: 'awg' not found in PATH."
    fi
    if ! command -v awg-quick >/dev/null 2>&1; then
        die "AmneziaWG installation failed: 'awg-quick' not found in PATH."
    fi
    info "AmneziaWG installed: $(awg --version 2>/dev/null | head -n1 || echo present)"
}

install_amneziawg_apt() {
    if ! grep -rqs '^deb .*amnezia' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
        info "Adding ppa:amnezia/ppa..."
        # On minimal Debian, add-apt-repository may be missing.
        if ! command -v add-apt-repository >/dev/null 2>&1; then
            apt-get install -y -qq software-properties-common
        fi
        # add-apt-repository on Debian needs a codename it understands; fall back
        # to ubuntu's "jammy" for Debian since the PPA only ships Ubuntu pockets,
        # but preferred path is to install on Ubuntu where the codename matches.
        if ! add-apt-repository -y ppa:amnezia/ppa 2>/dev/null; then
            warn "add-apt-repository failed; adding PPA manually for jammy."
            install -d -m 0755 /etc/apt/keyrings
            curl -fsSL 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x75c2cfd7e22b58dd45063c25d3bbf4ae40af89ed' \
                | gpg --dearmor --yes -o /etc/apt/keyrings/amnezia.gpg
            cat >/etc/apt/sources.list.d/amnezia.list <<EOF
deb [signed-by=/etc/apt/keyrings/amnezia.gpg] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu jammy main
EOF
        fi
        apt-get update -qq
    fi
    # The PPA package "amneziawg" pulls in the kernel module via DKMS; if DKMS
    # cannot build (custom kernel), apt will fail and we fall back to the
    # userspace go implementation.
    if ! apt-get install -y -qq amneziawg amneziawg-tools 2>/dev/null \
        && ! apt-get install -y -qq amneziawg 2>/dev/null; then
        warn "Kernel module package failed; installing userspace amneziawg-go fallback."
        apt-get install -y -qq amneziawg-go amneziawg-tools \
            || die "Could not install amneziawg* packages from the PPA."
    fi
}

install_amneziawg_dnf() {
    local pm
    pm=$(command -v dnf || command -v yum)
    # Try the community COPR first.
    if "$pm" copr enable -y amneziavpn/amneziawg 2>/dev/null \
       || "$pm" copr enable -y dgoutay/amneziawg 2>/dev/null; then
        "$pm" install -y amneziawg amneziawg-tools 2>/dev/null \
            || "$pm" install -y amneziawg-tools amneziawg-go \
            || die "COPR repo enabled but package install failed."
    else
        warn "No COPR available; building from source (amneziawg-go + amneziawg-tools)."
        build_from_source
    fi
}

install_amneziawg_arch() {
    if pacman -Si amneziawg-tools >/dev/null 2>&1; then
        pacman -Sy --noconfirm --needed amneziawg-tools amneziawg-dkms 2>/dev/null \
            || pacman -Sy --noconfirm --needed amneziawg-tools amneziawg-go
    elif command -v yay >/dev/null 2>&1; then
        sudo -u "${SUDO_USER:-nobody}" yay -S --noconfirm amneziawg-tools amneziawg-dkms-git \
            || sudo -u "${SUDO_USER:-nobody}" yay -S --noconfirm amneziawg-tools amneziawg-go
    elif command -v paru >/dev/null 2>&1; then
        sudo -u "${SUDO_USER:-nobody}" paru -S --noconfirm amneziawg-tools amneziawg-dkms-git \
            || sudo -u "${SUDO_USER:-nobody}" paru -S --noconfirm amneziawg-tools amneziawg-go
    else
        warn "No AUR helper found; building from source."
        build_from_source
    fi
}

build_from_source() {
    local src="/usr/local/src/amneziawg" tools_repo go_repo
    tools_repo="https://github.com/amnezia-vpn/amneziawg-tools.git"
    go_repo="https://github.com/amnezia-vpn/amneziawg-go.git"

    if is_debian_like; then
        apt-get install -y -qq build-essential git make pkg-config libmnl-dev \
            golang-go iproute2
    elif is_rhel_like; then
        local pm; pm=$(command -v dnf || command -v yum)
        "$pm" install -y @development-tools git make libmnl-devel golang iproute pkgconf-pkg-config
    elif is_arch_like; then
        pacman -Sy --noconfirm --needed base-devel git libmnl go
    fi

    install -d -m 0755 "$src"

    # amneziawg-tools (provides awg, awg-quick, manpages, systemd unit)
    if [ ! -d "$src/amneziawg-tools" ]; then
        git -C "$src" clone --depth=1 "$tools_repo"
    else
        git -C "$src/amneziawg-tools" pull --ff-only || true
    fi
    make -C "$src/amneziawg-tools/src" -j"$(nproc)"
    make -C "$src/amneziawg-tools/src" install \
        WITH_BASHCOMPLETION=yes WITH_WGQUICK=yes WITH_SYSTEMDUNITS=yes

    # amneziawg-go (userspace implementation, picks up automatically when no kmod)
    if [ ! -d "$src/amneziawg-go" ]; then
        git -C "$src" clone --depth=1 "$go_repo"
    else
        git -C "$src/amneziawg-go" pull --ff-only || true
    fi
    ( cd "$src/amneziawg-go" && go build -o /usr/local/bin/amneziawg-go . )
    ln -sf /usr/local/bin/amneziawg-go /usr/bin/amneziawg-go
}

# ---------------------------------------------------------------------------
# Sysctl: enable forwarding (required) without overwriting unrelated keys.
# ---------------------------------------------------------------------------
configure_sysctl() {
    log "Enabling IP forwarding (drop-in: $SYSCTL_FILE)..."
    {
        echo "# Managed by ${SCRIPT_NAME}; safe to remove on uninstall."
        echo "net.ipv4.ip_forward = 1"
        echo "net.ipv4.conf.all.src_valid_mark = 1"
        if [ "$ENABLE_IPV6" = "1" ]; then
            echo "net.ipv6.conf.all.forwarding = 1"
            echo "net.ipv6.conf.default.forwarding = 1"
        fi
    } >"$SYSCTL_FILE"
    sysctl -q --load="$SYSCTL_FILE"
}

# ---------------------------------------------------------------------------
# nftables hook scripts run by awg-quick on PostUp/PostDown.
# We use dedicated tables ("amnezia_*") so we never conflict with an existing
# firewall (ufw, firewalld, iptables-nft, plain nftables).
# ---------------------------------------------------------------------------
write_nft_hooks() {
    local wan="$1"
    log "Writing nftables hook scripts (WAN iface: $wan)..."

    cat >"$HOOK_UP" <<EOF
#!/usr/bin/env bash
# Auto-generated by ${SCRIPT_NAME}. Loaded by awg-quick PostUp.
set -e
WAN="\${1:-$wan}"
NET4="$NET4"
NET6="$NET6"
IFACE="$IFACE"

# Forward chain: allow VPN <-> WAN, but never bridge VPN traffic to itself.
nft add table inet ${NFT_T_FWD} 2>/dev/null || true
nft -f - <<NFT
flush table inet ${NFT_T_FWD}
table inet ${NFT_T_FWD} {
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "\$IFACE" oifname "\$WAN" accept
    iifname "\$WAN" oifname "\$IFACE" ct state related,established accept
  }
}
NFT

# IPv4 NAT — masquerade only when the destination is NOT a local/private network,
# so the server's LAN stays unreachable from VPN clients (defence in depth) and
# we never NAT traffic that's already local.
nft add table ip ${NFT_T_NAT4} 2>/dev/null || true
nft -f - <<NFT
flush table ip ${NFT_T_NAT4}
table ip ${NFT_T_NAT4} {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr \$NET4 oifname "\$WAN" \\
        ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, \\
                      100.64.0.0/10, 169.254.0.0/16, 127.0.0.0/8, 224.0.0.0/4 } \\
        masquerade
  }
}
NFT
EOF

    if [ "$ENABLE_IPV6" = "1" ]; then
        cat >>"$HOOK_UP" <<EOF

# IPv6 NAT (NAT66) — same idea for ULA, link-local, multicast and loopback.
nft add table ip6 ${NFT_T_NAT6} 2>/dev/null || true
nft -f - <<NFT
flush table ip6 ${NFT_T_NAT6}
table ip6 ${NFT_T_NAT6} {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip6 saddr \$NET6 oifname "\$WAN" \\
        ip6 daddr != { fc00::/7, fe80::/10, ff00::/8, ::1/128 } \\
        masquerade
  }
}
NFT
EOF
    fi

    cat >"$HOOK_DOWN" <<EOF
#!/usr/bin/env bash
# Auto-generated by ${SCRIPT_NAME}. Loaded by awg-quick PostDown.
nft delete table inet ${NFT_T_FWD}  2>/dev/null || true
nft delete table ip   ${NFT_T_NAT4} 2>/dev/null || true
nft delete table ip6  ${NFT_T_NAT6} 2>/dev/null || true
exit 0
EOF

    chmod +x "$HOOK_UP" "$HOOK_DOWN"
}

# ---------------------------------------------------------------------------
# AmneziaWG server config
# ---------------------------------------------------------------------------
generate_server_config() {
    local server_priv server_pub
    log "Generating server keypair..."
    install -d -m 0700 "$AWG_DIR"
    server_priv=$(awg genkey)
    server_pub=$(printf '%s' "$server_priv" | awg pubkey)
    printf '%s' "$server_priv" >"$AWG_DIR/server.key"
    printf '%s' "$server_pub"  >"$AWG_DIR/server.pub"
    chmod 600 "$AWG_DIR/server.key"

    SERVER_PUB="$server_pub"

    log "Writing $AWG_CONF (port $PORT, obfuscation $OBFUSCATION)..."
    {
        echo "# Generated by ${SCRIPT_NAME} v${SCRIPT_VERSION} on $(date -u +%FT%TZ)"
        echo "[Interface]"
        echo "PrivateKey = $server_priv"
        echo "ListenPort = $PORT"
        if [ "$ENABLE_IPV6" = "1" ]; then
            echo "Address = ${SERVER_IP4}/${NET4_PREFIX}, ${SERVER_IP6}/${NET6_PREFIX}"
        else
            echo "Address = ${SERVER_IP4}/${NET4_PREFIX}"
        fi
        echo "MTU = $MTU"
        if [ "$OBFUSCATION" != "off" ]; then
            echo "Jc = $JC"
            echo "Jmin = $JMIN"
            echo "Jmax = $JMAX"
            echo "S1 = $S1"
            echo "S2 = $S2"
            echo "H1 = $H1"
            echo "H2 = $H2"
            echo "H3 = $H3"
            echo "H4 = $H4"
        fi
        echo "PostUp = $HOOK_UP"
        echo "PostDown = $HOOK_DOWN"
    } >"$AWG_CONF"
    chmod 600 "$AWG_CONF"
}

# ---------------------------------------------------------------------------
# Persist server metadata so add-client / show-client work later.
# ---------------------------------------------------------------------------
save_meta() {
    install -d -m 0700 "$STATE_DIR" "$CLIENTS_DIR"
    cat >"$META_FILE" <<EOF
# Generated by ${SCRIPT_NAME} — do not edit unless you know what you are doing.
HOST="$HOST"
PORT="$PORT"
SERVER_PUB="$SERVER_PUB"
NET4="$NET4"
NET6="$NET6"
NET4_PREFIX="$NET4_PREFIX"
NET6_PREFIX="$NET6_PREFIX"
SERVER_IP4="$SERVER_IP4"
SERVER_IP6="$SERVER_IP6"
DNS="$DNS"
MTU="$MTU"
ENABLE_IPV6="$ENABLE_IPV6"
OBFUSCATION="$OBFUSCATION"
JC="$JC"
JMIN="$JMIN"
JMAX="$JMAX"
S1="$S1"
S2="$S2"
H1="$H1"
H2="$H2"
H3="$H3"
H4="$H4"
EOF
    chmod 600 "$META_FILE"
}

load_meta() {
    [ -r "$META_FILE" ] || die "No installation found at $META_FILE; run '$0 install' first."
    # shellcheck disable=SC1090
    . "$META_FILE"
}

# ---------------------------------------------------------------------------
# Client peer management
# ---------------------------------------------------------------------------
next_client_octet4() {
    # Returns the next free host octet in NET4 starting from .2 (.1 is the server).
    local used n
    used=$(awg show "$IFACE" allowed-ips 2>/dev/null \
        | awk '{for(i=2;i<=NF;i++) print $i}' \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    for n in $(seq 2 254); do
        if ! grep -qx "${NET4%.*}.$n" <<<"$used"; then
            printf '%s' "$n"; return
        fi
    done
    die "No free addresses left in $NET4."
}

next_client_id6() {
    # Use the same trailing host id as the v4 address for symmetry.
    local octet="$1"
    printf '%s' "${NET6%::*}::$(printf '%x' "$octet")"
}

add_client() {
    local name="$1"
    [ -n "$name" ] || die "Usage: $0 add-client <name>"
    [[ "$name" =~ ^[a-zA-Z0-9_.-]{1,32}$ ]] \
        || die "Client name must match [a-zA-Z0-9_.-] (max 32 chars)."
    [ ! -e "$CLIENTS_DIR/${name}.conf" ] || die "Client '$name' already exists."

    load_meta

    local priv pub psk octet ip4 ip6 allowed_ips client_addr
    priv=$(awg genkey)
    pub=$(printf '%s' "$priv" | awg pubkey)
    psk=$(awg genpsk)
    octet=$(next_client_octet4)
    ip4="${NET4%.*}.$octet"
    if [ "$ENABLE_IPV6" = "1" ]; then
        ip6=$(next_client_id6 "$octet")
        client_addr="${ip4}/32, ${ip6}/128"
        allowed_ips="${ip4}/32, ${ip6}/128"
    else
        ip6=""
        client_addr="${ip4}/32"
        allowed_ips="${ip4}/32"
    fi

    # Append peer to server config and inject live without restarting the tunnel.
    {
        echo ""
        echo "# BEGIN_PEER $name"
        echo "[Peer]"
        echo "# friendly-name: $name"
        echo "PublicKey = $pub"
        echo "PresharedKey = $psk"
        echo "AllowedIPs = $allowed_ips"
        echo "# END_PEER $name"
    } >>"$AWG_CONF"

    if systemctl is-active --quiet "$SVC"; then
        # Live reconfigure: strip the script-only sections awg(8) doesn't grok and reload.
        local stripped
        stripped=$(awg-quick strip "$IFACE")
        printf '%s' "$stripped" | awg syncconf "$IFACE" /dev/stdin
    fi

    # Build the client config.
    local conf="$CLIENTS_DIR/${name}.conf"
    {
        echo "# AmneziaWG client config for '$name' — generated $(date -u +%FT%TZ)"
        echo "[Interface]"
        echo "PrivateKey = $priv"
        echo "Address = $client_addr"
        echo "DNS = $DNS"
        echo "MTU = $MTU"
        if [ "$OBFUSCATION" != "off" ]; then
            echo "Jc = $JC"
            echo "Jmin = $JMIN"
            echo "Jmax = $JMAX"
            echo "S1 = $S1"
            echo "S2 = $S2"
            echo "H1 = $H1"
            echo "H2 = $H2"
            echo "H3 = $H3"
            echo "H4 = $H4"
        fi
        echo ""
        echo "[Peer]"
        echo "PublicKey = $SERVER_PUB"
        echo "PresharedKey = $psk"
        if [ "$ENABLE_IPV6" = "1" ]; then
            echo "AllowedIPs = 0.0.0.0/0, ::/0"
        else
            echo "AllowedIPs = 0.0.0.0/0"
        fi
        echo "Endpoint = ${HOST}:${PORT}"
        echo "PersistentKeepalive = 25"
    } >"$conf"
    chmod 600 "$conf"

    log "Client '$name' added."
    info "Config: $conf"
    show_client_payload "$conf"
}

remove_client() {
    local name="$1"
    [ -n "$name" ] || die "Usage: $0 remove-client <name>"
    load_meta
    [ -f "$CLIENTS_DIR/${name}.conf" ] || die "No such client: $name"

    # Remove the BEGIN_PEER..END_PEER block from the server config.
    local tmp; tmp=$(mktemp)
    awk -v n="$name" '
        $0 == "# BEGIN_PEER " n { skip=1; next }
        $0 == "# END_PEER "   n { skip=0; next }
        !skip
    ' "$AWG_CONF" >"$tmp"
    mv "$tmp" "$AWG_CONF"
    chmod 600 "$AWG_CONF"

    if systemctl is-active --quiet "$SVC"; then
        # Reconcile the running interface with the freshly-edited config.
        awg syncconf "$IFACE" <(awg-quick strip "$IFACE")
    fi
    rm -f "$CLIENTS_DIR/${name}.conf"
    log "Client '$name' revoked."
}

list_clients() {
    load_meta
    [ -d "$CLIENTS_DIR" ] || { info "No clients configured."; return; }
    local count=0
    printf '%-24s %-18s %s\n' "NAME" "IPv4" "IPv6"
    for f in "$CLIENTS_DIR"/*.conf; do
        [ -e "$f" ] || break
        local name addr v4 v6
        name=$(basename "$f" .conf)
        addr=$(awk -F'= *' '/^Address/ {print $2; exit}' "$f")
        v4=$(printf '%s' "$addr" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
        v6=$(printf '%s' "$addr" | grep -oE '[0-9a-fA-F:]+:+[0-9a-fA-F:]+' | head -n1)
        printf '%-24s %-18s %s\n' "$name" "${v4:--}" "${v6:--}"
        count=$((count+1))
    done
    [ "$count" -gt 0 ] || info "No clients configured."
}

show_client() {
    local name="$1"
    [ -n "$name" ] || die "Usage: $0 show-client <name>"
    load_meta
    [ -f "$CLIENTS_DIR/${name}.conf" ] || die "No such client: $name"
    show_client_payload "$CLIENTS_DIR/${name}.conf"
}

show_client_payload() {
    local conf="$1"
    info "----- Client config (${conf}) -----"
    cat "$conf"
    if command -v qrencode >/dev/null 2>&1; then
        info "----- QR code (scan with the AmneziaVPN client) -----"
        qrencode -t ansiutf8 <"$conf"
    else
        warn "qrencode not installed; skipping QR rendering."
    fi
}

# ---------------------------------------------------------------------------
# Status / uninstall
# ---------------------------------------------------------------------------
status() {
    load_meta || true
    info "Service: $SVC"
    systemctl --no-pager --full status "$SVC" 2>/dev/null | sed -n '1,8p' || true
    echo
    if command -v awg >/dev/null 2>&1 && ip link show "$IFACE" >/dev/null 2>&1; then
        awg show "$IFACE"
    else
        warn "Interface $IFACE is not up."
    fi
    echo
    info "nftables tables (amnezia_*):"
    nft list tables 2>/dev/null | grep -E 'amnezia_' || info "(none loaded)"
}

uninstall() {
    local purge=0
    [ "${1:-}" = "--purge" ] && purge=1

    log "Stopping $SVC..."
    systemctl disable --now "$SVC" 2>/dev/null || true

    log "Tearing down nftables tables..."
    nft delete table inet "$NFT_T_FWD"  2>/dev/null || true
    nft delete table ip   "$NFT_T_NAT4" 2>/dev/null || true
    nft delete table ip6  "$NFT_T_NAT6" 2>/dev/null || true

    log "Removing sysctl drop-in..."
    rm -f "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true

    log "Removing hook scripts..."
    rm -f "$HOOK_UP" "$HOOK_DOWN"

    if [ "$purge" -eq 1 ]; then
        warn "Purging $AWG_DIR and $STATE_DIR (all keys + client configs)..."
        rm -rf "$AWG_DIR" "$STATE_DIR"
    else
        info "Keeping $AWG_DIR and $STATE_DIR (use --purge to remove keys/configs)."
    fi
    log "Uninstall complete. AmneziaWG packages were left installed."
}

# ---------------------------------------------------------------------------
# Interactive install flow
# ---------------------------------------------------------------------------
prompt_obfuscation() {
    local choice
    choice=$(ask_choice "Select obfuscation profile:" 2 \
        "off          (plain WireGuard handshake — minimal CPU, no DPI evasion)" \
        "standard    (junk packets + randomised handshake magic — recommended)" \
        "aggressive  (heavy junk + padded handshake — best vs DPI, slightly higher overhead)")
    case "$choice" in
        off*)        printf '%s' off ;;
        standard*)   printf '%s' standard ;;
        aggressive*) printf '%s' aggressive ;;
    esac
}

apply_obfuscation_preset() {
    local preset="$1"
    JC=0; JMIN=0; JMAX=0; S1=0; S2=0; H1=1; H2=2; H3=3; H4=4
    case "$preset" in
        off)
            : ;;
        standard)
            JC=$(rand_in_range 4 6)
            JMIN=$(rand_in_range 8 40)
            JMAX=$(rand_in_range 80 120)
            S1=0; S2=0
            read -r H1 H2 H3 H4 <<<"$(rand_h_quad)"
            ;;
        aggressive)
            JC=$(rand_in_range 6 10)
            JMIN=$(rand_in_range 40 80)
            JMAX=$(rand_in_range 600 1200)
            # S1 + 56 ≠ S2 per AmneziaWG kernel module spec.
            while :; do
                S1=$(rand_in_range 15 150)
                S2=$(rand_in_range 15 150)
                [ $((S1 + 56)) -ne "$S2" ] && break
            done
            read -r H1 H2 H3 H4 <<<"$(rand_h_quad)"
            ;;
        *) die "Unknown obfuscation preset: $preset" ;;
    esac
}

cidr_address() {
    # cidr_address 10.66.66.0/24 1   -> 10.66.66.1
    local cidr="$1" host="$2" base
    base="${cidr%/*}"
    printf '%s.%s' "${base%.*}" "$host"
}

cidr6_address() {
    local cidr="$1" host="$2" base
    base="${cidr%/*}"
    base="${base%::*}"
    printf '%s::%x' "$base" "$host"
}

cidr_prefix()  { local c="$1"; printf '%s' "${c#*/}"; }

do_install() {
    need_root
    detect_os
    info "Detected OS: $PRETTY_NAME"

    maybe_cleanup_existing

    # ---- gather inputs ------------------------------------------------------
    local detected_ip4 detected_ip6 default_host wan
    detected_ip4=$(detect_public_ip4 || true)
    detected_ip6=$(detect_public_ip6 || true)
    default_host="${AMNEZIA_HOST:-${detected_ip4:-${detected_ip6:-}}}"

    HOST=$(ask "Public IP or DNS name clients should connect to" "$default_host")
    [ -n "$HOST" ] || die "Public host is required."

    # ----- Port --------------------------------------------------------------
    local suggested_port="${AMNEZIA_PORT:-$(suggest_port)}"
    info "Tip: ports 80, 443 (UDP) sometimes get less DPI scrutiny on hostile networks."
    PORT=$(ask "UDP listen port (current free suggestion below)" "$suggested_port")
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        die "Invalid port: $PORT"
    fi
    if is_port_in_use "$PORT"; then
        warn "Port $PORT is currently in use on this host."
        ask_yn "Use it anyway?" "n" || die "Pick a different port and re-run."
    fi

    # ----- IPv6 --------------------------------------------------------------
    local v6_default="auto"
    case "${AMNEZIA_ENABLE_IPV6:-auto}" in
        yes) ENABLE_IPV6=1 ;;
        no)  ENABLE_IPV6=0 ;;
        *)
            if has_global_ipv6; then
                v6_default="y"
            else
                v6_default="n"
                info "No global IPv6 detected on this host."
            fi
            if ask_yn "Enable IPv6 inside the VPN?" "$v6_default"; then
                ENABLE_IPV6=1
            else
                ENABLE_IPV6=0
            fi
            ;;
    esac

    # ----- Networks ----------------------------------------------------------
    NET4="${AMNEZIA_NET4:-10.66.66.0/24}"
    NET6="${AMNEZIA_NET6:-fd86:ea04:1115::/64}"
    NET4_PREFIX=$(cidr_prefix "$NET4")
    NET6_PREFIX=$(cidr_prefix "$NET6")
    SERVER_IP4=$(cidr_address "$NET4" 1)
    SERVER_IP6=$(cidr6_address "$NET6" 1)
    DNS="${AMNEZIA_DNS:-1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001}"
    MTU="${AMNEZIA_MTU:-1280}"

    # ----- Obfuscation -------------------------------------------------------
    if [ -n "${AMNEZIA_OBFUSCATION:-}" ]; then
        OBFUSCATION="$AMNEZIA_OBFUSCATION"
    else
        OBFUSCATION=$(prompt_obfuscation)
    fi
    apply_obfuscation_preset "$OBFUSCATION"

    # ----- WAN iface ---------------------------------------------------------
    wan=$(detect_default_iface || true)
    [ -n "$wan" ] || wan="eth0"
    wan=$(ask "Egress (WAN) interface for NAT" "$wan")
    ip link show "$wan" >/dev/null 2>&1 || warn "Interface '$wan' not found right now; will be used at service start."

    # ---- summary ------------------------------------------------------------
    cat <<EOF

${C_BOLD}Installation summary${C_RST}
  Public endpoint : ${HOST}:${PORT}/udp
  WAN interface   : ${wan}
  IPv4 VPN net    : ${NET4} (server ${SERVER_IP4})
  IPv6 VPN net    : $([ "$ENABLE_IPV6" = "1" ] && echo "${NET6} (server ${SERVER_IP6})" || echo disabled)
  DNS pushed      : ${DNS}
  MTU             : ${MTU}
  Obfuscation     : ${OBFUSCATION}$([ "$OBFUSCATION" != "off" ] && printf ' (Jc=%s Jmin=%s Jmax=%s S1=%s S2=%s)' "$JC" "$JMIN" "$JMAX" "$S1" "$S2")

EOF
    ask_yn "Proceed?" "y" || die "Aborted by user."

    # ---- do the work --------------------------------------------------------
    install_prereqs
    install_amneziawg
    configure_sysctl
    write_nft_hooks "$wan"
    generate_server_config
    save_meta

    # Make sure the awg-quick unit picks up our config.
    systemctl daemon-reload
    systemctl enable --now "$SVC"
    sleep 1
    systemctl is-active --quiet "$SVC" \
        || die "$SVC failed to start. Inspect: journalctl -u $SVC -n 40 --no-pager"

    # ---- first client -------------------------------------------------------
    local first_client="${AMNEZIA_CLIENT_NAME:-client1}"
    if [ ! -e "$CLIENTS_DIR/${first_client}.conf" ]; then
        log "Creating first client '${first_client}'..."
        add_client "$first_client"
    fi

    # ---- stage a copy of ourselves for later subcommands & self-update ------
    install_self_to_state

    cat <<EOF

${C_GRN}AmneziaWG server is up.${C_RST}
  Service       : ${SVC}  ($(systemctl is-active "$SVC"))
  Endpoint      : ${HOST}:${PORT}/udp
  Server pub    : ${SERVER_PUB}
  Local script  : ${INSTALLED_SELF}  (also at ${SYMLINK})

Next steps:
  • Open UDP/${PORT} inbound on any cloud-provider firewall.
  • To add another client:    sudo ${SCRIPT_NAME} add-client <name>
  • To list clients:           sudo ${SCRIPT_NAME} list-clients
  • To revoke a client:        sudo ${SCRIPT_NAME} remove-client <name>
  • To check status:           sudo ${SCRIPT_NAME} status
  • To force an update check:  sudo ${SCRIPT_NAME} self-update --force
  • To uninstall:              sudo ${SCRIPT_NAME} uninstall [--purge]
EOF
}

# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
${SCRIPT_NAME} v${SCRIPT_VERSION}

Quick install (always pulls the latest from the main branch):
  # Non-interactive one-liner (all defaults; override with AMNEZIA_* env):
  curl -fsSL https://raw.githubusercontent.com/maciekish/amnezia-installer/main/amnezia-installer.sh | sudo bash

  # Interactive (keeps the TTY so prompts work):
  sudo bash -c "\$(curl -fsSL https://raw.githubusercontent.com/maciekish/amnezia-installer/main/amnezia-installer.sh)"

Usage:
  sudo $0 [install]                  # interactive install (default)
  sudo $0 add-client    <name>
  sudo $0 remove-client <name>
  sudo $0 list-clients
  sudo $0 show-client   <name>
  sudo $0 status
  sudo $0 self-update [--force]      # force a network check + re-exec
  sudo $0 version
  sudo $0 uninstall [--purge]

After install the script lives at ${INSTALLED_SELF}
and is symlinked at ${SYMLINK}, so 'sudo ${SCRIPT_NAME} <cmd>' works directly.
The script auto-checks for updates against the URL above (cached for 24 h).
Set AMNEZIA_NO_UPDATE_CHECK=1 to suppress; AMNEZIA_FORCE_CLEANUP=1 to skip the
existing-install-detection prompt during reinstalls.

See the comment header at the top of this script for non-interactive env vars.
EOF
}

main() {
    local cmd="${1:-install}"

    # Skip the network call for read-only / destructive / help commands. For
    # everything else, opportunistically self-update (cached for a day).
    case "$cmd" in
        -h|--help|help|version|--version|uninstall|status|list-clients) ;;
        *) self_update "$@" ;;
    esac

    case "$cmd" in
        install)
            shift || true
            do_install "$@"
            ;;
        add-client)
            need_root; shift; add_client "${1:-}"
            ;;
        remove-client)
            need_root; shift; remove_client "${1:-}"
            ;;
        list-clients)
            need_root; list_clients
            ;;
        show-client)
            need_root; shift; show_client "${1:-}"
            ;;
        status)
            need_root; status
            ;;
        uninstall)
            need_root; shift; uninstall "${1:-}"
            ;;
        self-update)
            need_root; shift; self_update --force "$@"
            info "Already running ${SCRIPT_VERSION}; nothing newer found."
            ;;
        version|--version)
            printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            err "Unknown subcommand: $cmd"; usage; exit 2
            ;;
    esac
}

# Make `curl -fsSL ... | sudo bash` actually interactive: when our stdin is the
# pipe carrying the script source (so `read` would hit the script bytes), but a
# controlling terminal can actually be opened, redirect the *main* invocation's
# stdin from /dev/tty so prompts read the user's keyboard. We probe with a
# subshell open instead of `[ -r /dev/tty ]` because the latter reports true on
# unopenable tty device nodes (containers, CI runners, cron, systemd units).
# The redirect is local to the main call — bash's own script-source stdin (the
# pipe) stays intact, so the parser won't suddenly start reading commands from
# the user's tty after main returns.
if [ ! -t 0 ] && ( : </dev/tty ) 2>/dev/null; then
    main "$@" </dev/tty
else
    main "$@"
fi
