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
#   AMNEZIA_PORT=<port>[,<port>] primary UDP listen port, optionally followed by
#                                comma-separated alias ports that are DNAT-redirected
#                                to the primary (e.g. AMNEZIA_PORT=51820,443).
#                                Clients can connect on any alias port.
#   AMNEZIA_OBFUSCATION=off|standard|aggressive
#   AMNEZIA_CLIENT_NAME=<csv>    comma-separated list of clients to create on install
#                                (default: client1). Only the FIRST one is rendered
#                                + QR'd at the end; the rest live under
#                                /var/lib/amnezia-installer/clients/.
#   AMNEZIA_ENABLE_IPV6=auto|yes|no
#   AMNEZIA_NET4=10.66.66.0/24
#   AMNEZIA_NET6=fd86:ea04:1115::/64
#   AMNEZIA_DNS="1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001"
#   AMNEZIA_MTU=1280
#   AMNEZIA_MANAGE_IPTABLES=1|0  1 = add iptables INPUT/FORWARD/DNAT rules (default in
#                                interactive and non-interactive); 0 = skip iptables entirely
#   AMNEZIA_ENABLE_UPNP=1|0      1 = install miniupnpc and keep UPnP UDP forwards
#                                for all VPN ports refreshed by a systemd timer
#                                (default: 0 / prompted as "n")
#   AMNEZIA_UPNP_ROOT_URL=<url>  optional UPnP IGD XML root description URL
#                                (e.g. http://192.168.1.1:5000/rootDesc.xml)
#                                used with upnpc -u when SSDP discovery is flaky
#   AMNEZIA_NO_UPDATE_CHECK=1    skip the on-startup self-update check
#   AMNEZIA_FORCE_CLEANUP=1      auto-clean any existing AmneziaWG install before reinstalling
#   AMNEZIA_NO_SHELL_DROP=1      do not exec $SHELL at /var/lib/amnezia-installer on completion
#   AMNEZIA_SECURE_BOOT_MOK=1|0  1 = queue Ubuntu MOK enrollment when Secure Boot rejects
#                                the DKMS module; requires reboot + boot console.
#
# Client config files are saved as <host>-<clientname>.conf (e.g.
# "vpn.example.com-maciej.conf") so a bulk import into the AmneziaVPN client
# stays self-describing. This is the only filename format the script knows
# about; pre-1.2 unprefixed files are not migrated.
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
readonly SCRIPT_VERSION="1.4.5"
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
readonly UPNP_SCRIPT="${STATE_DIR}/upnp-refresh.sh"
readonly UPNP_SERVICE="/etc/systemd/system/${SCRIPT_NAME}-upnp.service"
readonly UPNP_TIMER="/etc/systemd/system/${SCRIPT_NAME}-upnp.timer"
readonly HOOK_UP="${AWG_DIR}/${IFACE}.up.sh"
readonly HOOK_DOWN="${AWG_DIR}/${IFACE}.down.sh"
readonly NFT_T_FWD="amnezia_fwd"
readonly NFT_T_NAT4="amnezia_nat4"
readonly NFT_T_NAT6="amnezia_nat6"
readonly UPDATE_URL="https://raw.githubusercontent.com/maciekish/amnezia-installer/main/amnezia-installer.sh"
readonly UPDATE_CACHE_SECONDS=86400  # only hit the network once a day
readonly UPNP_ROOT_URL_EXAMPLE="http://192.168.1.1:5000/rootDesc.xml"
readonly UBUNTU_MOK_DIR="/var/lib/shim-signed/mok"
readonly UBUNTU_MOK_DER="${UBUNTU_MOK_DIR}/MOK.der"
readonly UBUNTU_MOK_PRIV="${UBUNTU_MOK_DIR}/MOK.priv"

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

ask_placeholder() {
    # ask_placeholder "question" "placeholder" -> echoes the answer, or empty if skipped.
    local prompt="$1" placeholder="${2-}" reply=""
    if [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ] || [ ! -t 0 ]; then
        printf ''
        return
    fi
    if [ -n "$placeholder" ]; then
        read -r -p "$prompt [$placeholder]: " reply || reply=""
    else
        read -r -p "$prompt: " reply || reply=""
    fi
    printf '%s' "$reply"
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
    [ -e "$UPNP_SCRIPT" ] || [ -e "$UPNP_SERVICE" ] || [ -e "$UPNP_TIMER" ] \
        && found+=("UPnP refresh service/timer")
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

    # Load meta before anything else so remove_iptables_rules knows what to clean.
    # shellcheck disable=SC1090
    [ -r "$META_FILE" ] && . "$META_FILE" 2>/dev/null || true

    systemctl disable --now "$SVC" 2>/dev/null || true

    nft delete table inet "$NFT_T_FWD"  2>/dev/null || true
    nft delete table ip   "$NFT_T_NAT4" 2>/dev/null || true
    nft delete table ip6  "$NFT_T_NAT6" 2>/dev/null || true

    remove_upnp_port_forwards
    remove_iptables_rules

    if ip link show "$IFACE" >/dev/null 2>&1; then
        # If the unit didn't manage to bring the link down (e.g. failed state),
        # bring the interface down ourselves — but only if it's named exactly
        # awg0, never any other interface.
        ip link set "$IFACE" down 2>/dev/null || true
        ip link delete "$IFACE" 2>/dev/null || true
    fi

    rm -f "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true

    log "Removing UPnP refresh units..."
    rm -f "$UPNP_SCRIPT" "$UPNP_SERVICE" "$UPNP_TIMER"
    systemctl daemon-reload 2>/dev/null || true

    rm -f "$HOOK_UP" "$HOOK_DOWN" "$AWG_CONF"
    rm -f "$AWG_DIR/server.key" "$AWG_DIR/server.pub"
    # Only remove $AWG_DIR if we created it and it's now empty — never recursive.
    rmdir "$AWG_DIR" 2>/dev/null || true
    rmdir "$(dirname "$AWG_DIR")" 2>/dev/null || true

    rm -rf "$STATE_DIR"
    log "Cleanup complete."
}

maybe_cleanup_existing() {
    # Called from do_install. If we find AmneziaWG artefacts:
    #   - in interactive mode, drop into the menu (where the user can manage
    #     clients, inspect status, or pick "cleanup and reinstall");
    #   - in non-interactive mode, only proceed when AMNEZIA_FORCE_CLEANUP=1,
    #     never silently nuke an existing install.
    local findings
    findings=$(detect_existing_awg || true)
    [ -z "$findings" ] && return 0

    warn "Existing AmneziaWG artefacts detected:"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        printf '  - %s\n' "$line" >&2
    done <<<"$findings"

    info "(Stock WireGuard, /etc/wireguard/, wg-quick@*, and any other VPNs will NOT be touched.)"

    if [ "${AMNEZIA_FORCE_CLEANUP:-0}" = "1" ]; then
        cleanup_existing_awg
        return 0
    fi
    if [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ]; then
        warn "Non-interactive mode and AMNEZIA_FORCE_CLEANUP not set; aborting to avoid stomping."
        die "Set AMNEZIA_FORCE_CLEANUP=1 to auto-clean, or run '$0 uninstall --purge' first."
    fi

    # Interactive: hand off to the menu. It either calls back to the caller
    # (return 0 == "user picked Reinstall, please clean up") or exits the
    # script outright on Uninstall / Exit / etc.
    if existing_install_menu; then
        cleanup_existing_awg
    else
        # The menu indicated "user is done with this run, do not reinstall".
        exit 0
    fi
}

# ---------------------------------------------------------------------------
# Interactive management menu shown when the script is invoked on a host that
# already has an AmneziaWG install. Most options just call the corresponding
# subcommand handler and loop back; "Cleanup and reinstall" returns 0 so the
# caller proceeds with a fresh install; everything else exits the script.
# ---------------------------------------------------------------------------
existing_install_menu() {
    # Best-effort: try to load the meta file so the client-mgmt actions have
    # HOST/PORT/keys handy. When meta is missing or unreadable, those options
    # would die inside load_meta — so we build the option list dynamically and
    # only expose the universal entries (Cleanup / Uninstall / Uninstall+purge
    # / Exit) in that degraded state.
    local has_meta=0
    if [ -r "$META_FILE" ]; then
        # shellcheck disable=SC1090
        if . "$META_FILE" 2>/dev/null; then
            has_meta=1
        fi
    fi
    if [ "$has_meta" -ne 1 ]; then
        warn "Server metadata at $META_FILE is missing or unreadable —"
        warn "client-management options will be hidden until you reinstall."
    fi

    while :; do
        echo
        local opts=()
        if [ "$has_meta" -eq 1 ]; then
            opts+=(
                "Add client(s)                    (comma-separated names accepted)"
                "List clients"
                "Show a client's config + QR code"
                "Remove a client"
                "Show server status"
            )
        fi
        opts+=(
            "Cleanup and reinstall            (regenerates ALL keys; current clients become invalid)"
            "Uninstall                        (stop service, keep keys/clients in /var/lib)"
            "Uninstall and purge              (remove everything, including keys/clients)"
            "Exit"
        )

        local choice
        choice=$(ask_choice "An AmneziaWG installation already exists. What would you like to do?" 1 "${opts[@]}")
        case "$choice" in
            "Add client(s)"*)
                local names first_path
                names=$(ask "Client name(s), comma-separated" "client1")
                first_path=$(add_clients_from_csv "$names")
                info "Done. Configs are in $CLIENTS_DIR — use 'Show a client's config' to print/QR any of them."
                if [ -n "$first_path" ] && ask_yn "Show + QR the first client's config now?" "y"; then
                    show_client_payload "$first_path"
                fi
                ;;
            "List clients")
                list_clients
                ;;
            "Show a client's config"*)
                list_clients
                local name
                name=$(ask "Client name to show" "")
                [ -n "$name" ] && show_client "$name"
                ;;
            "Remove a client")
                local name
                name=$(ask "Client name to revoke" "")
                if [ -n "$name" ] && ask_yn "Really revoke '$name'?" "n"; then
                    remove_client "$name"
                fi
                ;;
            "Show server status")
                status
                ;;
            "Cleanup and reinstall"*)
                if ask_yn "Confirm: ALL existing keys and clients will be regenerated. Continue?" "n"; then
                    return 0
                fi
                ;;
            "Uninstall and purge"*)
                if ask_yn "Confirm: remove the server AND wipe all keys/clients?" "n"; then
                    uninstall --purge
                    exit 0
                fi
                ;;
            "Uninstall"*)
                uninstall
                exit 0
                ;;
            "Exit")
                return 1
                ;;
        esac
    done
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
            software-properties-common gpg jq kmod
        if [ "${ENABLE_UPNP:-0}" = "1" ]; then
            apt-get install -y -qq miniupnpc
        fi
    elif is_rhel_like; then
        local pm
        pm=$(command -v dnf || command -v yum)
        "$pm" install -y curl ca-certificates iproute nftables qrencode jq \
            'dnf-command(copr)' || "$pm" install -y curl iproute nftables qrencode jq
        if [ "${ENABLE_UPNP:-0}" = "1" ]; then
            "$pm" install -y miniupnpc
        fi
    elif is_arch_like; then
        pacman -Sy --noconfirm --needed curl ca-certificates iproute2 nftables qrencode jq
        if [ "${ENABLE_UPNP:-0}" = "1" ]; then
            pacman -Sy --noconfirm --needed miniupnpc
        fi
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
    ensure_amneziawg_runtime
}

apt_pkg_available() {
    apt-cache show "$1" >/dev/null 2>&1
}

running_kernel() {
    uname -r
}

latest_installed_kernel() {
    # Prefer the modules tree because it works across generic, cloud, lowlatency,
    # and vendor-flavoured kernels without hard-coding package names.
    find /lib/modules -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null \
        | sort -V \
        | tail -n1
}

kernel_headers_ready() {
    local kernel="${1:-$(running_kernel)}"
    [ -e "/lib/modules/${kernel}/build" ]
}

install_debian_kernel_build_prereqs() {
    local kernel headers_pkg packages=()
    kernel=$(running_kernel)
    headers_pkg="linux-headers-${kernel}"

    # DKMS needs a compiler toolchain and headers for the *running* kernel.  APT
    # may install a newer kernel during normal upgrades; that is not enough until
    # the host has rebooted into it.
    packages+=(dkms build-essential)
    if kernel_headers_ready "$kernel"; then
        info "Kernel headers present for running kernel $kernel."
    elif apt_pkg_available "$headers_pkg"; then
        packages+=("$headers_pkg")
    else
        warn "APT cannot find $headers_pkg for the running kernel $kernel."
        warn "If DKMS cannot build AmneziaWG, reboot into an installed kernel with headers or install matching headers manually."
    fi

    apt-get install -y -qq "${packages[@]}"
}

secure_boot_state() {
    if command -v mokutil >/dev/null 2>&1; then
        mokutil --sb-state 2>/dev/null | head -n1 || true
        return 0
    fi

    local sbvar bytes value
    sbvar=$(find /sys/firmware/efi/efivars -maxdepth 1 -name 'SecureBoot-*' -print -quit 2>/dev/null || true)
    [ -r "$sbvar" ] || return 0

    # efivarfs prepends four attribute bytes; the fifth byte is the SecureBoot
    # value (1 = enabled, 0 = disabled). This is a fallback for minimal servers
    # where mokutil is not installed.
    bytes=$(od -An -t u1 -N5 "$sbvar" 2>/dev/null || true)
    value=$(printf '%s\n' "$bytes" | awk '{print $5; exit}')
    case "$value" in
        1) printf '%s\n' "SecureBoot enabled (from efivarfs)" ;;
        0) printf '%s\n' "SecureBoot disabled (from efivarfs)" ;;
    esac
}

modprobe_key_rejected() {
    case "${1:-}" in
        *"Key was rejected"*|*"Required key not available"*) return 0 ;;
    esac
    return 1
}

prepare_secure_boot_mok_enrollment() {
    is_debian_like || { warn "Automatic MOK preparation is currently implemented only for Debian/Ubuntu systems."; return 1; }

    log "Preparing Ubuntu MOK enrollment for Secure Boot module loading..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq mokutil shim-signed dkms kmod \
        || { warn "Could not install mokutil/shim-signed; cannot queue MOK enrollment automatically."; return 1; }

    if ! command -v update-secureboot-policy >/dev/null 2>&1; then
        warn "update-secureboot-policy is unavailable; cannot create/enroll Ubuntu's DKMS MOK automatically."
        return 1
    fi

    if [ ! -r "$UBUNTU_MOK_DER" ] || [ ! -r "$UBUNTU_MOK_PRIV" ]; then
        info "No Ubuntu DKMS MOK found at $UBUNTU_MOK_DIR; generating one."
        update-secureboot-policy --new-key \
            || { warn "Could not generate Ubuntu DKMS MOK keypair."; return 1; }
    fi

    # Re-run DKMS now that the Ubuntu MOK exists so the installed module is
    # signed with the key the user will enroll on next boot. This is harmless
    # if DKMS has already signed it with the same key.
    if command -v dkms >/dev/null 2>&1; then
        info "Re-running DKMS autoinstall for $(running_kernel) so modules are signed with the Ubuntu MOK."
        dkms autoinstall -k "$(running_kernel)" || warn "DKMS autoinstall reported an error; check 'dkms status' and /var/lib/dkms logs."
    fi

    if mokutil --test-key "$UBUNTU_MOK_DER" >/dev/null 2>&1; then
        info "Ubuntu DKMS MOK is already enrolled; retrying modprobe may succeed after DKMS signing completes."
        return 0
    fi

    warn "A trusted key cannot be added to Secure Boot from the running OS alone."
    warn "This command can only queue enrollment; shim/MokManager must confirm it during the next boot."
    warn "You do NOT need BIOS setup, but you do need boot-console access (cloud serial/VNC/IPMI/hosting rescue console)."
    warn "When prompted now, choose a one-time password; after reboot pick: Enroll MOK -> Continue -> Yes -> enter that password -> Reboot."

    if ! update-secureboot-policy --enroll-key; then
        warn "Ubuntu enrollment helper failed; falling back to direct mokutil import."
        mokutil --import "$UBUNTU_MOK_DER" || { warn "Could not queue MOK enrollment."; return 1; }
    fi

    warn "MOK enrollment is queued. Reboot and complete MokManager to make the kernel trust DKMS-signed modules."
    return 0
}

maybe_prepare_secure_boot_fix() {
    local modprobe_hint="${1:-}"
    modprobe_key_rejected "$modprobe_hint" || return 0

    case "${AMNEZIA_SECURE_BOOT_MOK:-auto}" in
        1|yes|true|enroll)
            prepare_secure_boot_mok_enrollment || true
            ;;
        0|no|false|skip)
            warn "Secure Boot MOK enrollment skipped (AMNEZIA_SECURE_BOOT_MOK=0)."
            ;;
        auto|"")
            if [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ] || [ ! -t 0 ]; then
                warn "Set AMNEZIA_SECURE_BOOT_MOK=1 and run from a TTY to queue MOK enrollment for the kernel module."
            elif ask_yn "Queue Ubuntu MOK enrollment to fix Secure Boot module rejection on next reboot?" "y"; then
                prepare_secure_boot_mok_enrollment || true
            else
                warn "MOK enrollment skipped; using userspace fallback for this install."
            fi
            ;;
        *)
            warn "Unknown AMNEZIA_SECURE_BOOT_MOK value '${AMNEZIA_SECURE_BOOT_MOK}'; expected 1/0/auto."
            ;;
    esac
}

print_amneziawg_runtime_diagnostics() {
    local kernel latest headers_pkg dkms_lines modprobe_hint="${1:-}"
    kernel=$(running_kernel)
    latest=$(latest_installed_kernel || true)
    headers_pkg="linux-headers-${kernel}"

    err "AmneziaWG runtime is unavailable for the running kernel ($kernel)."
    err "The service cannot create '$IFACE' because 'ip link add $IFACE type amneziawg' is unsupported."
    if [ -n "$modprobe_hint" ]; then
        warn "modprobe amneziawg failed with: $modprobe_hint"
        case "$modprobe_hint" in
            *"Key was rejected"*|*"Required key not available"*)
                local sb_state
                sb_state=$(secure_boot_state || true)
                [ -n "$sb_state" ] && warn "Secure Boot state: $sb_state"
                warn "The DKMS module exists, but the kernel rejected its signature/key."
                warn "With Secure Boot enabled, enroll the DKMS/MOK signing key or disable Secure Boot to load the kernel module."
                warn "The installer will use amneziawg-go instead because it does not require loading an out-of-tree kernel module."
                ;;
        esac
    fi

    if [ -n "$latest" ] && [ "$latest" != "$kernel" ]; then
        warn "A different kernel appears installed: $latest. Reboot into it, then rerun this installer."
    fi

    if is_debian_like; then
        if ! kernel_headers_ready "$kernel"; then
            if apt_pkg_available "$headers_pkg"; then
                warn "Missing headers for the running kernel. Install them with: apt-get install $headers_pkg"
            else
                warn "No installable $headers_pkg package was found in the enabled APT repositories."
            fi
        fi
        if command -v dkms >/dev/null 2>&1; then
            dkms_lines=$(dkms status 2>/dev/null | grep -i 'amneziawg' || true)
            if [ -n "$dkms_lines" ]; then
                warn "DKMS status for AmneziaWG:"
                printf '%s\n' "$dkms_lines" >&2
            else
                warn "DKMS has no registered AmneziaWG build for this kernel."
            fi
        fi
    fi

    if command -v modinfo >/dev/null 2>&1 && modinfo amneziawg >/dev/null 2>&1; then
        warn "modinfo can see an amneziawg module, but modprobe failed. Check: modprobe -v amneziawg"
    else
        warn "No loadable amneziawg kernel module was found for $kernel."
    fi
}

amneziawg_userspace_available() {
    command -v "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" >/dev/null 2>&1
}

build_amneziawg_go_from_source() {
    local src="/usr/local/src/amneziawg" go_repo
    go_repo="https://github.com/amnezia-vpn/amneziawg-go.git"

    warn "Building amneziawg-go userspace fallback from source."
    if is_debian_like; then
        apt-get install -y -qq build-essential git golang-go iproute2
    elif is_rhel_like; then
        local pm; pm=$(command -v dnf || command -v yum)
        "$pm" install -y @development-tools git golang iproute
    elif is_arch_like; then
        pacman -Sy --noconfirm --needed base-devel git go
    fi

    install -d -m 0755 "$src"
    if [ ! -d "$src/amneziawg-go" ]; then
        git -C "$src" clone --depth=1 "$go_repo"
    else
        git -C "$src/amneziawg-go" pull --ff-only || true
    fi
    ( cd "$src/amneziawg-go" && go build -o /usr/local/bin/amneziawg-go . )
    ln -sf /usr/local/bin/amneziawg-go /usr/bin/amneziawg-go
}

install_amneziawg_userspace_fallback() {
    amneziawg_userspace_available && return 0

    warn "Installing amneziawg-go userspace fallback."
    if is_debian_like; then
        if apt_pkg_available amneziawg-go; then
            apt-get install -y -qq amneziawg-go amneziawg-tools \
                || build_amneziawg_go_from_source
        else
            build_amneziawg_go_from_source
        fi
    elif is_rhel_like; then
        local pm; pm=$(command -v dnf || command -v yum)
        "$pm" install -y amneziawg-go 2>/dev/null || build_amneziawg_go_from_source
    elif is_arch_like; then
        pacman -Sy --noconfirm --needed amneziawg-go 2>/dev/null || build_amneziawg_go_from_source
    else
        build_amneziawg_go_from_source
    fi

    amneziawg_userspace_available \
        || die "Could not install amneziawg-go userspace fallback."
}

ensure_amneziawg_runtime() {
    log "Checking AmneziaWG runtime support..."

    if lsmod 2>/dev/null | grep -q '^amneziawg[[:space:]]'; then
        info "AmneziaWG kernel module is already loaded."
        return 0
    fi

    local modprobe_out=""
    if command -v modprobe >/dev/null 2>&1; then
        if modprobe_out=$(modprobe amneziawg 2>&1); then
            info "Loaded AmneziaWG kernel module for $(running_kernel)."
            return 0
        fi
        modprobe_out=$(printf '%s' "$modprobe_out" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')
    fi

    if amneziawg_userspace_available; then
        warn "AmneziaWG kernel module is unavailable; awg-quick will use ${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}."
        return 0
    fi

    print_amneziawg_runtime_diagnostics "$modprobe_out"
    maybe_prepare_secure_boot_fix "$modprobe_out"
    install_amneziawg_userspace_fallback

    warn "Continuing with ${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}; the DKMS kernel module is not required."
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

    install_debian_kernel_build_prereqs

    # The PPA package "amneziawg" pulls in the kernel module via DKMS.  Keep APT
    # output visible enough to diagnose DKMS/header failures instead of hiding
    # the root cause behind awg-quick's later "Unknown device type" error.
    local apt_log
    apt_log=$(mktemp)
    if apt-get install -y -qq amneziawg amneziawg-tools 2>"$apt_log" \
        || apt-get install -y -qq amneziawg 2>>"$apt_log"; then
        rm -f "$apt_log"
        return 0
    fi

    warn "Kernel AmneziaWG package installation failed. Last APT/DKMS output:"
    tail -n 40 "$apt_log" >&2 || true
    rm -f "$apt_log"

    install_amneziawg_userspace_fallback
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
    local src="/usr/local/src/amneziawg" tools_repo
    tools_repo="https://github.com/amnezia-vpn/amneziawg-tools.git"

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
    build_amneziawg_go_from_source
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

    install -d -m 700 "$AWG_DIR"

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
PORT_ALIASES="${PORT_ALIASES:-}"
WAN="${WAN:-}"
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
MANAGE_IPTABLES="${MANAGE_IPTABLES:-0}"
ENABLE_UPNP="${ENABLE_UPNP:-0}"
UPNP_ROOT_URL="${UPNP_ROOT_URL:-}"
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

sanitize_for_filename() {
    # Map every character outside [A-Za-z0-9._-] to '_' so things like
    # IPv6 colons and slashes can never produce illegal-on-import filenames.
    # Empty input echoes empty (caller is expected to validate non-emptiness).
    printf '%s' "${1-}" | tr -c 'A-Za-z0-9._-' '_'
}

valid_client_name() {
    # The user-facing client name. Conservative on purpose so the name is also
    # a safe filename component on its own.
    [[ "$1" =~ ^[a-zA-Z0-9_.-]{1,32}$ ]]
}

client_filename() {
    # The on-disk filename for a given client. Uses HOST as the prefix so a
    # bulk import into the AmneziaVPN client app produces self-describing
    # entries like "sgp.swic.name-maciej".  Requires HOST to be set.
    local name="$1"
    printf '%s-%s.conf' "$(sanitize_for_filename "$HOST")" "$name"
}

client_path() {
    printf '%s/%s' "$CLIENTS_DIR" "$(client_filename "$1")"
}

resolve_client_path() {
    # Map a user-facing client name to its on-disk config file. Echoes the
    # resolved path, or empty if no such file exists. The script is still in
    # active development and there's only one canonical filename format — the
    # host-prefixed one written by client_filename().
    local name="$1" p
    p="$CLIENTS_DIR/$(client_filename "$name")"
    if [ -f "$p" ]; then printf '%s' "$p"; fi
}

next_client_octet4() {
    # Return the next free host octet in NET4 starting from .2 (.1 is the
    # server). The check unions TWO sources:
    #   (a) `awg show <iface> allowed-ips`  — the live kernel state
    #   (b) AllowedIPs lines in $AWG_CONF   — the on-disk source of truth
    #
    # (b) is essential during a CSV batch add: _add_client_core appends each
    # new peer to $AWG_CONF immediately but defers `awg syncconf` until the
    # end of the loop, so during iteration N the live interface still holds
    # only the pre-batch peers. Without (b) every batched client would race
    # to the same slot.
    local used_live used_conf used n
    used_live=$(awg show "$IFACE" allowed-ips 2>/dev/null \
        | awk '{for(i=2;i<=NF;i++) print $i}' \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    used_conf=""
    if [ -f "$AWG_CONF" ]; then
        used_conf=$(grep -E '^[[:space:]]*AllowedIPs' "$AWG_CONF" \
            | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
            || true)
    fi
    used=$(printf '%s\n%s\n' "$used_live" "$used_conf" | sort -u)
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

_add_client_core() {
    # Silent worker: writes the client config + appends the peer to the server
    # config + (optionally) syncs the live interface. Echoes the output path.
    # Caller is responsible for any user-facing rendering.
    local name="$1" sync_now="${2:-1}"
    valid_client_name "$name" \
        || die "Client name '$name' must match [a-zA-Z0-9_.-] (max 32 chars)."

    # Reject either the new or legacy filename so we never collide on upgrade.
    if [ -n "$(resolve_client_path "$name")" ]; then
        die "Client '$name' already exists."
    fi
    # Also reject when an existing peer block in the server config carries the
    # same friendly-name marker — covers the case where the .conf file was
    # deleted but the server-side peer entry was left behind.
    if [ -f "$AWG_CONF" ] && grep -qx "# BEGIN_PEER $name" "$AWG_CONF"; then
        die "A peer named '$name' already exists in $AWG_CONF."
    fi

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

    # Append peer to server config so awg-quick(8) sees it on next start AND
    # awg syncconf can reconcile the live interface without a restart.
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

    if [ "$sync_now" = "1" ] && systemctl is-active --quiet "$SVC"; then
        awg syncconf "$IFACE" <(awg-quick strip "$IFACE")
    fi

    # Build the per-client config file.
    install -d -m 0700 "$CLIENTS_DIR"
    local conf
    conf=$(client_path "$name")
    {
        echo "# AmneziaWG client config for '$name' on ${HOST} — generated $(date -u +%FT%TZ)"
        if [ -n "${PORT_ALIASES:-}" ]; then
            local _alias_note=""
            local _an_arr; IFS=',' read -ra _an_arr <<< "$PORT_ALIASES"
            for _an in "${_an_arr[@]}"; do
                _an="${_an// /}"; [ -z "$_an" ] && continue
                _alias_note="${_alias_note:+$_alias_note, }${HOST}:${_an}/udp"
            done
            [ -n "$_alias_note" ] && \
                echo "# Endpoint aliases (DNAT on server, also connectable): $_alias_note"
        fi
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

    printf '%s' "$conf"
}

add_client() {
    # User-facing wrapper — adds one client and prints config + QR.
    local name="$1"
    [ -n "$name" ] || die "Usage: $0 add-client <name>"
    load_meta
    local conf
    conf=$(_add_client_core "$name" 1)
    log "Client '$name' added."
    info "Config: $conf"
    show_client_payload "$conf"
}

add_clients_from_csv() {
    # Used by the install flow and by the menu's "Add client(s)" entry.
    # Argument: a comma-separated list. All clients are configured; only the
    # FIRST is rendered + QR'd. Echoes the path of the first config so the
    # caller can reference it in summary output. The live awg syncconf runs
    # only once at the end so all peers are picked up in a single reload.
    local csv="$1" first="" raw n names=()
    [ -n "$csv" ] || die "No client names provided."
    IFS=',' read -ra raw <<<"$csv"
    for n in "${raw[@]}"; do
        # trim leading/trailing whitespace
        n="${n#"${n%%[![:space:]]*}"}"
        n="${n%"${n##*[![:space:]]}"}"
        [ -z "$n" ] && continue
        valid_client_name "$n" \
            || die "Invalid client name '$n' (allowed: [a-zA-Z0-9_.-], 1-32 chars)."
        names+=("$n")
    done
    [ "${#names[@]}" -gt 0 ] || die "No valid client names parsed from '$csv'."

    # Dedupe while preserving order so add_clients "a,b,a" == "a,b".
    local -A seen=()
    local unique=()
    for n in "${names[@]}"; do
        [ -n "${seen[$n]:-}" ] && continue
        seen[$n]=1
        unique+=("$n")
    done

    load_meta

    local conf
    for n in "${unique[@]}"; do
        # Defer the live syncconf until the last peer to avoid N reloads.
        conf=$(_add_client_core "$n" 0)
        [ -z "$first" ] && first="$conf"
        log "Configured client '$n' -> $conf"
    done

    if systemctl is-active --quiet "$SVC"; then
        awg syncconf "$IFACE" <(awg-quick strip "$IFACE")
    fi

    [ -n "$first" ] && printf '%s' "$first"
}

remove_client() {
    local name="$1"
    [ -n "$name" ] || die "Usage: $0 remove-client <name>"
    load_meta

    local conf
    conf=$(resolve_client_path "$name")
    [ -n "$conf" ] || die "No such client: $name"

    # Remove the BEGIN_PEER..END_PEER block (matched on the friendly name we
    # wrote when the peer was created — never on the public key, which we may
    # not still have in the file path).
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
    rm -f "$conf"
    log "Client '$name' revoked."
}

list_clients() {
    load_meta
    [ -d "$CLIENTS_DIR" ] || { info "No clients configured."; return; }
    local count=0 prefix
    prefix=$(sanitize_for_filename "$HOST")
    [ -n "$prefix" ] || { info "No clients configured."; return; }
    printf '%-32s %-18s %s\n' "NAME" "IPv4" "IPv6"
    # Glob only files that match this host's prefix; anything else under
    # CLIENTS_DIR is unrelated and shouldn't be shown.
    for f in "$CLIENTS_DIR"/"${prefix}"-*.conf; do
        [ -e "$f" ] || break
        local base name addr v4 v6
        base=$(basename "$f" .conf)
        name="${base#"${prefix}"-}"
        addr=$(awk -F'= *' '/^Address/ {print $2; exit}' "$f")
        v4=$(printf '%s' "$addr" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
        v6=$(printf '%s' "$addr" | grep -oE '[0-9a-fA-F:]+:+[0-9a-fA-F:]+' | head -n1)
        printf '%-32s %-18s %s\n' "$name" "${v4:--}" "${v6:--}"
        count=$((count+1))
    done
    [ "$count" -gt 0 ] || info "No clients configured."
}

show_client() {
    local name="$1"
    [ -n "$name" ] || die "Usage: $0 show-client <name>"
    load_meta
    local conf
    conf=$(resolve_client_path "$name")
    [ -n "$conf" ] || die "No such client: $name"
    show_client_payload "$conf"
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
# Doctor: runtime health diagnostics
# ---------------------------------------------------------------------------
_doc_pass() { printf '%s[+]%s %-52s %s\n' "$C_GRN" "$C_RST" "$1" "${2:-}"; }
_doc_warn_line() { printf '%s[!]%s %-52s %s\n' "$C_YLW" "$C_RST" "$1" "${2:-}"; }
_doc_fail_line() { printf '%s[x]%s %-52s %s\n' "$C_RED" "$C_RST" "$1" "${2:-}"; }
_doc_hint()  { printf '       %s\n' "$*"; }

# Returns 0 if an ACCEPT rule covering UDP $port exists in INPUT for the given
# iptables command (iptables or ip6tables). Handles both --dport and --dports
# (multiport) format as shown by `iptables -L INPUT -n`.
_ipt_input_allows_port() {
    local cmd="$1" port="$2"
    "$cmd" -L INPUT -n 2>/dev/null \
        | grep -E '^ACCEPT[[:space:]]' \
        | grep -E 'udp|all' \
        | grep -qE "(^|[^0-9])${port}([^0-9]|$)"
}

do_doctor() {
    local _errs=0 _warns=0
    need_root

    # Load meta variables if available; leave empty so the checks that need
    # them degrade gracefully on a partial or uninstalled state.
    local HOST="" PORT="" PORT_ALIASES="" WAN="" UPNP_ROOT_URL="" NET4="" NET6="" NET4_PREFIX="" NET6_PREFIX=""
    local SERVER_IP4="" SERVER_IP6="" DNS="" MTU="" ENABLE_IPV6="0"
    local OBFUSCATION="off" JC=0 JMIN=0 JMAX=0 S1=0 S2=0 H1=1 H2=2 H3=3 H4=4
    local MANAGE_IPTABLES="0" ENABLE_UPNP="0"
    if [ -r "$META_FILE" ]; then
        # shellcheck disable=SC1090
        . "$META_FILE" 2>/dev/null || true
    fi

    printf '\n%s%sAmneziaWG Doctor%s%s\n\n' \
        "$C_BOLD" "$C_BLU" \
        "${HOST:+ — ${HOST}:${PORT}/udp}" "$C_RST"

    # ── 1. Kernel/userspace runtime ─────────────────────────────────────────
    if lsmod 2>/dev/null | grep -q '^amneziawg[[:space:]]'; then
        _doc_pass "runtime" "amneziawg kernel module loaded"
    elif command -v modprobe >/dev/null 2>&1 && modprobe amneziawg >/dev/null 2>&1; then
        _doc_pass "runtime" "amneziawg kernel module loaded by doctor"
    elif amneziawg_userspace_available; then
        _doc_warn_line "runtime" "kernel module unavailable; userspace ${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go} is present"
        _warns=$((_warns+1))
    else
        _doc_fail_line "runtime" "no amneziawg kernel module or amneziawg-go userspace fallback"
        _doc_hint "Try: modprobe amneziawg"
        _doc_hint "Check: dkms status | grep -i amneziawg"
        _doc_hint "On Debian/Ubuntu, ensure linux-headers-$(uname -r) is installed and reboot if a kernel upgrade is pending."
        _errs=$((_errs+1))
    fi

    # ── 2. Binaries ─────────────────────────────────────────────────────────
    if command -v awg >/dev/null 2>&1; then
        local _awg_ver; _awg_ver=$(awg --version 2>/dev/null | head -n1 || echo "present")
        _doc_pass "awg binary" "$_awg_ver"
    else
        _doc_fail_line "awg binary" "not found in PATH — package not installed?"
        _errs=$((_errs+1))
    fi
    if command -v awg-quick >/dev/null 2>&1; then
        _doc_pass "awg-quick binary" "found"
    else
        _doc_fail_line "awg-quick binary" "not found in PATH"
        _errs=$((_errs+1))
    fi

    # ── 3. Config and hook scripts ──────────────────────────────────────────
    if [ -f "$AWG_CONF" ] && [ -r "$AWG_CONF" ]; then
        _doc_pass "server config" "$AWG_CONF (readable)"
    else
        _doc_fail_line "server config" "$AWG_CONF: missing or unreadable"
        _errs=$((_errs+1))
    fi

    local _hooks_ok=1
    for _hf in "$HOOK_UP" "$HOOK_DOWN"; do
        if [ ! -f "$_hf" ]; then
            _doc_fail_line "hook script" "$(basename "$_hf"): missing"
            _hooks_ok=0; _errs=$((_errs+1))
        elif [ ! -x "$_hf" ]; then
            _doc_fail_line "hook script" "$(basename "$_hf"): not executable"
            _hooks_ok=0; _errs=$((_errs+1))
        fi
    done
    [ "$_hooks_ok" = "1" ] && _doc_pass "hook scripts" "up + down exist and are executable"

    # ── 4. Service status ────────────────────────────────────────────────────
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
        _doc_pass "service" "$SVC active"
    else
        local _sstate; _sstate=$(systemctl is-active "$SVC" 2>/dev/null || echo "unknown")
        _doc_fail_line "service" "$SVC is ${_sstate} (not active)"
        _doc_hint "Check: journalctl -u $SVC -n 40 --no-pager"
        _errs=$((_errs+1))
    fi

    # ── 5. Journal errors ────────────────────────────────────────────────────
    local _jerr
    _jerr=$(journalctl -u "$SVC" -n 100 --no-pager 2>/dev/null \
        | grep -iE '\b(error|failed|fatal|assert|denied)\b' \
        | grep -v "^--" | head -5 || true)
    if [ -z "$_jerr" ]; then
        _doc_pass "journal" "no errors/failures in last 100 lines"
    else
        _doc_warn_line "journal" "errors found in service log:"
        while IFS= read -r _jl; do _doc_hint "$_jl"; done <<<"$_jerr"
        _warns=$((_warns+1))
    fi

    # ── 6. Interface ─────────────────────────────────────────────────────────
    if ip link show "$IFACE" >/dev/null 2>&1; then
        local _iaddrs; _iaddrs=$(ip -o addr show "$IFACE" 2>/dev/null \
            | awk '{printf $4 " "}')
        _doc_pass "interface" "$IFACE UP — ${_iaddrs:-no addresses assigned}"
    else
        _doc_fail_line "interface" "$IFACE does not exist — service may have failed to start"
        _errs=$((_errs+1))
    fi

    # ── 7. Port listening ────────────────────────────────────────────────────
    if [ -n "$PORT" ]; then
        if ss -ulnp 2>/dev/null | grep -qE ":${PORT}[[:space:]]"; then
            _doc_pass "port listening" "UDP :$PORT bound (0.0.0.0 + [::])"
        else
            _doc_fail_line "port listening" "UDP :$PORT NOT found in ss output"
            _doc_hint "Check: ss -ulnp"
            _errs=$((_errs+1))
        fi
    else
        _doc_warn_line "port" "unknown — meta file not loaded"
        _warns=$((_warns+1))
    fi

    # ── 8. Peers ──────────────────────────────────────────────────────────────
    local _pc=0 _pl=0
    [ -f "$AWG_CONF" ] && _pc=$(grep -c '^\[Peer\]' "$AWG_CONF" 2>/dev/null || echo 0)
    ip link show "$IFACE" >/dev/null 2>&1 \
        && _pl=$(awg show "$IFACE" peers 2>/dev/null | wc -l || echo 0)
    if [ "$_pc" -gt 0 ]; then
        _doc_pass "peers" "${_pc} in config, ${_pl} in live interface"
    else
        _doc_warn_line "peers" "no peers in config — add one: sudo $SCRIPT_NAME add-client <name>"
        _warns=$((_warns+1))
    fi

    # ── 9. sysctl ─────────────────────────────────────────────────────────────
    local _f4; _f4=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
    local _svm; _svm=$(sysctl -n net.ipv4.conf.all.src_valid_mark 2>/dev/null || echo 0)
    local _f6; _f6=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 0)
    local _sctl_ok=1 _sctl_bad=""
    [ "$_f4"  != "1" ] && { _sctl_ok=0; _sctl_bad+=" ipv4_forward=$_f4"; }
    [ "$_svm" != "1" ] && { _sctl_ok=0; _sctl_bad+=" src_valid_mark=$_svm"; }
    [ "$ENABLE_IPV6" = "1" ] && [ "$_f6" != "1" ] \
        && { _sctl_ok=0; _sctl_bad+=" ipv6_forward=$_f6"; }
    if [ "$_sctl_ok" = "1" ]; then
        local _s6note=""; [ "$ENABLE_IPV6" = "1" ] && _s6note=" ipv6_forward=1"
        _doc_pass "sysctl" "ipv4_forward=1 src_valid_mark=1${_s6note}"
    else
        _doc_fail_line "sysctl" "wrong values:${_sctl_bad}"
        _doc_hint "Fix: sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.src_valid_mark=1"
        _errs=$((_errs+1))
    fi

    # ── 10. nftables amnezia tables ───────────────────────────────────────────
    local _nft_ok=1 _nft_missing=""
    nft list table inet "$NFT_T_FWD"  >/dev/null 2>&1 || { _nft_ok=0; _nft_missing+=" $NFT_T_FWD"; }
    nft list table ip   "$NFT_T_NAT4" >/dev/null 2>&1 || { _nft_ok=0; _nft_missing+=" $NFT_T_NAT4"; }
    if [ "$ENABLE_IPV6" = "1" ]; then
        nft list table ip6 "$NFT_T_NAT6" >/dev/null 2>&1 \
            || { _nft_ok=0; _nft_missing+=" $NFT_T_NAT6"; }
    fi
    if [ "$_nft_ok" = "1" ]; then
        local _nft_desc="${NFT_T_FWD}, ${NFT_T_NAT4}"
        [ "$ENABLE_IPV6" = "1" ] && _nft_desc+=", ${NFT_T_NAT6}"
        _doc_pass "nftables" "${_nft_desc} loaded"
    else
        _doc_fail_line "nftables" "missing tables:${_nft_missing}"
        _doc_hint "Restart service: systemctl restart $SVC"
        _errs=$((_errs+1))
    fi

    # ── 11. iptables INPUT – VPN listen port ──────────────────────────────────
    if [ -n "$PORT" ] && command -v iptables >/dev/null 2>&1; then
        local _ipt_pol
        _ipt_pol=$(iptables -L INPUT -n 2>/dev/null | sed -n '1s/.*policy \([A-Z]*\).*/\1/p')
        if [ "$_ipt_pol" = "ACCEPT" ]; then
            _doc_pass "iptables INPUT" "policy ACCEPT — all ports reachable"
        elif _ipt_input_allows_port iptables "$PORT"; then
            _doc_pass "iptables INPUT" "policy ${_ipt_pol}, UDP :$PORT has ACCEPT rule"
        else
            _doc_fail_line "iptables INPUT" \
                "policy ${_ipt_pol}, no ACCEPT for UDP :$PORT — handshake blocked"
            _doc_hint "Fix: iptables -I INPUT -p udp --dport $PORT -j ACCEPT"
            _doc_hint "     Persist: netfilter-persistent save"
            _doc_hint "           OR: iptables-save > /etc/iptables/rules.v4"
            _errs=$((_errs+1))
        fi
    fi

    # ── 12. ip6tables INPUT ───────────────────────────────────────────────────
    if [ "$ENABLE_IPV6" = "1" ] && [ -n "$PORT" ] \
        && command -v ip6tables >/dev/null 2>&1; then
        local _ip6t_pol
        _ip6t_pol=$(ip6tables -L INPUT -n 2>/dev/null | sed -n '1s/.*policy \([A-Z]*\).*/\1/p')
        if [ "$_ip6t_pol" = "ACCEPT" ]; then
            _doc_pass "ip6tables INPUT" "policy ACCEPT"
        elif _ipt_input_allows_port ip6tables "$PORT"; then
            _doc_pass "ip6tables INPUT" "policy ${_ip6t_pol}, UDP :$PORT has ACCEPT rule"
        else
            _doc_fail_line "ip6tables INPUT" \
                "policy ${_ip6t_pol}, no ACCEPT for UDP :$PORT"
            _doc_hint "Fix: ip6tables -I INPUT -p udp --dport $PORT -j ACCEPT"
            _errs=$((_errs+1))
        fi
    fi

    # ── 13. iptables FORWARD – VPN subnet forwarding ──────────────────────────
    if [ -n "$NET4" ] && command -v iptables >/dev/null 2>&1; then
        local _fwd_pol
        _fwd_pol=$(iptables -L FORWARD -n 2>/dev/null | sed -n '1s/.*policy \([A-Z]*\).*/\1/p')
        if [ "$_fwd_pol" = "ACCEPT" ]; then
            _doc_pass "iptables FORWARD" "policy ACCEPT — forwarding unrestricted"
        else
            # Check for the interface-pair rule we add (preferred) then fall back
            # to looking for any ACCEPT covering our interface or subnet.
            local _fwd_iface_ok=0 _fwd_desc=""
            if [ -n "$WAN" ] \
                && iptables -C FORWARD -i "$IFACE" -o "$WAN" -j ACCEPT 2>/dev/null; then
                _fwd_iface_ok=1; _fwd_desc="ACCEPT $IFACE → $WAN present"
            fi
            if [ "$_fwd_iface_ok" = "0" ]; then
                local _fwd_generic
                _fwd_generic=$(iptables -L FORWARD -n 2>/dev/null \
                    | grep -E '^ACCEPT' | grep -Ev 'ctstate' \
                    | grep -E "(${NET4//./\\.}|[[:space:]]${IFACE}[[:space:]])" \
                    || true)
                [ -n "$_fwd_generic" ] && { _fwd_iface_ok=1; _fwd_desc="ACCEPT rule covers $NET4"; }
            fi
            if [ "$_fwd_iface_ok" = "1" ]; then
                _doc_pass "iptables FORWARD" "policy ${_fwd_pol}, ${_fwd_desc}"
            else
                _doc_warn_line "iptables FORWARD" \
                    "policy ${_fwd_pol}, no ACCEPT for $IFACE → ${WAN:-<wan>}"
                _doc_hint "nftables amnezia_fwd may handle this; if VPN clients can't reach internet:"
                local _wan_hint="${WAN:-<wan-iface>}"
                _doc_hint "  iptables -I FORWARD -i $IFACE -o $_wan_hint -j ACCEPT"
                _doc_hint "  iptables -I FORWARD -i $_wan_hint -o $IFACE -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
                _warns=$((_warns+1))
            fi
        fi
    fi

    # ── 13b. iptables DNAT alias ports ────────────────────────────────────────
    if [ -n "${PORT_ALIASES:-}" ] && [ -n "$PORT" ] \
        && command -v iptables >/dev/null 2>&1; then
        local _dnat_ok=1 _dnat_missing=""
        local _da_arr; IFS=',' read -ra _da_arr <<< "$PORT_ALIASES"
        for _da in "${_da_arr[@]}"; do
            _da="${_da// /}"; [ -z "$_da" ] && continue
            if ! iptables -t nat -C PREROUTING -p udp --dport "$_da" \
                -j REDIRECT --to-port "$PORT" 2>/dev/null; then
                _dnat_ok=0; _dnat_missing+=" :$_da"
            fi
        done
        if [ "$_dnat_ok" = "1" ]; then
            _doc_pass "port alias DNAT" "UDP ${PORT_ALIASES//,/ and :} → :$PORT rules present"
        else
            _doc_warn_line "port alias DNAT" "missing PREROUTING rules for${_dnat_missing}"
            _doc_hint "Fix: iptables -t nat -I PREROUTING -p udp --dport <alias> -j REDIRECT --to-port $PORT"
            _warns=$((_warns+1))
        fi
    fi

    # ── 13c. UPnP router port mappings ───────────────────────────────────────
    if [ "${ENABLE_UPNP:-0}" = "1" ]; then
        if ! command -v upnpc >/dev/null 2>&1; then
            _doc_fail_line "UPnP" "enabled, but upnpc is missing (install miniupnpc)"
            _errs=$((_errs+1))
        elif ! systemctl is-enabled --quiet "$(basename "$UPNP_TIMER")" 2>/dev/null; then
            _doc_warn_line "UPnP" "refresh timer is not enabled"
            _doc_hint "Fix: systemctl enable --now $(basename "$UPNP_TIMER")"
            _warns=$((_warns+1))
        elif systemctl is-failed --quiet "$(basename "$UPNP_SERVICE")" 2>/dev/null; then
            _doc_warn_line "UPnP" "last refresh failed; router may not support UPnP IGD"
            _doc_hint "Inspect: journalctl -u $(basename "$UPNP_SERVICE") -n 40 --no-pager"
            _warns=$((_warns+1))
        else
            _doc_pass "UPnP" "refresh timer enabled for UDP $(vpn_port_list | paste -sd, -)"
        fi
    fi

    # ── 14. ufw ───────────────────────────────────────────────────────────────
    if command -v ufw >/dev/null 2>&1; then
        local _ufw_st; _ufw_st=$(ufw status 2>/dev/null | head -1 || echo "unknown")
        if echo "$_ufw_st" | grep -qi "inactive"; then
            _doc_pass "ufw" "inactive"
        else
            local _ufw_rule
            _ufw_rule=$(ufw status 2>/dev/null | grep -E "^${PORT:-0}[[:space:]]" || true)
            if [ -n "$_ufw_rule" ]; then
                _doc_pass "ufw" "active, port $PORT allowed"
            else
                _doc_fail_line "ufw" "active, no rule found for UDP :$PORT"
                _doc_hint "Fix: ufw allow $PORT/udp"
                _errs=$((_errs+1))
            fi
        fi
    fi

    # ── 15. firewalld ─────────────────────────────────────────────────────────
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            local _fwz; _fwz=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
            local _fwp
            _fwp=$(firewall-cmd --list-ports --zone="$_fwz" 2>/dev/null \
                | grep -E "(^| )${PORT:-0}/(udp|tcp)" || true)
            if [ -n "$_fwp" ]; then
                _doc_pass "firewalld" "active, port $PORT open in zone ${_fwz}"
            else
                _doc_fail_line "firewalld" "active, port $PORT NOT open in zone ${_fwz}"
                _doc_hint "Fix: firewall-cmd --permanent --add-port=$PORT/udp && firewall-cmd --reload"
                _errs=$((_errs+1))
            fi
        else
            _doc_pass "firewalld" "not active"
        fi
    fi

    # ── 16. Hostname resolution ───────────────────────────────────────────────
    if [ -n "$HOST" ]; then
        local _resolved
        _resolved=$(getent hosts "$HOST" 2>/dev/null | awk '{print $1}' | head -1 || true)
        if [ -n "$_resolved" ]; then
            _doc_pass "hostname" "$HOST → $_resolved"
        elif [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
            || [[ "$HOST" == *:*:* ]]; then
            _doc_pass "hostname" "$HOST (IP literal, no DNS needed)"
        else
            _doc_warn_line "hostname" "$HOST does not resolve from this server"
            _doc_hint "Clients may fail to connect. Check DNS propagation."
            _warns=$((_warns+1))
        fi
    fi

    # ── 17. Meta file ─────────────────────────────────────────────────────────
    if [ -r "$META_FILE" ]; then
        _doc_pass "meta file" "$META_FILE"
    else
        _doc_warn_line "meta file" "$META_FILE missing — client subcommands need it"
        _warns=$((_warns+1))
    fi

    # ── Summary ───────────────────────────────────────────────────────────────
    echo
    if [ "$_errs" -gt 0 ]; then
        printf '%s%s[FAIL] Doctor: %d error(s), %d warning(s). VPN likely NOT functional.%s\n' \
            "$C_RED" "$C_BOLD" "$_errs" "$_warns" "$C_RST" >&2
        return 1
    elif [ "$_warns" -gt 0 ]; then
        printf '%s%s[WARN] Doctor: 0 errors, %d warning(s). VPN may have limited functionality.%s\n' \
            "$C_YLW" "$C_BOLD" "$_warns" "$C_RST"
        return 0
    else
        printf '%s%s[ OK ] Doctor: all checks passed. VPN should be functional.%s\n' \
            "$C_GRN" "$C_BOLD" "$C_RST"
        return 0
    fi
}


# ---------------------------------------------------------------------------
# UPnP port forwarding lifecycle. Ubuntu ships the miniupnpc package, whose
# upnpc client can add a mapping with:
#   upnpc [-u <root-desc-url>] -a <internal-ip> <internal-port> <external-port> UDP [duration]
# We request duration 0 (permanent where supported) and also install a systemd
# boot service + hourly timer because many home routers forget or expire UPnP
# mappings despite accepting "permanent" leases.
# ---------------------------------------------------------------------------
valid_upnp_root_url() {
    local url="${1:-}"
    case "$url" in
        http://*|https://*) ;;
        *) return 1 ;;
    esac
    case "$url" in
        *[[:space:]]*|*\"*) return 1 ;;
    esac
    return 0
}

upnp_args_for() {
    local -n _out="$1"
    _out=()
    [ -n "${WAN:-}" ] && _out+=(-m "$WAN")
    [ -n "${UPNP_ROOT_URL:-}" ] && _out+=(-u "$UPNP_ROOT_URL")
}

upnp_extract_root_url() {
    awk '/^[[:space:]]*desc:[[:space:]]*/ { print $2; exit }'
}

upnp_discover_root_url() {
    command -v upnpc >/dev/null 2>&1 || return 1
    local _args=() _out="" _url=""
    [ -n "${WAN:-}" ] && _args=(-m "$WAN")
    _out=$(timeout 12s upnpc "${_args[@]}" -l 2>&1 || true)
    _url=$(printf '%s\n' "$_out" | upnp_extract_root_url)
    valid_upnp_root_url "$_url" || return 1
    printf '%s' "$_url"
}

ensure_upnp_root_url() {
    [ "${ENABLE_UPNP:-0}" = "1" ] || return 0
    if [ -n "${UPNP_ROOT_URL:-}" ]; then
        valid_upnp_root_url "$UPNP_ROOT_URL" || die "Invalid UPnP root URL: $UPNP_ROOT_URL"
        return 0
    fi

    local _url=""
    _url=$(upnp_discover_root_url || true)
    if [ -n "$_url" ]; then
        UPNP_ROOT_URL="$_url"
        info "UPnP: discovered IGD root URL: $UPNP_ROOT_URL"
        return 0
    fi

    if [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ] || [ ! -t 0 ]; then
        warn "UPnP: could not discover an IGD root URL; continuing with normal SSDP discovery."
        return 0
    fi

    warn "UPnP discovery did not find an IGD. If your router's UPnP root description URL is known, enter it now."
    while :; do
        _url=$(ask_placeholder "UPnP root URL (leave empty to keep automatic discovery)" "$UPNP_ROOT_URL_EXAMPLE")
        [ -n "$_url" ] || return 0
        if valid_upnp_root_url "$_url"; then
            UPNP_ROOT_URL="$_url"
            return 0
        fi
        warn "Enter a URL like $UPNP_ROOT_URL_EXAMPLE, or press Enter to skip hard-coding it."
    done
}

vpn_port_list() {
    local _seen_ports="" p
    for p in "$PORT" ${PORT_ALIASES//,/ }; do
        p="${p// /}"
        [ -z "$p" ] && continue
        case " $_seen_ports " in *" $p "*) continue ;; esac
        _seen_ports+=" $p"
        printf '%s\n' "$p"
    done
}

upnp_internal_ip4() {
    local wan="${1:-${WAN:-}}" ip=""
    if [ -n "$wan" ]; then
        ip=$(ip -4 -o addr show dev "$wan" scope global 2>/dev/null \
            | awk '{sub(/\/.*/, "", $4); print $4; exit}' || true)
    fi
    if [ -z "$ip" ]; then
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null \
            | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}' || true)
    fi
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    printf '%s' "$ip"
}

write_upnp_refresh_script() {
    [ "${ENABLE_UPNP:-0}" = "1" ] || return 0
    install -d -m 0700 "$STATE_DIR"
    cat >"$UPNP_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
META_FILE="/var/lib/amnezia-installer/server.env"
SCRIPT_NAME="amnezia-installer"
[ -r "$META_FILE" ] || { echo "Missing $META_FILE" >&2; exit 1; }
# shellcheck disable=SC1090
. "$META_FILE"
[ "${ENABLE_UPNP:-0}" = "1" ] || exit 0
command -v upnpc >/dev/null 2>&1 || { echo "upnpc not found; install miniupnpc" >&2; exit 1; }

valid_upnp_root_url() {
    local url="${1:-}"
    case "$url" in
        http://*|https://*) ;;
        *) return 1 ;;
    esac
    case "$url" in
        *[[:space:]]*|*\"*) return 1 ;;
    esac
    return 0
}

upnp_args_for() {
    local -n _out="$1"
    _out=()
    [ -n "${WAN:-}" ] && _out+=(-m "$WAN")
    if [ -n "${UPNP_ROOT_URL:-}" ]; then
        valid_upnp_root_url "$UPNP_ROOT_URL" || { echo "Invalid UPnP root URL: $UPNP_ROOT_URL" >&2; exit 1; }
        _out+=(-u "$UPNP_ROOT_URL")
    fi
}

vpn_port_list() {
    local _seen_ports="" p
    for p in "$PORT" ${PORT_ALIASES//,/ }; do
        p="${p// /}"
        [ -z "$p" ] && continue
        case " $_seen_ports " in *" $p "*) continue ;; esac
        _seen_ports+=" $p"
        printf '%s\n' "$p"
    done
}

internal_ip4() {
    local ip=""
    if [ -n "${WAN:-}" ]; then
        ip=$(ip -4 -o addr show dev "$WAN" scope global 2>/dev/null \
            | awk '{sub(/\/.*/, "", $4); print $4; exit}' || true)
    fi
    if [ -z "$ip" ]; then
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null \
            | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}' || true)
    fi
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    printf '%s' "$ip"
}

ip4=$(internal_ip4) || { echo "Could not determine this server's LAN IPv4 address" >&2; exit 1; }
upnp_args_for upnpc_args

ok=0
failed=0
while IFS= read -r port; do
    [ -n "$port" ] || continue
    desc="${SCRIPT_NAME} awg0 UDP ${port}"
    if upnpc "${upnpc_args[@]}" -e "$desc" -a "$ip4" "$port" "$port" UDP 0; then
        echo "UPnP mapped UDP ${port} -> ${ip4}:${port}"
        ok=$((ok + 1))
    else
        echo "UPnP failed for UDP ${port}" >&2
        failed=$((failed + 1))
    fi
done < <(vpn_port_list)

if [ "$ok" -gt 0 ] && [ "$failed" -gt 0 ]; then
    echo "UPnP partially refreshed: ${ok} port(s) mapped, ${failed} port(s) failed" >&2
    exit 2
elif [ "$ok" -gt 0 ]; then
    echo "UPnP refreshed: ${ok} port(s) mapped"
    exit 0
else
    echo "UPnP refresh failed: no ports were mapped" >&2
    exit 1
fi
EOF
    chmod 0700 "$UPNP_SCRIPT"
}

write_upnp_systemd_units() {
    [ "${ENABLE_UPNP:-0}" = "1" ] || return 0
    cat >"$UPNP_SERVICE" <<EOF
[Unit]
Description=Refresh AmneziaWG UPnP port mappings
Documentation=https://manpages.ubuntu.com/manpages/jammy/man1/upnpc.1.html
Wants=network-online.target
After=network-online.target ${SVC}

[Service]
Type=oneshot
ExecStart=${UPNP_SCRIPT}
SuccessExitStatus=2
EOF

    cat >"$UPNP_TIMER" <<EOF
[Unit]
Description=Periodically refresh AmneziaWG UPnP port mappings

[Timer]
OnBootSec=45s
OnUnitActiveSec=1h
Unit=$(basename "$UPNP_SERVICE")
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

apply_upnp_port_forwards() {
    [ "${ENABLE_UPNP:-0}" = "1" ] || return 0
    command -v upnpc >/dev/null 2>&1 || {
        warn "UPnP requested, but upnpc is missing (package: miniupnpc)."
        return 1
    }
    log "Configuring UPnP port forwarding for VPN UDP port(s): $(vpn_port_list | paste -sd, -)"

    ensure_upnp_root_url

    local ip4
    ip4=$(upnp_internal_ip4 "$WAN") || {
        warn "UPnP: could not determine this server's LAN IPv4 address; skipping mappings."
        return 1
    }

    write_upnp_refresh_script
    write_upnp_systemd_units
    systemctl daemon-reload
    systemctl enable --now "$(basename "$UPNP_TIMER")" >/dev/null 2>&1 \
        || warn "UPnP: failed to enable refresh timer; mappings may not survive reboot."

    local _upnp_rc=0
    "$UPNP_SCRIPT" || _upnp_rc=$?
    case "$_upnp_rc" in
        0)
            log "UPnP mappings are active and will be refreshed hourly."
            ;;
        2)
            warn "UPnP partially succeeded. Successful ports are active and will be refreshed hourly."
            return 0
            ;;
        *)
            warn "UPnP mapping failed. Ensure your router supports UPnP IGD and has UPnP enabled."
            return 1
            ;;
    esac
}

remove_upnp_port_forwards() {
    [ "${ENABLE_UPNP:-0}" = "1" ] || [ -e "$UPNP_SERVICE" ] || [ -e "$UPNP_TIMER" ] || return 0
    log "Removing UPnP port forwarding refresh service and mappings..."
    systemctl disable --now "$(basename "$UPNP_TIMER")" >/dev/null 2>&1 || true
    systemctl stop "$(basename "$UPNP_SERVICE")" >/dev/null 2>&1 || true

    if [ "${ENABLE_UPNP:-0}" = "1" ] && command -v upnpc >/dev/null 2>&1 && [ -n "${PORT:-}" ]; then
        local _up
        while IFS= read -r _up; do
            [ -n "$_up" ] || continue
            local _upnp_args=()
            upnp_args_for _upnp_args
            upnpc "${_upnp_args[@]}" -d "$_up" UDP >/dev/null 2>&1 || true
        done < <(vpn_port_list)
    fi
}

# ---------------------------------------------------------------------------
# iptables lifecycle: apply/remove/persist. All rules are tightly scoped:
#   INPUT  — only the AWG listen port (UDP).
#   PREROUTING — DNAT only for alias ports → primary port; no other traffic.
#   FORWARD — only the awg0 ↔ WAN interface pair; wg0/strongswan/LAN unaffected.
# ---------------------------------------------------------------------------

# persist_iptables: save rules to survive reboots.
# Interactive: ask. Non-interactive / AMNEZIA_NONINTERACTIVE=1: auto-save if
# netfilter-persistent is available, otherwise print a manual instruction.
persist_iptables() {
    if command -v netfilter-persistent >/dev/null 2>&1; then
        if [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ] || [ ! -t 0 ]; then
            netfilter-persistent save >/dev/null 2>&1 \
                && log "  iptables: rules persisted via netfilter-persistent." \
                || warn "  iptables: netfilter-persistent save failed — rules will be lost on reboot."
        elif ask_yn "  Save iptables rules with netfilter-persistent (survives reboots)?" "y"; then
            netfilter-persistent save >/dev/null 2>&1 \
                && log "  iptables: rules saved." \
                || warn "  iptables: save failed — rules will be lost on reboot."
        else
            warn "  iptables: rules added but NOT persisted. After reboot, run: sudo $SCRIPT_NAME doctor"
        fi
    else
        warn "  iptables: netfilter-persistent not installed — rules will NOT survive reboots."
        warn "  Persist manually after verifying everything works:"
        warn "    iptables-save > /etc/iptables/rules.v4"
        [ "${ENABLE_IPV6:-0}" = "1" ] && \
            warn "    ip6tables-save > /etc/iptables/rules.v6" || true
    fi
}

# apply_iptables_rules: called during do_install after the service starts.
# Uses globals: PORT, PORT_ALIASES, WAN, IFACE, ENABLE_IPV6, MANAGE_IPTABLES.
apply_iptables_rules() {
    [ "${MANAGE_IPTABLES:-0}" = "1" ] || return 0
    command -v iptables >/dev/null 2>&1 || {
        info "iptables not found — skipping firewall rule management."
        return 0
    }
    log "Configuring iptables rules (scoped to $IFACE / port $PORT)..."

    local _ipt6=0
    [ "${ENABLE_IPV6:-0}" = "1" ] && command -v ip6tables >/dev/null 2>&1 && _ipt6=1

    # ── INPUT: allow the primary AWG listen port ───────────────────────────
    if ! _ipt_input_allows_port iptables "$PORT"; then
        iptables -I INPUT -p udp --dport "$PORT" -j ACCEPT
        log "  iptables INPUT: ACCEPT UDP :$PORT"
    else
        info "  iptables INPUT: rule for UDP :$PORT already present"
    fi
    if [ "$_ipt6" = "1" ] && ! _ipt_input_allows_port ip6tables "$PORT"; then
        ip6tables -I INPUT -p udp --dport "$PORT" -j ACCEPT
        log "  ip6tables INPUT: ACCEPT UDP :$PORT"
    fi

    # ── PREROUTING DNAT: alias ports → primary (clients can use any port) ──
    if [ -n "${PORT_ALIASES:-}" ]; then
        local _aa_arr; IFS=',' read -ra _aa_arr <<< "$PORT_ALIASES"
        for _ap in "${_aa_arr[@]}"; do
            _ap="${_ap// /}"; [ -z "$_ap" ] && continue
            if ! iptables -t nat -C PREROUTING -p udp --dport "$_ap" \
                -j REDIRECT --to-port "$PORT" 2>/dev/null; then
                iptables -t nat -I PREROUTING -p udp --dport "$_ap" \
                    -j REDIRECT --to-port "$PORT"
                log "  iptables PREROUTING: DNAT UDP :$_ap → :$PORT"
            else
                info "  iptables PREROUTING: DNAT :$_ap → :$PORT already present"
            fi
            if [ "$_ipt6" = "1" ]; then
                if ! ip6tables -t nat -C PREROUTING -p udp --dport "$_ap" \
                    -j REDIRECT --to-port "$PORT" 2>/dev/null; then
                    ip6tables -t nat -I PREROUTING -p udp --dport "$_ap" \
                        -j REDIRECT --to-port "$PORT"
                    log "  ip6tables PREROUTING: DNAT UDP :$_ap → :$PORT"
                fi
            fi
        done
    fi

    # ── FORWARD: awg0 ↔ WAN only ───────────────────────────────────────────
    # These two rules mirror exactly what nftables amnezia_fwd does, but in
    # the iptables layer so legacy-iptables DROP policy doesn't win first.
    # Scoped to the IFACE/WAN pair — wg0, strongswan, and LAN routes are
    # untouched because none of them involve awg0.
    if ! iptables -C FORWARD -i "$IFACE" -o "$WAN" -j ACCEPT 2>/dev/null; then
        iptables -I FORWARD -i "$IFACE" -o "$WAN" -j ACCEPT
        log "  iptables FORWARD: ACCEPT $IFACE → $WAN"
    fi
    if ! iptables -C FORWARD -i "$WAN" -o "$IFACE" \
        -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
        iptables -I FORWARD -i "$WAN" -o "$IFACE" \
            -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        log "  iptables FORWARD: ACCEPT $WAN → $IFACE (RELATED,ESTABLISHED)"
    fi
    if [ "$_ipt6" = "1" ]; then
        if ! ip6tables -C FORWARD -i "$IFACE" -o "$WAN" -j ACCEPT 2>/dev/null; then
            ip6tables -I FORWARD -i "$IFACE" -o "$WAN" -j ACCEPT
            log "  ip6tables FORWARD: ACCEPT $IFACE → $WAN"
        fi
        if ! ip6tables -C FORWARD -i "$WAN" -o "$IFACE" \
            -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
            ip6tables -I FORWARD -i "$WAN" -o "$IFACE" \
                -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
            log "  ip6tables FORWARD: ACCEPT $WAN → $IFACE (RELATED,ESTABLISHED)"
        fi
    fi

    persist_iptables
}

# remove_iptables_rules: mirror of apply_iptables_rules — deletes only the
# rules we added, identified by exact specification. Idempotent.
# Uses globals loaded from META_FILE: PORT, PORT_ALIASES, WAN, ENABLE_IPV6, MANAGE_IPTABLES.
remove_iptables_rules() {
    [ "${MANAGE_IPTABLES:-0}" = "1" ] || return 0
    command -v iptables >/dev/null 2>&1 || return 0
    local _port="${PORT:-}" _wan="${WAN:-}" _aliases="${PORT_ALIASES:-}"
    local _ipt6=0
    command -v ip6tables >/dev/null 2>&1 && _ipt6=1

    log "Removing iptables rules added by $SCRIPT_NAME..."

    if [ -n "$_port" ]; then
        iptables  -D INPUT -p udp --dport "$_port" -j ACCEPT 2>/dev/null || true
        [ "$_ipt6" = "1" ] && \
            ip6tables -D INPUT -p udp --dport "$_port" -j ACCEPT 2>/dev/null || true
    fi

    if [ -n "$_aliases" ] && [ -n "$_port" ]; then
        local _ra_arr; IFS=',' read -ra _ra_arr <<< "$_aliases"
        for _ap in "${_ra_arr[@]}"; do
            _ap="${_ap// /}"; [ -z "$_ap" ] && continue
            iptables  -t nat -D PREROUTING -p udp --dport "$_ap" \
                -j REDIRECT --to-port "$_port" 2>/dev/null || true
            [ "$_ipt6" = "1" ] && \
                ip6tables -t nat -D PREROUTING -p udp --dport "$_ap" \
                    -j REDIRECT --to-port "$_port" 2>/dev/null || true
        done
    fi

    if [ -n "$_wan" ]; then
        iptables  -D FORWARD -i "$IFACE" -o "$_wan" -j ACCEPT 2>/dev/null || true
        iptables  -D FORWARD -i "$_wan" -o "$IFACE" \
            -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
        if [ "$_ipt6" = "1" ]; then
            ip6tables -D FORWARD -i "$IFACE" -o "$_wan" -j ACCEPT 2>/dev/null || true
            ip6tables -D FORWARD -i "$_wan" -o "$IFACE" \
                -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
        fi
    fi

    persist_iptables
    log "iptables rules removed."
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
    echo
    if [ "${ENABLE_UPNP:-0}" = "1" ]; then
        info "UPnP refresh timer:"
        systemctl --no-pager --full status "$(basename "$UPNP_TIMER")" 2>/dev/null | sed -n '1,8p' || true
        if command -v upnpc >/dev/null 2>&1; then
            info "UPnP router mappings:"
            local _upnp_args=()
            upnp_args_for _upnp_args
            upnpc "${_upnp_args[@]}" -l 2>/dev/null | sed -n '1,80p' || true
        fi
    else
        info "UPnP forwarding: disabled"
    fi
}

uninstall() {
    local purge=0
    [ "${1:-}" = "--purge" ] && purge=1

    # Load meta so remove_iptables_rules knows what to clean up.
    # shellcheck disable=SC1090
    [ -r "$META_FILE" ] && . "$META_FILE" 2>/dev/null || true

    log "Stopping $SVC..."
    systemctl disable --now "$SVC" 2>/dev/null || true

    log "Tearing down nftables tables..."
    nft delete table inet "$NFT_T_FWD"  2>/dev/null || true
    nft delete table ip   "$NFT_T_NAT4" 2>/dev/null || true
    nft delete table ip6  "$NFT_T_NAT6" 2>/dev/null || true

    remove_upnp_port_forwards
    remove_iptables_rules

    log "Removing sysctl drop-in..."
    rm -f "$SYSCTL_FILE"
    sysctl --system >/dev/null 2>&1 || true

    log "Removing hook scripts..."
    rm -f "$HOOK_UP" "$HOOK_DOWN"

    log "Removing UPnP refresh units..."
    rm -f "$UPNP_SCRIPT" "$UPNP_SERVICE" "$UPNP_TIMER"
    systemctl daemon-reload 2>/dev/null || true

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

    # ----- Port(s) -----------------------------------------------------------
    local suggested_port="${AMNEZIA_PORT:-$(suggest_port)}"
    info "Tip: ports 80, 443 (UDP) get less DPI scrutiny on hostile networks."
    info "You may enter multiple ports separated by commas (e.g. 51820,443)."
    info "AWG listens on the first; the rest are iptables DNAT aliases (clients"
    info "can connect on any). Alias ports don't need separate INPUT rules."
    local _port_input
    _port_input=$(ask "UDP listen port(s)" "$suggested_port")

    PORT=""; PORT_ALIASES=""
    local _plist_arr
    IFS=',' read -ra _plist_arr <<< "$(printf '%s' "$_port_input" | tr -d ' ')"
    local _pi_first=1
    for _p in "${_plist_arr[@]}"; do
        [ -z "$_p" ] && continue
        if ! [[ "$_p" =~ ^[0-9]+$ ]] || [ "$_p" -lt 1 ] || [ "$_p" -gt 65535 ]; then
            die "Invalid port: $_p"
        fi
        if [ "$_pi_first" = "1" ]; then
            PORT="$_p"; _pi_first=0
        else
            PORT_ALIASES="${PORT_ALIASES:+$PORT_ALIASES,}$_p"
        fi
    done
    [ -n "$PORT" ] || die "No valid port specified."

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
    ip link show "$wan" >/dev/null 2>&1 \
        || warn "Interface '$wan' not found right now; will be used at service start."
    # Export WAN to global so save_meta and apply_iptables_rules can use it.
    WAN="$wan"

    # ----- UPnP port forwarding -----------------------------------------------
    # Optional because UPnP exposes ports on the edge router and many operators
    # prefer explicit router/cloud-firewall rules. Default is intentionally "n".
    ENABLE_UPNP=0
    case "${AMNEZIA_ENABLE_UPNP:-}" in
        1|y|Y|yes|YES|true|TRUE)
            ENABLE_UPNP=1
            info "UPnP: miniupnpc/upnpc will forward all VPN UDP ports."
            ;;
        0|n|N|no|NO|false|FALSE)
            ENABLE_UPNP=0
            ;;
        "")
            if [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ] || [ ! -t 0 ]; then
                ENABLE_UPNP=0
            else
                warn "UPnP can automatically open ports on your router; enable it only on a trusted LAN/router."
                if ask_yn "Forward VPN UDP port(s) on your router with UPnP?" "n"; then
                    ENABLE_UPNP=1
                fi
            fi
            ;;
        *) die "AMNEZIA_ENABLE_UPNP must be 1/0, yes/no, or true/false." ;;
    esac
    if [ "$ENABLE_UPNP" = "1" ] && [ -n "${AMNEZIA_UPNP_ROOT_URL:-}" ]; then
        valid_upnp_root_url "$AMNEZIA_UPNP_ROOT_URL" \
            || die "AMNEZIA_UPNP_ROOT_URL must look like $UPNP_ROOT_URL_EXAMPLE"
        UPNP_ROOT_URL="$AMNEZIA_UPNP_ROOT_URL"
        info "UPnP: using configured IGD root URL: $UPNP_ROOT_URL"
    fi

    # ----- iptables management -----------------------------------------------
    # Detect iptables and decide whether to manage INPUT/FORWARD/DNAT rules.
    MANAGE_IPTABLES=0
    if command -v iptables >/dev/null 2>&1; then
        if [ "${AMNEZIA_MANAGE_IPTABLES:-}" = "0" ]; then
            info "iptables management disabled (AMNEZIA_MANAGE_IPTABLES=0)."
        else
            local _ipt_prompt="Add iptables rules: INPUT UDP :$PORT"
            [ -n "$PORT_ALIASES" ] && _ipt_prompt+=", DNAT aliases ($PORT_ALIASES → $PORT)"
            _ipt_prompt+=", FORWARD $IFACE ↔ $wan"
            if [ "${AMNEZIA_MANAGE_IPTABLES:-}" = "1" ] \
                || [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ] \
                || [ ! -t 0 ]; then
                MANAGE_IPTABLES=1
                info "iptables: rules will be configured automatically."
            elif ask_yn "$_ipt_prompt?" "y"; then
                MANAGE_IPTABLES=1
            else
                info "Skipping iptables management. Ensure port $PORT is reachable."
            fi
        fi
    fi

    # ----- Initial client roster --------------------------------------------
    # A comma-separated list — the first one will be displayed + QR'd at the
    # end; the rest are saved for later retrieval via the 'show-client'
    # subcommand or directly from /var/lib/amnezia-installer/clients/.
    CLIENTS_CSV="${AMNEZIA_CLIENT_NAME:-client1}"
    CLIENTS_CSV=$(ask "Initial client name(s) — comma-separated (e.g. 'maciej,alice,bob')" "$CLIENTS_CSV")
    # Validate every name up-front, AND require at least one survives trimming,
    # so an input like ", ," or "" can't slip past this gate and only fail
    # halfway through the install (after packages + service start).
    local n _valid_count=0
    IFS=',' read -ra _check_names <<<"$CLIENTS_CSV"
    for n in "${_check_names[@]}"; do
        n="${n#"${n%%[![:space:]]*}"}"
        n="${n%"${n##*[![:space:]]}"}"
        [ -z "$n" ] && continue
        valid_client_name "$n" \
            || die "Invalid client name '$n' (allowed: [a-zA-Z0-9_.-], 1-32 chars)."
        _valid_count=$((_valid_count + 1))
    done
    unset _check_names
    [ "$_valid_count" -gt 0 ] \
        || die "Need at least one client name; got '$CLIENTS_CSV' which trims to nothing."

    # ---- summary ------------------------------------------------------------
    local _port_summary="${HOST}:${PORT}/udp"
    [ -n "$PORT_ALIASES" ] && _port_summary+=" (+ aliases: ${PORT_ALIASES//,/ })"
    local _ipt_summary="skipped"
    [ "$MANAGE_IPTABLES" = "1" ] && _ipt_summary="INPUT :$PORT, FORWARD $IFACE↔$wan"
    [ "$MANAGE_IPTABLES" = "1" ] && [ -n "$PORT_ALIASES" ] \
        && _ipt_summary+=", DNAT ${PORT_ALIASES//,/ } → $PORT"
    local _upnp_summary="disabled"
    [ "$ENABLE_UPNP" = "1" ] && _upnp_summary="enabled for UDP $(vpn_port_list | paste -sd, -) via miniupnpc/upnpc"
    [ "$ENABLE_UPNP" = "1" ] && [ -n "${UPNP_ROOT_URL:-}" ] && _upnp_summary+=" (root URL: $UPNP_ROOT_URL)"
    cat <<EOF

${C_BOLD}Installation summary${C_RST}
  Public endpoint : ${_port_summary}
  WAN interface   : ${wan}
  IPv4 VPN net    : ${NET4} (server ${SERVER_IP4})
  IPv6 VPN net    : $([ "$ENABLE_IPV6" = "1" ] && echo "${NET6} (server ${SERVER_IP6})" || echo disabled)
  DNS pushed      : ${DNS}
  MTU             : ${MTU}
  Obfuscation     : ${OBFUSCATION}$([ "$OBFUSCATION" != "off" ] && printf ' (Jc=%s Jmin=%s Jmax=%s S1=%s S2=%s)' "$JC" "$JMIN" "$JMAX" "$S1" "$S2")
  iptables rules  : ${_ipt_summary}
  UPnP forwarding : ${_upnp_summary}
  Initial clients : ${CLIENTS_CSV}

EOF
    ask_yn "Proceed?" "y" || die "Aborted by user."

    # ---- do the work --------------------------------------------------------
    install_prereqs
    if [ "$ENABLE_UPNP" = "1" ]; then
        ensure_upnp_root_url
    fi
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

    # ---- UPnP router mappings + iptables rules -----------------------------
    apply_upnp_port_forwards || true
    apply_iptables_rules

    # ---- initial client roster ---------------------------------------------
    # All clients in the CSV are configured; only the FIRST is shown + QR'd.
    log "Creating initial client(s): ${CLIENTS_CSV}"
    local first_conf
    first_conf=$(add_clients_from_csv "$CLIENTS_CSV")

    # ---- stage a copy of ourselves for later subcommands & self-update ------
    install_self_to_state

    # ---- pre-flight doctor check -------------------------------------------
    log "Running connectivity checks (doctor)..."
    local _install_ok=0
    do_doctor && _install_ok=1 || true

    if [ "$_install_ok" = "1" ]; then
        cat <<EOF

${C_GRN}${C_BOLD}AmneziaWG server is up and all checks passed.${C_RST}
  Service       : ${SVC}  ($(systemctl is-active "$SVC"))
  Endpoint      : ${HOST}:${PORT}/udp
  Server pub    : ${SERVER_PUB}
  UPnP         : $([ "${ENABLE_UPNP:-0}" = "1" ] && echo "enabled (timer: $(basename "$UPNP_TIMER")$([ -n "${UPNP_ROOT_URL:-}" ] && printf ', root URL: %s' "$UPNP_ROOT_URL"))" || echo disabled)
  Local script  : ${INSTALLED_SELF}  (also at ${SYMLINK})
  Clients dir   : ${CLIENTS_DIR}

Next steps:
  • Open UDP/${PORT} inbound on any cloud-provider firewall.
  • To add another client:    sudo ${SCRIPT_NAME} add-client <name>
  • To list clients:           sudo ${SCRIPT_NAME} list-clients
  • To revoke a client:        sudo ${SCRIPT_NAME} remove-client <name>
  • To check status:           sudo ${SCRIPT_NAME} status
  • To run health checks:      sudo ${SCRIPT_NAME} doctor
  • To force an update check:  sudo ${SCRIPT_NAME} self-update --force
  • To uninstall:              sudo ${SCRIPT_NAME} uninstall [--purge]
EOF

        # ---- render the FIRST client (config + QR) -------------------------
        if [ -n "$first_conf" ] && [ -f "$first_conf" ]; then
            echo
            info "Showing the first client only. The rest are saved as ${CLIENTS_DIR}/<host>-<name>.conf"
            info "and can be re-rendered any time with: sudo ${SCRIPT_NAME} show-client <name>"
            show_client_payload "$first_conf"
        fi
    else
        cat <<EOF

${C_YLW}${C_BOLD}AmneziaWG installed but doctor found connectivity issues (see above).${C_RST}
  Service       : ${SVC}  ($(systemctl is-active "$SVC"))
  Endpoint      : ${HOST}:${PORT}/udp
  Clients dir   : ${CLIENTS_DIR}

Fix the issues reported above, then run:
  sudo ${SCRIPT_NAME} doctor          — re-run checks
  sudo ${SCRIPT_NAME} show-client <name>  — print config + QR once everything is green
EOF
    fi

    # ---- drop the user into a shell at the install dir so they can keep ----
    # working with the script and the clients/ directory locally. exec()
    # replaces this process, so anything below MUST run before the exec.
    drop_into_install_shell
}

drop_into_install_shell() {
    # Skip in non-interactive runs and when the operator opted out.
    [ "${AMNEZIA_NONINTERACTIVE:-0}" = "1" ] && return 0
    [ "${AMNEZIA_NO_SHELL_DROP:-0}" = "1" ] && return 0
    # Only meaningful when we have a tty to drop into. The same probe we use
    # at the entrypoint applies here — `[ -t 0 ]` already covers our redirected
    # case because main was invoked with </dev/tty in the pipe-to-bash flow.
    [ -t 0 ] || return 0

    [ -d "$STATE_DIR" ] || return 0

    if ! ask_yn "Drop into a shell at ${STATE_DIR} so you can keep working with the script?" "y"; then
        info "Skipping shell drop. You can return any time with: cd ${STATE_DIR}"
        return 0
    fi

    cd "$STATE_DIR" || { warn "Could not cd to $STATE_DIR; staying put."; return 0; }
    local sh="${SHELL:-/bin/bash}"
    [ -x "$sh" ] || sh="/bin/bash"
    info "Launching ${sh} in ${PWD}. Type 'exit' to leave."
    # `exec` so the user's shell becomes the process the original caller
    # waits on; works inside `curl | sudo bash` because main's stdin was
    # redirected from /dev/tty at the entrypoint.
    exec "$sh"
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
  sudo $0 [install]                  # interactive install (default).
                                     # On a host with an existing install,
                                     # opens an interactive menu (add/list/show/
                                     # remove/status/reinstall/uninstall/exit).
  sudo $0 menu                       # same management menu without trying to install.
  sudo $0 add-client    <names>      # comma-separated names accepted, e.g. "alice,bob".
  sudo $0 remove-client <name>
  sudo $0 list-clients
  sudo $0 show-client   <name>
  sudo $0 status
  sudo $0 doctor                     # check service, port, firewall, sysctl, nftables, etc.
  sudo $0 secure-boot-fix            # queue Ubuntu MOK enrollment for DKMS modules
  sudo $0 self-update [--force]      # force a network check + re-exec
  sudo $0 version
  sudo $0 uninstall [--purge]

Client config files are stored as ${CLIENTS_DIR}/<host>-<name>.conf
so a bulk import into the AmneziaVPN client app stays self-describing.
After install the script lives at ${INSTALLED_SELF}
and is symlinked at ${SYMLINK}, so 'sudo ${SCRIPT_NAME} <cmd>' works directly.
The script auto-checks for updates against the URL above (cached for 24 h).
Set AMNEZIA_NO_UPDATE_CHECK=1 to suppress; AMNEZIA_FORCE_CLEANUP=1 to skip the
existing-install-detection prompt during reinstalls; AMNEZIA_NO_SHELL_DROP=1
to skip the post-install 'cd into install dir' shell drop;
AMNEZIA_MANAGE_IPTABLES=0 to skip all iptables rule management;
AMNEZIA_ENABLE_UPNP=1 to install miniupnpc and keep router UPnP UDP forwards
AMNEZIA_UPNP_ROOT_URL=http://192.168.1.1:5000/rootDesc.xml to bypass flaky UPnP discovery
refreshed by systemd (default is disabled / prompted as "n").
AMNEZIA_SECURE_BOOT_MOK=1 queues Ubuntu MOK enrollment when Secure Boot rejects
the DKMS module; this still requires reboot-time MokManager confirmation.

See the comment header at the top of this script for non-interactive env vars.
EOF
}

main() {
    local cmd="${1:-install}"

    # Skip the network call for read-only / diagnostic / destructive / help
    # commands. For everything else, opportunistically self-update (cached 24 h).
    case "$cmd" in
        -h|--help|help|version|--version|uninstall|status|list-clients|doctor) ;;
        *) self_update "$@" ;;
    esac

    case "$cmd" in
        install)
            shift || true
            do_install "$@"
            ;;
        menu)
            need_root
            [ -r "$META_FILE" ] || die "No installation found at $META_FILE; run '$0 install' first."
            # The menu function returns 0 if the user picks "Cleanup and reinstall"
            # — in that case we fall through to do_install. Otherwise it has
            # already exited the script for us.
            if existing_install_menu; then
                cleanup_existing_awg
                do_install
            fi
            ;;
        add-client)
            need_root; shift
            local arg="${1:-}"
            [ -n "$arg" ] || die "Usage: $0 add-client <name>[,<name>,...]"
            # Accept either a single name or a comma-separated list.
            if [[ "$arg" == *,* ]]; then
                load_meta
                local first
                first=$(add_clients_from_csv "$arg")
                [ -n "$first" ] && show_client_payload "$first"
                info "All clients written under ${CLIENTS_DIR}/"
            else
                add_client "$arg"
            fi
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
        doctor)
            need_root
            _rc=0; do_doctor || _rc=$?; exit "$_rc"
            ;;
        secure-boot-fix)
            need_root
            prepare_secure_boot_mok_enrollment
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
