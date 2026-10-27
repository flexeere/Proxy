#!/usr/bin/env bash
# Flexeere Proxy Manager 1.0.0 | 2026-10-27
# Standalone Squid HTTP forward proxy; HTTPS uses CONNECT, without TLS interception.
# Intended OS: Ubuntu 22.04/24.04/26.04, Debian 12/13, CentOS Stream 9/10.
# Run: sudo bash flexeere-proxy.sh
# This file is also its own documentation: bash flexeere-proxy.sh --help

set -Eeuo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
umask 077

VERSION=1.0.0
CONF=/etc/squid/squid.conf
PASSFILE=/etc/squid/flexeere.passwd
STATE=/etc/flexeere-proxy
SETTINGS=$STATE/settings.json
BACKUPS=/var/backups/flexeere-proxy
MANAGER=/usr/local/sbin/flexeere-proxy
OS_RELEASE=/etc/os-release
LOG_DIR=/var/log/squid
UFW_DIR=/etc/ufw/applications.d
MARKER='# Managed by Flexeere Proxy Manager'
PORT='' ALLOW='' USERNAME='' PASSWORD='' ZONE='' FW_MODE=auto
PASS_STDIN=0 TAKEOVER=0 GENERATED=0
TX='' TX_ACTIVE=0 WAS_ACTIVE=0 WAS_ENABLED=0
NEW_UFW='' NEW_FW_RUNTIME=0 NEW_FW_PERMANENT=0 NEW_SELINUX=0
FW_BACKEND=none FW_ZONE='' FW_RUNTIME=0 FW_PERMANENT=0 SELINUX_OWNED=0
OLD_PORT='' OLD_BACKEND=none OLD_ZONE='' OLD_RUNTIME=0 OLD_PERMANENT=0 OLD_SELINUX=0
OS_ID='' OS_VERSION='' RUN_USER='' RUN_GROUP='' AUTH_HELPER=''

say() { printf '%s\n' "$*"; }
warn() { printf 'NOTICE: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'HELP'
Flexeere Proxy Manager — port enter karke authenticated proxy banayein.

  sudo bash flexeere-proxy.sh                  Interactive menu
  sudo bash flexeere-proxy.sh install          Guided installation
  sudo bash flexeere-proxy.sh install --port 8080 --username flexeere
  sudo flexeere-proxy port 9090                Replace the current listening port
  sudo flexeere-proxy add-user customer1       Add user / change its password
  sudo flexeere-proxy delete-user customer1    Remove user (last user is protected)
  sudo flexeere-proxy users                   List usernames, without passwords
  sudo flexeere-proxy allow 203.0.113.10/32     Restrict client IP; comma-separated
  sudo flexeere-proxy allow all               Any source IP, login still required
  sudo flexeere-proxy status
  sudo flexeere-proxy restart

Install options:
  --port NUMBER         Listening TCP port 1-65535; default 3128
  --username NAME       1-64 letters, digits, dot, underscore or dash
  --allow IP/CIDR,...    Allowed IPv4 client networks; default all authenticated
  --password-stdin      Read one password line from stdin; never pass in argv
  --takeover            Back up and replace a pre-existing unmanaged Squid config
  --firewall auto|none  Use active firewalld/UFW, or leave rules to administrator
  --zone NAME           firewalld ingress zone, useful with multiple active zones

Without a terminal, install requires --port and --username and either reads
--password-stdin or generates a random password. Blank interactive password also
generates a password. Passwords must contain 12-72 printable ASCII characters.

One listening port is managed at a time; all users share it. IPv4 clients are
supported. Destination HTTP ports: 80/8080; HTTPS CONNECT ports: 443/8443.
Local/private/link-local destinations and the server's assigned IPs are blocked.
The password is required even for localhost. No disk response caching is enabled.

Passwords are stored as bcrypt hashes. New/generated passwords are shown once.
Proxy Basic login is not encrypted on the client-to-proxy HTTP connection:
use a trusted network, VPN or SSH tunnel for that connection.

Test from your computer (curl prompts for the password):
  curl --noproxy '' --proxy http://SERVER_IP:8080 --proxy-user flexeere https://example.com

Change port and allow commands accept --firewall auto|none and --zone NAME.
When no managed firewall is active, custom nftables/iptables and upstream/cloud
firewall rules need to be allowed separately. The script never flushes rules,
enables a firewall, disables SELinux, changes SSH, or changes IP forwarding.

Files: /etc/squid/squid.conf, /etc/squid/flexeere.passwd,
       /etc/flexeere-proxy/settings.json
Backups: /var/backups/flexeere-proxy/<timestamp>/
Logs: /var/log/squid/access.log and /var/log/squid/cache.log
Config/password/settings files and new firewall/SELinux additions are rolled
back on failed changes. Installed packages are retained after failure. Rules
that existed before installation are retained. Backups contain password hashes;
they are root-only. Package-provided log rotation remains in use.
After an administrator changes the main config, port/allow commands regenerate
the managed file; an external custom config is never overwritten silently.

CentOS Linux 7/8 and Stream 8 are unsupported because their normal support ended.
All commands need root except --help/--version. A systemd VM/server and working
OS package repositories are required; containers without systemd are excluded.
HELP
}

require_root() {
    (( EUID == 0 )) || die 'Root se chalayein: sudo bash flexeere-proxy.sh'
}

detect_os() {
    [[ -f $OS_RELEASE ]] || die '/etc/os-release nahi mila.'
    # This is the operating system-owned file, never the user-managed state.
    # shellcheck disable=SC1090
    . "$OS_RELEASE"
    OS_ID=${ID:-unknown}; OS_VERSION=${VERSION_ID:-unknown}
    case "$OS_ID:$OS_VERSION" in
        ubuntu:22.04|ubuntu:24.04|ubuntu:26.04|debian:12|debian:13) ;;
        centos:9|centos:10)
            [[ ${PRETTY_NAME:-} == *Stream* ]] || die 'CentOS Stream 9/10 chahiye.' ;;
        *) die "Unsupported OS: ${PRETTY_NAME:-$OS_ID $OS_VERSION}. Ubuntu 22.04/24.04/26.04, Debian 12/13, CentOS Stream 9/10 use karein." ;;
    esac
}

require_systemd() {
    [[ -d /run/systemd/system ]] || die 'Running systemd chahiye; Proxmox VM use karein.'
    command -v systemctl >/dev/null || die 'systemctl nahi mila.'
}

validate_port() {
    [[ $1 =~ ^[0-9]{1,5}$ ]] || die 'Port 1 se 65535 ke beech hona chahiye.'
    local value=$((10#$1))
    (( value >= 1 && value <= 65535 )) || die 'Port 1 se 65535 ke beech hona chahiye.'
    PORT=$value
}

validate_user() {
    [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || die 'Username: 1-64 letters/digits/._-; first character letter/digit.'
}

normalize_allow() {
    python3 - "$1" <<'PY'
import ipaddress, sys
value = sys.argv[1].strip()
if value == 'all':
    print('all'); sys.exit(0)
try:
    networks = []
    for item in value.split(','):
        net = ipaddress.ip_network(item.strip(), strict=False)
        if net.version != 4:
            raise ValueError('Only IPv4 client CIDRs are supported')
        if str(net) not in networks:
            networks.append(str(net))
    if not 1 <= len(networks) <= 100:
        raise ValueError('Supply 1-100 networks')
    print(','.join(networks))
except ValueError as exc:
    print('Invalid allowed client IP/CIDR: ' + str(exc), file=sys.stderr)
    sys.exit(1)
PY
}

read_password() {
    local confirm=''
    GENERATED=0
    if (( PASS_STDIN )); then
        IFS= read -r PASSWORD || [[ -n $PASSWORD ]] || die 'stdin par password line dein.'
        [[ -n $PASSWORD ]] || die 'Empty stdin password allowed nahi hai.'
    elif [[ -t 0 ]]; then
        IFS= read -r -s -p 'Password (blank = auto-generate): ' PASSWORD
        printf '\n'
        if [[ -n $PASSWORD ]]; then
            IFS= read -r -s -p 'Confirm password: ' confirm
            printf '\n'
            [[ $PASSWORD == "$confirm" ]] || die 'Passwords match nahi hue.'
        fi
    fi
    if [[ -z $PASSWORD ]]; then
        PASSWORD=$(python3 -c 'import secrets; print(secrets.token_hex(12))')
        GENERATED=1
    fi
    [[ ${#PASSWORD} -ge 5 && ${#PASSWORD} -le 25 && $PASSWORD != *[![:print:]]* ]] ||
        die 'Password 5-25 printable ASCII characters ka rakhein.'
}

parse_options() {
    while (( $# )); do
        case "$1" in
            --port|--username|--allow|--firewall|--zone)
                (( $# >= 2 )) || die "$1 ke baad value dein."
                case "$1" in
                    --port) PORT=$2 ;;
                    --username) USERNAME=$2 ;;
                    --allow) ALLOW=$2 ;;
                    --firewall) FW_MODE=$2 ;;
                    --zone) ZONE=$2 ;;
                esac
                shift 2 ;;
            --password-stdin) PASS_STDIN=1; shift ;;
            --takeover) TAKEOVER=1; shift ;;
            *) die "Unknown option: $1 (use --help)." ;;
        esac
    done
    [[ $FW_MODE == auto || $FW_MODE == none ]] || die '--firewall auto ya none use karein.'
    [[ -z $ZONE || $ZONE =~ ^[A-Za-z0-9_-]+$ ]] || die 'Invalid firewalld zone.'
}

install_packages() {
    say "OS: $OS_ID $OS_VERSION — Squid aur dependencies install ho rahi hain..."
    case "$OS_ID" in
        ubuntu|debian)
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                squid apache2-utils python3 curl ca-certificates iproute2 util-linux ;;
        centos)
            dnf install -y squid httpd-tools python3 curl ca-certificates iproute util-linux policycoreutils-python-utils ;;
    esac
}

find_runtime() {
    command -v squid >/dev/null || die 'Squid install nahi hai.'
    command -v htpasswd >/dev/null || die 'htpasswd nahi mila.'
    command -v python3 >/dev/null || die 'python3 nahi mila.'
    local candidate version
    version=$(squid -v 2>&1)
    [[ $version != *'Version 8.'* ]] || die 'Squid 8 configuration requires a separate migration; Squid 5/6/7 package use karein.'
    for candidate in /usr/lib/squid/basic_ncsa_auth /usr/lib64/squid/basic_ncsa_auth /usr/libexec/squid/basic_ncsa_auth; do
        if [[ -x $candidate ]]; then AUTH_HELPER=$candidate; break; fi
    done
    [[ -n $AUTH_HELPER ]] || die 'basic_ncsa_auth helper nahi mila.'
    if [[ $OS_ID == centos ]]; then RUN_USER=squid; else RUN_USER=proxy; fi
    id "$RUN_USER" >/dev/null 2>&1 || die "Squid account $RUN_USER missing hai."
    RUN_GROUP=$(id -gn "$RUN_USER")
}

is_managed() {
    [[ -f $CONF && -f $SETTINGS ]] && [[ $(head -n 1 "$CONF") == "$MARKER" ]]
}

load_settings() {
    is_managed || die 'Pehle install chalayein; managed configuration nahi mili.'
    local loaded
    loaded=$(python3 - "$SETTINGS" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d['schema'] == 1 and type(d['port']) is int and 1 <= d['port'] <= 65535
assert d['firewall'] in ('none', 'ufw', 'firewalld')
for key in ('allow', 'zone'):
    assert isinstance(d[key], str) and '\n' not in d[key] and '\r' not in d[key]
print(d['port'], d['allow'], d['firewall'], d['zone'] or '-',
      int(d['runtime_owned']), int(d['permanent_owned']), int(d['selinux_owned']), sep='\n')
PY
    ) || die 'settings.json invalid hai; backup restore karein.'
    local -a fields
    mapfile -t fields <<< "$loaded"
    OLD_PORT=${fields[0]}; PORT=$OLD_PORT; ALLOW=${fields[1]}
    OLD_BACKEND=${fields[2]}; OLD_ZONE=${fields[3]}; [[ $OLD_ZONE == - ]] && OLD_ZONE=''
    OLD_RUNTIME=${fields[4]}; OLD_PERMANENT=${fields[5]}; OLD_SELINUX=${fields[6]}
    ALLOW=$(normalize_allow "$ALLOW") || die 'Saved client ACL invalid hai.'
}

assert_regular_paths() {
    local p
    for p in "$CONF" "$PASSFILE" "$STATE" "$SETTINGS" "$BACKUPS" "$MANAGER"; do
        [[ ! -L $p ]] || die "Symlink path refused: $p"
    done
}

begin_transaction() {
    assert_regular_paths
    NEW_UFW=''; NEW_FW_RUNTIME=0; NEW_FW_PERMANENT=0; NEW_SELINUX=0
    install -d -m 700 "$STATE" "$BACKUPS"
    TX=$(mktemp -d "$BACKUPS/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
    local key path
    for key in conf passwd settings; do
        case "$key" in conf) path=$CONF;; passwd) path=$PASSFILE;; settings) path=$SETTINGS;; esac
        if [[ -f $path ]]; then cp -a -- "$path" "$TX/$key"; fi
    done
    systemctl is-active --quiet squid && WAS_ACTIVE=1 || WAS_ACTIVE=0
    systemctl is-enabled --quiet squid && WAS_ENABLED=1 || WAS_ENABLED=0
    printf 'Prior active=%s enabled=%s\n' "$WAS_ACTIVE" "$WAS_ENABLED" > "$TX/service-state.txt"
    TX_ACTIVE=1
    say "Configuration backup: $TX"
}

restore_files() {
    local key path
    for key in conf passwd settings; do
        case "$key" in conf) path=$CONF;; passwd) path=$PASSFILE;; settings) path=$SETTINGS;; esac
        if [[ -f $TX/$key ]]; then cp -a -- "$TX/$key" "$path"; else rm -f -- "$path"; fi
    done
}

cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    if (( TX_ACTIVE )); then
        warn "Change fail/cancel hua; previous files aur service restore ho rahe hain. Backup: $TX"
        systemctl stop squid >/dev/null 2>&1
        restore_files
        if [[ -n $NEW_UFW ]]; then
            ufw --force delete allow "$NEW_UFW" >/dev/null 2>&1
            rm -f -- "$UFW_DIR/$NEW_UFW"
        fi
        (( NEW_FW_RUNTIME )) && firewall-cmd --zone="$FW_ZONE" --remove-port="$PORT/tcp" >/dev/null 2>&1
        (( NEW_FW_PERMANENT )) && firewall-cmd --permanent --zone="$FW_ZONE" --remove-port="$PORT/tcp" >/dev/null 2>&1
        (( NEW_SELINUX )) && semanage port -d -p tcp "$PORT" >/dev/null 2>&1
        if (( WAS_ENABLED )); then systemctl enable squid >/dev/null 2>&1; else systemctl disable squid >/dev/null 2>&1; fi
        if (( WAS_ACTIVE )); then
            systemctl start squid >/dev/null 2>&1 || warn 'Old service restart failed; backup aur journalctl -u squid check karein.'
        fi
        (( rc == 0 )) && rc=1
    fi
    PASSWORD=''
    exit "$rc"
}

check_port_available() {
    local listeners line
    listeners=$(ss -H -ltnp "sport = :$PORT")
    # A package installation may already have started Squid on its default port.
    # That listener will be replaced by the same service's controlled restart.
    while IFS= read -r line; do
        [[ -z $line ]] && continue
        [[ $line =~ users:\(\(\"squid(-[0-9]+)?\" ]] ||
            die "TCP port $PORT already in use hai. Dusra port select karein."
    done <<< "$listeners"
}

write_user() {
    local tmp reply
    tmp=$(mktemp "$(dirname "$PASSFILE")/.flexeere-passwd.XXXXXX")
    if [[ -f $PASSFILE ]]; then cp -- "$PASSFILE" "$tmp"; fi
    # -i reads the password from stdin, never from process arguments.
    if ! printf '%s\n' "$PASSWORD" | htpasswd -iB -C 10 "$tmp" "$USERNAME" >/dev/null 2>&1; then
        rm -f -- "$tmp"; die 'Password hash create nahi hua.'
    fi
    chown "root:$RUN_GROUP" "$tmp"
    chmod 640 "$tmp"
    mv -f -- "$tmp" "$PASSFILE"
    command -v restorecon >/dev/null && restorecon "$PASSFILE" || true
    reply=$(printf '%s' "$PASSWORD" | python3 -c \
        'import sys, urllib.parse; print(sys.argv[1]+" "+urllib.parse.quote(sys.stdin.read(),safe=""))' "$USERNAME" | \
        runuser -u "$RUN_USER" -- "$AUTH_HELPER" "$PASSFILE")
    [[ $reply == OK* ]] || die 'Squid helper bcrypt/password verify nahi kar saka; packages update karein.'
}

server_addresses() {
    ip -j address show | python3 -c '
import json, sys
addresses = {"127.0.0.1"}
for interface in json.load(sys.stdin):
    for address in interface.get("addr_info", []):
        value = address.get("local", "")
        if value and "%" not in value:
            addresses.add(value)
print(" ".join(sorted(addresses)))'
}

write_config() {
    local tmp local_ips sources
    tmp=$(mktemp "$(dirname "$CONF")/.flexeere-conf.XXXXXX")
    local_ips=$(server_addresses)
    cat > "$tmp" <<CONFIG
$MARKER
# Generated settings: sudo flexeere-proxy --help
http_port 0.0.0.0:$PORT
visible_hostname flexeere-proxy
cache_effective_user $RUN_USER
cache_effective_group $RUN_GROUP

auth_param basic program $AUTH_HELPER $PASSFILE
auth_param basic children 10 startup=2 idle=2
auth_param basic realm Flexeere Proxy
auth_param basic credentialsttl 1 minute
acl authenticated proxy_auth REQUIRED
acl loopback_client src 127.0.0.1/32
acl Safe_ports port 80 443 8080 8443
acl SSL_ports port 443 8443
acl CONNECT method CONNECT
acl unsafe_dst dst 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4 ::/128 ::1/128 fc00::/7 fe80::/10 ff00::/8
acl local_server dst $local_ips

http_access deny manager
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
# Authenticate before DNS-dependent destination ACLs.
http_access deny !authenticated
http_access deny unsafe_dst
http_access deny local_server
http_access allow loopback_client authenticated
CONFIG
    if [[ $ALLOW == all ]]; then
        printf 'http_access allow authenticated\n' >> "$tmp"
    else
        sources=${ALLOW//,/ }
        printf 'acl permitted_clients src %s\nhttp_access allow permitted_clients authenticated\n' "$sources" >> "$tmp"
    fi
    cat >> "$tmp" <<'CONFIG'
http_access deny all

cache deny all
cache_mem 32 MB
maximum_object_size_in_memory 0 KB
CONFIG
    printf 'access_log stdio:%s/access.log squid\ncache_log %s/cache.log\n' "$LOG_DIR" "$LOG_DIR" >> "$tmp"
    cat >> "$tmp" <<'CONFIG'
cache_store_log none
logfile_rotate 7
shutdown_lifetime 1 seconds
CONFIG
    chmod 644 "$tmp"
    chown root:root "$tmp"
    mv -f -- "$tmp" "$CONF"
    command -v restorecon >/dev/null && restorecon "$CONF" || true
    if ! squid -k parse -f "$CONF" > "$TX/parse.log" 2>&1; then
        tail -n 30 "$TX/parse.log" >&2
        die 'Squid configuration validation fail hui.'
    fi
}

configure_selinux() {
    SELINUX_OWNED=0
    if [[ $PORT == "$OLD_PORT" ]]; then SELINUX_OWNED=$OLD_SELINUX; fi
    command -v selinuxenabled >/dev/null && selinuxenabled || return 0
    command -v semanage >/dev/null || die 'SELinux ke liye policycoreutils-python-utils install karein.'
    local port_types
    port_types=$(semanage port -l | python3 -c '
import sys
port = int(sys.argv[1])
for line in sys.stdin:
    parts = line.split()
    if len(parts) < 3 or parts[1] != "tcp": continue
    for entry in "".join(parts[2:]).split(","):
        try:
            bounds = [int(n) for n in entry.split("-")]
            if bounds[0] <= port <= bounds[-1]: print(parts[0]); break
        except ValueError: pass
' "$PORT")
    if [[ $port_types == *squid_port_t* || $port_types == *http_cache_port_t* ]]; then return 0; fi
    # Generic unreserved/port types are ranges and permit an explicit override.
    if [[ -n $port_types ]] && printf '%s\n' "$port_types" | grep -Ev '^(unreserved_port_t|port_t|ephemeral_port_t)$' >/dev/null; then
        die "SELinux port $PORT kisi aur service ko assigned hai ($port_types). Dusra unused port choose karein."
    fi
    semanage port -a -t squid_port_t -p tcp "$PORT"
    NEW_SELINUX=1; SELINUX_OWNED=1
}

configure_firewall() {
    FW_BACKEND=none; FW_ZONE=''; FW_RUNTIME=0; FW_PERMANENT=0
    [[ $FW_MODE == none ]] && { warn 'Firewall manual mode: TCP port ko network firewall mein allow karein.'; return 0; }
    local firewalld_active=0 ufw_active=0
    command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1 && firewalld_active=1
    command -v ufw >/dev/null && ufw status | grep -q '^Status: active' && ufw_active=1
    (( firewalld_active && ufw_active )) && die 'UFW aur firewalld dono active hain; --firewall none ke saath manually rules manage karein.'
    if (( firewalld_active )); then
        FW_BACKEND=firewalld
        local -a zones
        mapfile -t zones < <(firewall-cmd --get-active-zones | awk '/^[^[:space:]]/{print $1}')
        if [[ -n $ZONE ]]; then FW_ZONE=$ZONE
        elif (( ${#zones[@]} == 1 )); then FW_ZONE=${zones[0]}
        elif (( ${#zones[@]} == 0 )); then FW_ZONE=$(firewall-cmd --get-default-zone)
        else die 'Multiple firewalld zones active hain. --zone ZONE_NAME dein.'; fi
        firewall-cmd --get-zones | tr ' ' '\n' | grep -Fxq -- "$FW_ZONE" || die "Unknown zone: $FW_ZONE"
        if [[ $PORT == "$OLD_PORT" && $OLD_BACKEND == firewalld && $FW_ZONE == "$OLD_ZONE" ]]; then
            FW_RUNTIME=$OLD_RUNTIME; FW_PERMANENT=$OLD_PERMANENT
        fi
        if ! firewall-cmd --zone="$FW_ZONE" --query-port="$PORT/tcp" >/dev/null; then
            firewall-cmd --zone="$FW_ZONE" --add-port="$PORT/tcp"
            NEW_FW_RUNTIME=1; FW_RUNTIME=1
        fi
        if ! firewall-cmd --permanent --zone="$FW_ZONE" --query-port="$PORT/tcp" >/dev/null; then
            firewall-cmd --permanent --zone="$FW_ZONE" --add-port="$PORT/tcp"
            NEW_FW_PERMANENT=1; FW_PERMANENT=1
        fi
    elif (( ufw_active )); then
        FW_BACKEND=ufw
        local app="FlexeereProxy-$PORT" profile
        profile="$UFW_DIR/$app"
        if [[ $PORT == "$OLD_PORT" && $OLD_BACKEND == ufw && $OLD_RUNTIME == 1 ]]; then
            FW_RUNTIME=1
            ufw allow "$app" >/dev/null
        else
            [[ ! -e $profile && ! -L $profile ]] || die "Existing UFW profile conflict: $profile"
            NEW_UFW=$app
            printf '[%s]\ntitle=Flexeere authenticated proxy\ndescription=Managed by Flexeere Proxy Manager\nports=%s/tcp\n' "$app" "$PORT" > "$profile"
            chmod 644 "$profile"
            ufw allow "$app"
            FW_RUNTIME=1
        fi
    else
        warn "Active UFW/firewalld nahi mila. Custom nftables/iptables."
    fi
}

save_settings() {
    local tmp
    tmp=$(mktemp "$STATE/.settings.XXXXXX")
    python3 - "$PORT" "$ALLOW" "$FW_BACKEND" "$FW_ZONE" "$FW_RUNTIME" "$FW_PERMANENT" "$SELINUX_OWNED" > "$tmp" <<'PY'
import json, sys
port, allow, firewall, zone, runtime, permanent, selinux = sys.argv[1:]
json.dump(dict(schema=1, port=int(port), allow=allow, firewall=firewall, zone=zone,
               runtime_owned=bool(int(runtime)), permanent_owned=bool(int(permanent)),
               selinux_owned=bool(int(selinux))), sys.stdout, indent=2)
print()
PY
    chmod 600 "$tmp"
    mv -f -- "$tmp" "$SETTINGS"
}

verify_service() {
    systemctl enable squid
    if ! systemctl restart squid; then
        journalctl -u squid -n 20 --no-pager >&2 || true
        die 'Squid start nahi hua.'
    fi
    local code='' attempt
    for attempt in {1..15}; do
        if systemctl is-active --quiet squid; then
            code=$(curl --noproxy '' --silent --max-time 2 --output /dev/null --write-out '%{http_code}' \
                --proxy "http://127.0.0.1:$PORT" http://example.com/ || true)
            [[ $code == 407 ]] && return 0
        fi
        sleep 1
    done
    journalctl -u squid -n 20 --no-pager >&2 || true
    die "Local auth check fail (expected HTTP 407, got $code)."
}

retire_old_rules() {
    # Run only after commit. Never remove administrator-owned rules or labels.
    if [[ -n $OLD_PORT ]] && [[ $PORT != "$OLD_PORT" || $FW_BACKEND != "$OLD_BACKEND" || $FW_ZONE != "$OLD_ZONE" ]]; then
        if [[ $OLD_BACKEND == firewalld ]]; then
            if (( OLD_RUNTIME )); then firewall-cmd --zone="$OLD_ZONE" --remove-port="$OLD_PORT/tcp" || warn "Old runtime rule $OLD_PORT remove manually."; fi
            if (( OLD_PERMANENT )); then firewall-cmd --permanent --zone="$OLD_ZONE" --remove-port="$OLD_PORT/tcp" || warn "Old permanent rule $OLD_PORT remove manually."; fi
        elif [[ $OLD_BACKEND == ufw && $OLD_RUNTIME == 1 ]]; then
            if ufw --force delete allow "FlexeereProxy-$OLD_PORT"; then
                rm -f -- "$UFW_DIR/FlexeereProxy-$OLD_PORT"
            else warn "Old UFW profile FlexeereProxy-$OLD_PORT remove manually."; fi
        fi
    fi
    if [[ -n $OLD_PORT && $PORT != "$OLD_PORT" && $OLD_SELINUX == 1 ]]; then
        semanage port -d -p tcp "$OLD_PORT" || warn "Old SELinux port $OLD_PORT remove manually."
    fi
}

apply_change() {
    check_port_available
    configure_selinux
    write_config
    verify_service
    configure_firewall
    save_settings
    TX_ACTIVE=0
    retire_old_rules
}

show_connection() {
    say "Proxy ready: SERVER_PUBLIC_IP:$PORT (HTTP proxy / HTTPS CONNECT)"
    if [[ -n $USERNAME ]]; then say "Username: $USERNAME"; fi
    if (( GENERATED )); then
        say "Generated password: $PASSWORD"
        say 'Is password ko ab save kar lein; plaintext file mein store nahi hota.'
    fi
    say "Allowed clients: $ALLOW (localhost bhi login ke baad allowed hai)"
    say 'Manage later: sudo flexeere-proxy'
    say "Test: curl --noproxy '' --proxy http://SERVER_PUBLIC_IP:$PORT --proxy-user ${USERNAME:-USERNAME} https://example.com"
}

install_proxy() {
    parse_options "$@"
    [[ ! -f $SETTINGS ]] || die 'Already managed. Menu, port, add-user ya allow command use karein.'
    assert_regular_paths
    if [[ -f $CONF && $TAKEOVER == 0 ]]; then
        if [[ -t 0 ]]; then
            local answer
            say 'Existing Squid configuration mili. Backup lekar managed config replace hogi.'
            IFS= read -r -p 'Take over? Type YES: ' answer
            [[ $answer == YES ]] || die 'No changes made.'
        else die 'Existing Squid config: replacement ke liye explicit --takeover dein.'; fi
    fi
    if [[ -z $PORT ]]; then
        [[ -t 0 ]] || die 'Noninteractive install ke liye --port dein.'
        IFS= read -r -p 'Proxy port [3128]: ' PORT; PORT=${PORT:-3128}
    fi
    validate_port "$PORT"
    if [[ -z $USERNAME ]]; then
        [[ -t 0 ]] || die 'Noninteractive install ke liye --username dein.'
        IFS= read -r -p 'Proxy username [flexeere]: ' USERNAME; USERNAME=${USERNAME:-flexeere}
    fi
    validate_user "$USERNAME"
    [[ -n $ALLOW ]] || ALLOW=all
    # Snapshot before package installation, which may start a default service.
    begin_transaction
    install_packages
    find_runtime
    ALLOW=$(normalize_allow "$ALLOW") || die 'Allowed client networks invalid hain.'
    read_password
    install -d -m 755 "$(dirname "$CONF")"
    install -d -o "$RUN_USER" -g "$RUN_GROUP" -m 750 "$LOG_DIR"
    : > "$PASSFILE"
    write_user
    apply_change
    # A manager installation failure must be reported without undoing a working proxy.
    if [[ $(readlink -f -- "${BASH_SOURCE[0]}") != "$MANAGER" ]]; then
        install -o root -g root -m 750 -- "${BASH_SOURCE[0]}" "$MANAGER" || warn 'Manager copy failed; downloaded script se commands chalayein.'
    fi
    show_connection
}

change_port() {
    (( $# )) || die 'Usage: flexeere-proxy port 8080 [--zone public]'
    local requested=$1; shift
    load_settings; parse_options "$@"; validate_port "$requested"
    find_runtime; begin_transaction; apply_change; show_connection
}

change_allow() {
    (( $# )) || die 'Usage: flexeere-proxy allow IP/CIDR,... | all'
    local requested=$1; shift
    load_settings; parse_options "$@"
    ALLOW=$(normalize_allow "$requested") || die 'Allowed client networks invalid hain.'
    find_runtime; begin_transaction; apply_change; show_connection
}

add_user() {
    (( $# )) || die 'Usage: flexeere-proxy add-user USERNAME [--password-stdin]'
    USERNAME=$1; shift
    validate_user "$USERNAME"; load_settings; parse_options "$@"; find_runtime
    read_password; begin_transaction; write_user; verify_service
    TX_ACTIVE=0
    say "User ready: $USERNAME"
    if (( GENERATED )); then say "Generated password: $PASSWORD"; fi
}

delete_user() {
    (( $# == 1 )) || die 'Usage: flexeere-proxy delete-user USERNAME'
    USERNAME=$1
    validate_user "$USERNAME"; load_settings; find_runtime
    awk -F: -v u="$USERNAME" '$1==u{found=1} END{exit !found}' "$PASSFILE" || die 'User nahi mila.'
    [[ $(awk 'NF{n++} END{print n+0}' "$PASSFILE") -gt 1 ]] || die 'Last user delete nahi kar sakte.'
    begin_transaction
    htpasswd -D "$PASSFILE" "$USERNAME" >/dev/null 2>&1
    verify_service; TX_ACTIVE=0
    say "User removed: $USERNAME"
}

show_status() {
    load_settings
    say "Configured proxy port: $PORT | Allowed clients: $ALLOW"
    say "Firewall integration: $OLD_BACKEND ${OLD_ZONE:-}"
    systemctl status squid --no-pager --full || true
    ss -ltn "sport = :$PORT"
    say 'Logs: sudo journalctl -u squid -n 50 --no-pager'
}

menu() {
    local choice value
    say "Flexeere Proxy Manager $VERSION"
    say '1) Install proxy'
    say '2) Change proxy port'
    say '3) Add user / change password'
    say '4) Delete user'
    say '5) List users'
    say '6) Set allowed client IP/CIDR (or all)'
    say '7) Status'
    say '8) Restart'
    say '0) Exit'
    [[ -t 0 ]] || die 'Menu needs a terminal. Use install --port PORT --username USER or --help.'
    IFS= read -r -p 'Option: ' choice
    case "$choice" in
        1) install_proxy ;;
        2) IFS= read -r -p 'New port: ' value; change_port "$value" ;;
        3) IFS= read -r -p 'Username: ' value; add_user "$value" ;;
        4) IFS= read -r -p 'Username: ' value; delete_user "$value" ;;
        5) load_settings; cut -d: -f1 "$PASSFILE" ;;
        6) IFS= read -r -p 'Allowed IPv4 IP/CIDR comma-separated [all]: ' value; change_allow "${value:-all}" ;;
        7) show_status ;;
        8) load_settings; find_runtime; verify_service; say 'Restart successful.' ;;
        0) return ;;
        *) die 'Invalid menu option.' ;;
    esac
}

main() {
    local command=${1:-menu}
    case "$command" in --help|-h|help) usage; return;; --version) say "$VERSION"; return;; esac
    (( $# == 0 )) || shift
    require_root
    detect_os
    require_systemd
    command -v flock >/dev/null || die 'util-linux (flock) install karein.'
    exec 9>/run/lock/flexeere-proxy.lock
    flock -n 9 || die 'Another proxy management command chal raha hai.'
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'printf "ERROR: command failed near line %s.\n" "$LINENO" >&2' ERR
    case "$command" in
        menu) menu ;;
        install) install_proxy "$@" ;;
        port) change_port "$@" ;;
        allow) change_allow "$@" ;;
        add-user) add_user "$@" ;;
        delete-user) delete_user "$@" ;;
        users) load_settings; cut -d: -f1 "$PASSFILE" ;;
        status) show_status ;;
        restart) load_settings; find_runtime; verify_service; say 'Restart successful.' ;;
        *) die "Unknown command: $command (use --help)." ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
