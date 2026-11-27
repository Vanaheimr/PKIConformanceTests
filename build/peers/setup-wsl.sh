#!/bin/sh
#
# The ACME peers of the interop tests, installed into WSL - or into a
# Debian 13 container of CI, where this runs as root already.
#
#   wsl -u root sh build/peers/setup-wsl.sh                  install what is missing
#   wsl -u root sh build/peers/setup-wsl.sh --with-boulder   and Boulder (Docker)
#   sudo sh build/peers/setup-wsl.sh --only-boulder          Boulder alone, on any Debian or Ubuntu
#   wsl sh build/peers/setup-wsl.sh --check                  only say what is there
#
# From Debian: certbot (+ the RFC 2136 plugin), acme.sh (+ socat, its web
# server), Pebble and its
# challenge test server, BIND for dns-01 by RFC 2136, dehydrated, uacme,
# openssl and curl. From upstream, pinned in pins.env: lego, whose Debian
# package is three years behind; step-ca, which Debian does not have; and
# Pebble once more, beside Debian's, at its current version.
#
# Boulder only with --with-boulder or --only-boulder: its source at the
# pinned tag, and the images of its compose stack pulled - several GB, for
# the Docker lane alone; --only-boulder is what that lane runs, with dig,
# openssl and curl beside it.
#
# BIND is installed for its named and nsupdate only: the suite starts a named
# of its own per test, on a port of its own. Where this script is what
# installed it, the service Debian starts is stopped again, so that nothing of
# this answers on port 53; a BIND that was there before is left as it was.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
. "$here/pins.env"

# Where the upstream peers that are no single binary on the PATH go - Pebble
# beside Debian's, Boulder's source - as the suite looks for them (Peers/).
LIB=/usr/local/lib/pkiconformance
PEBBLE_DIR="$LIB/pebble-$PEBBLE_VERSION"
BOULDER_DIR="$LIB/boulder-$BOULDER_VERSION"

APT_PACKAGES="curl ca-certificates openssl rsync socat certbot python3-certbot-dns-rfc2136 acme.sh pebble bind9 bind9-dnsutils dehydrated uacme"

version_of() {
    case "$1" in
        lego)                 lego --version 2>/dev/null | head -n1 ;;
        step-ca)              step-ca version 2>/dev/null | head -n1 ;;
        # As the suite starts it: /usr/local off Python's path (PLAN.md, "Learned in phase 0").
        certbot)              python3 -c 'import sys; sys.path[:] = [p for p in sys.path if not p.startswith("/usr/local/")]; import certbot; print("certbot", certbot.__version__)' 2>&1 | tail -n1 ;;
        acme.sh)              acme.sh --version 2>/dev/null | tail -n1 ;;
        pebble)               dpkg-query -W -f='pebble ${Version}' pebble 2>/dev/null ;;
        pebble-challtestsrv)  dpkg-query -W -f='pebble-challtestsrv ${Version}' pebble 2>/dev/null ;;
        named)                named -v 2>/dev/null | head -n1 ;;
        nsupdate)             dpkg-query -W -f='nsupdate ${Version}' bind9-dnsutils 2>/dev/null ;;
        dehydrated)           dpkg-query -W -f='dehydrated ${Version}' dehydrated 2>/dev/null ;;
        uacme)                dpkg-query -W -f='uacme ${Version}' uacme 2>/dev/null ;;
        openssl)              openssl version 2>/dev/null ;;
        curl)                 curl --version 2>/dev/null | head -n1 ;;
        rsync)                rsync --version 2>/dev/null | head -n1 ;;
        socat)                socat -V 2>/dev/null | grep -m1 "socat version" ;;
        dig)                  dig -v 2>&1 | head -n1 ;;
        unshare)              unshare --version 2>/dev/null | head -n1 ;;
        dotnet)               dotnet --version 2>/dev/null ;;
    esac
}

check() {
    missing=0
    for tool in lego step-ca certbot acme.sh socat pebble pebble-challtestsrv named nsupdate dig dehydrated uacme openssl curl rsync unshare dotnet; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf '  %-20s %s\n' "$tool" "$(version_of "$tool")"
        else
            printf '  %-20s MISSING\n' "$tool"
            missing=$((missing + 1))
        fi
    done
    if command -v lego >/dev/null 2>&1 && ! lego --version 2>/dev/null | grep -q "$LEGO_VERSION"; then
        printf '  lego is not the pinned %s\n' "$LEGO_VERSION"
        missing=$((missing + 1))
    fi
    if command -v step-ca >/dev/null 2>&1 && ! step-ca version 2>/dev/null | grep -q "$STEPCA_VERSION"; then
        printf '  step-ca is not the pinned %s\n' "$STEPCA_VERSION"
        missing=$((missing + 1))
    fi
    for tool in pebble pebble-challtestsrv; do
        if [ -x "$PEBBLE_DIR/$tool" ]; then
            printf '  %-20s %s\n' "$tool $PEBBLE_VERSION" "$PEBBLE_DIR/$tool"
        else
            printf '  %-20s MISSING\n' "$tool $PEBBLE_VERSION"
            missing=$((missing + 1))
        fi
    done
    # Boulder is the Docker lane's alone: its absence fails no check.
    if [ -d "$BOULDER_DIR/.git" ]; then
        printf '  %-20s %s at %s\n' "boulder" "$BOULDER_VERSION" "$(git -C "$BOULDER_DIR" rev-parse --short HEAD 2>/dev/null)"
    else
        printf '  %-20s not installed (--with-boulder)\n' "boulder"
    fi
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        printf '  %-20s %s\n' "docker" "$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
    else
        printf '  %-20s no daemon reachable (Boulder only)\n' "docker"
    fi
    return $missing
}

# A release archive of upstream, checked against its pin and unpacked into
# a directory of its own:  fetch URL SHA256 DIRECTORY
fetch() {
    archive="$3/$(basename "$1")"
    curl -fsSL -o "$archive" "$1"
    echo "$2  $archive" | sha256sum -c -
    tar -xzf "$archive" -C "$3"
}

if [ "${1:-}" = "--check" ]; then
    check
    exit $?
fi

with_boulder=0
[ "${1:-}" = "--with-boulder" ] && with_boulder=1

only_boulder=0
[ "${1:-}" = "--only-boulder" ] && only_boulder=1

if [ "$(id -u)" -ne 0 ]; then
    echo "Installing needs root: wsl -u root sh build/peers/setup-wsl.sh" >&2
    exit 1
fi

bind_was_there=0
dpkg-query -W -f='${Status}' bind9 2>/dev/null | grep -q "install ok installed" && bind_was_there=1

install_boulder() {
    command -v git >/dev/null 2>&1 || apt-get install -y -qq --no-install-recommends git
    if [ ! -d "$BOULDER_DIR/.git" ]; then
        mkdir -p "$LIB"
        git -c advice.detachedHead=false clone -q --depth 1 --branch "$BOULDER_VERSION" https://github.com/letsencrypt/boulder "$BOULDER_DIR"
    fi
    commit=$(git -C "$BOULDER_DIR" rev-parse HEAD)
    if [ "$commit" != "$BOULDER_COMMIT" ]; then
        echo "Boulder $BOULDER_VERSION is $commit, not the pinned $BOULDER_COMMIT" >&2
        exit 1
    fi
    (cd "$BOULDER_DIR" && BOULDER_TOOLS_TAG="$BOULDER_TOOLS_TAG" BOULDER_VTCOMBOSERVER_TAG="$BOULDER_VTCOMBOSERVER_TAG" BOULDER_SUNLIGHT_TAG="$BOULDER_SUNLIGHT_TAG" docker compose pull -q)
}

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

if [ $only_boulder -eq 1 ]; then
    apt-get install -y -qq --no-install-recommends git curl ca-certificates openssl bind9-dnsutils
    install_boulder
    exit 0
fi

apt-get install -y -qq --no-install-recommends $APT_PACKAGES

if [ $bind_was_there -eq 0 ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet named 2>/dev/null; then
    systemctl disable --now named >/dev/null 2>&1 || true
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if ! lego --version 2>/dev/null | grep -q "$LEGO_VERSION"; then
    mkdir -p "$tmp/lego"
    fetch "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_amd64.tar.gz" "$LEGO_SHA256" "$tmp/lego"
    install -m 0755 "$tmp/lego/lego" /usr/local/bin/lego
fi

if ! step-ca version 2>/dev/null | grep -q "$STEPCA_VERSION"; then
    mkdir -p "$tmp/step-ca"
    fetch "https://github.com/smallstep/certificates/releases/download/v${STEPCA_VERSION}/step-ca_linux_amd64.tar.gz" "$STEPCA_SHA256" "$tmp/step-ca"
    install -m 0755 "$(find "$tmp/step-ca" -type f -name step-ca | head -n1)" /usr/local/bin/step-ca
fi

if [ ! -x "$PEBBLE_DIR/pebble" ] || [ ! -x "$PEBBLE_DIR/pebble-challtestsrv" ]; then
    mkdir -p "$tmp/pebble" "$PEBBLE_DIR"
    fetch "https://github.com/letsencrypt/pebble/releases/download/v${PEBBLE_VERSION}/pebble-linux-amd64.tar.gz" "$PEBBLE_SHA256" "$tmp/pebble"
    fetch "https://github.com/letsencrypt/pebble/releases/download/v${PEBBLE_VERSION}/pebble-challtestsrv-linux-amd64.tar.gz" "$PEBBLE_CHALLTESTSRV_SHA256" "$tmp/pebble"
    install -m 0755 "$(find "$tmp/pebble" -type f -name pebble | head -n1)"              "$PEBBLE_DIR/pebble"
    install -m 0755 "$(find "$tmp/pebble" -type f -name pebble-challtestsrv | head -n1)" "$PEBBLE_DIR/pebble-challtestsrv"
fi

if [ $with_boulder -eq 1 ]; then
    install_boulder
fi

check
