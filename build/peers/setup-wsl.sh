#!/bin/sh
#
# The ACME peers of the interop tests, installed into WSL - or into a
# Debian 13 container of CI, where this runs as root already.
#
#   wsl -u root sh build/peers/setup-wsl.sh            install what is missing
#   wsl sh build/peers/setup-wsl.sh --check            only say what is there
#
# From Debian: certbot (+ the RFC 2136 plugin), acme.sh, Pebble and its
# challenge test server, BIND for dns-01 by RFC 2136, dehydrated, uacme,
# openssl and curl. From upstream, pinned in pins.env: lego, whose Debian
# package is three years behind.
#
# BIND is installed for its named and nsupdate only: the suite starts a named
# of its own per test, on a port of its own. Where this script is what
# installed it, the service Debian starts is stopped again, so that nothing of
# this answers on port 53; a BIND that was there before is left as it was.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
. "$here/pins.env"

APT_PACKAGES="curl ca-certificates openssl rsync certbot python3-certbot-dns-rfc2136 acme.sh pebble bind9 bind9-dnsutils dehydrated uacme"

version_of() {
    case "$1" in
        lego)                 lego --version 2>/dev/null | head -n1 ;;
        certbot)              certbot --version 2>&1 | head -n1 ;;
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
        dotnet)               dotnet --version 2>/dev/null ;;
    esac
}

check() {
    missing=0
    for tool in lego certbot acme.sh pebble pebble-challtestsrv named nsupdate dehydrated uacme openssl curl rsync dotnet; do
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
    return $missing
}

if [ "${1:-}" = "--check" ]; then
    check
    exit $?
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Installing needs root: wsl -u root sh build/peers/setup-wsl.sh" >&2
    exit 1
fi

bind_was_there=0
dpkg-query -W -f='${Status}' bind9 2>/dev/null | grep -q "install ok installed" && bind_was_there=1

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends $APT_PACKAGES

if [ $bind_was_there -eq 0 ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet named 2>/dev/null; then
    systemctl disable --now named >/dev/null 2>&1 || true
fi

if ! lego --version 2>/dev/null | grep -q "$LEGO_VERSION"; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    curl -fsSL -o "$tmp/lego.tar.gz" \
        "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_amd64.tar.gz"
    echo "${LEGO_SHA256}  $tmp/lego.tar.gz" | sha256sum -c -
    tar -xzf "$tmp/lego.tar.gz" -C "$tmp" lego
    install -m 0755 "$tmp/lego" /usr/local/bin/lego
fi

check
