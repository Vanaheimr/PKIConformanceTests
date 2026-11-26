#!/bin/sh
#
# Run a command where the names of the bench resolve to the loopback:
#
#   sh build/bench-namespace.sh dotnet test PKIConformanceTests.slnx ...
#
# Why: the PKI resolves the names of http-01 through the operating system
# (ToDo T-S5, PLAN.md section 0.3), and the real ACME clients of the interop
# tests prove "www.acme.test" by their web servers on the loopback. Until the
# PKI asks Hermod's DNSClient - which the suite points at a name server of
# its own - the names have to be in /etc/hosts.
#
# How, without touching the system: in a user and mount namespace of its own
# (unshare, no root needed), with an /etc/hosts of its own laid over the
# system's - the system's /etc/hosts and everything outside this command see
# nothing of it. Inside, the command is "root" of that namespace, which also
# lets the suite lay a CA bundle of its own over the system's for a peer that
# takes no CA file (uacme, through libcurl-gnutls).
#
# Where unprivileged user namespaces are not allowed - a CI container, which
# runs as root and is thrown away afterwards - and CI is set, the names are
# appended to /etc/hosts itself instead.

set -eu

names="acme.test www.acme.test"
for n in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16; do
    names="$names n$n.acme.test"
done

hosts=$(mktemp "${TMPDIR:-/tmp}/pkiconformance-hosts.XXXXXX")
cat /etc/hosts > "$hosts"
printf '\n# PKIConformanceTests bench names (build/bench-namespace.sh)\n127.0.0.1 %s\n' "$names" >> "$hosts"
chmod 0644 "$hosts"

export PKICONFORMANCE_BENCH_HOSTS="$hosts"
export PKICONFORMANCE_BENCH_NAMES="$names"

if unshare --user --map-root-user --mount true 2>/dev/null; then
    # Inside, the user is "root" of the namespace, and the real root's files
    # in /tmp (NuGet's /tmp/NuGetScratchroot, say) are nobody's: a temporary
    # directory of the run's own.
    export TMPDIR="${PKICONFORMANCE_TMPDIR:-$HOME/.cache/pkiconformance/tmp}"
    mkdir -p "$TMPDIR"
    exec unshare --user --map-root-user --mount \
         sh -c 'mount --bind "$PKICONFORMANCE_BENCH_HOSTS" /etc/hosts && exec "$@"' sh "$@"
fi

if [ "$(id -u)" -eq 0 ] && [ -n "${CI:-}" ]; then
    cat "$hosts" > /etc/hosts
    exec "$@"
fi

echo "No user namespace to lay the bench's /etc/hosts into (unshare --user --map-root-user --mount)," >&2
echo "and this is no CI container to write it into: the tests of names will skip." >&2
exec "$@"
