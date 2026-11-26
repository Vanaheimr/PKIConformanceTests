#!/bin/sh
#
# The suite run inside WSL - or on any Linux - from a copy of this checkout
# in the Linux file system:
#
#   wsl sh build/test-in-wsl.sh --filter "TestCategory=WSL"
#
# Why a copy: Windows builds into the bin/ and obj/ beside every project, and
# a Linux build over /mnt/d into the same ones takes each other's
# project.assets.json and .deps.json for its own - XMPPConformanceTests found
# out that a run then prints nothing and still exits 0. Hermod and Styx would
# take a root Directory.Build.props that moves their output, but the PKI,
# Norn, Urdr and WWCP_* import none from above. A copy has none of that, and
# under WSL it is also on a file system that is fast.
#
# Why at all: a peer inside WSL reaches a server of a Windows process only
# through WSL's NAT and the Windows firewall; natively there is one loopback.
# The results land in artifacts/ of the checkout, as on Windows.

set -eu

src=$(cd "$(dirname "$0")/.." && pwd)
tree="${PKICONFORMANCE_WSL_TREE:-$HOME/.cache/pkiconformance/tree}"

mkdir -p "$tree" "$src/artifacts"

rsync -a --delete \
      --exclude 'bin/' --exclude 'obj/' --exclude '.vs/' \
      --exclude 'artifacts/' --exclude 'TestResults/' --exclude 'node_modules/' \
      "$src/" "$tree/"

cd "$tree"

# Git for Windows checks out with core.autocrlf=true from its system
# gitconfig, which the git of Linux does not read: in the copy every file then
# differs from the index by its line ends, and every assembly is stamped
# "-dirty" by the provenance target of the submodules' Directory.Build.props.
# Said for this run only, through the environment, without touching a config.
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=core.autocrlf
export GIT_CONFIG_VALUE_0=true

exec dotnet test PKIConformanceTests.slnx --results-directory "$src/artifacts" "$@"
