# PKI ACME Conformance & Interoperability Test Suite

[![CI](https://github.com/Vanaheimr/PKIConformanceTests/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanaheimr/PKIConformanceTests/actions/workflows/ci.yml)
[![Nightly](https://github.com/Vanaheimr/PKIConformanceTests/actions/workflows/nightly.yml/badge.svg)](https://github.com/Vanaheimr/PKIConformanceTests/actions/workflows/nightly.yml)

An independent .NET 11 test solution that measures both ends of ACME
(RFC 8555) as this family implements them - **Hermod's ACME client** and **the
PKI's ACME server** - against the RFCs and against real implementations:
lego, certbot, acme.sh, dehydrated and uacme as clients of the server, and
Pebble, step-ca and Boulder as servers for the client.

Hermod, the PKI and what they need (Styx, Norn, Urdr, WWCP_Node, WWCP_Core)
are consumed as git submodules under `libs/`, so the suite can act as an
unbiased referee and be run against any revision of them. Every assertion is
checked against something that is neither Hermod nor the PKI: codecs of the
suite's own, RFC vectors, openssl, and the peers.

- [PLAN.md](PLAN.md) - what is tested, how, in which order, and the ToDos
- [FINDINGS.md](FINDINGS.md) - where the implementations deviate from the RFCs

**State (2026-11-27, PKI `ba8324a9`, Hermod `0a93a6fb`):** phases 0 to 3
and 5 done, phases 4 and 6 nearly (the nightly has not run yet) - natively
in WSL 720 ✅ · 100 ❌ of 820 (87 codec, 239 server, 40 validation, 168
client, 178 interop of five real clients against the PKI - certbot 4.0.0
and 5.10.0, lego 5.7.0, acme.sh 3.1.1 and 3.1.7, dehydrated 0.7.2, uacme
1.7.6 - and 108 of Hermod against four real servers - Pebble 2.6.0 and
2.10.3, step-ca 0.30.2, Boulder in Docker; cell by cell in
[docs/INTEROP-MATRIX.md](docs/INTEROP-MATRIX.md), generated from the run),
and every red one is a finding or a ToDo: **29 findings**, tagged
`KnownIssue` - 14 against the PKI's server and validator, S-1 to S-13 and
V-1 (among them dns-01, which never validates - for three real clients in
five versions too, whose records reach BIND), and 15 against Hermod's
client and certificate manager, C-1 to C-11 and M-1 to M-4 (among them a
certificate chain with a private key in it, which the client takes) - and
13 trackers of ToDos, T-S5 and T-C1 to T-C12, tagged `ToDo`. The real
clients found nothing new in the PKI, not at their current versions
either; the real servers found one thing in Hermod, M-4 (privkey.pem
without the final newline of certbot's), and saw C-7 again. On Windows S-3
is red as well, the interop tests skip (the Windows firewall keeps WSL
out), and so do the test of a certificate dated 0001, which Windows cannot
load, and the one of a key file's POSIX mode.

## Running

```
dotnet test PKIConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=Docker&TestCategory!=KnownIssue&TestCategory!=ToDo"
```

The interop tests need the peers. Inside WSL (or on any Debian 13):

```
wsl -u root sh build/peers/setup-wsl.sh
wsl sh build/peers/setup-wsl.sh --check
```

A peer inside WSL reaches a server of a Windows test process only through
WSL's NAT and the Windows firewall, which usually says no; those tests then
skip and say so. Run them inside WSL instead, from a copy of the checkout in
the Linux file system (results land in `artifacts/` here as usual):

```
wsl sh build/test-in-wsl.sh -c Release --filter "TestCategory=WSL"
```

The run happens in a user and mount namespace of its own
(`build/bench-namespace.sh`, no root needed): there the names of the bench -
`acme.test`, `www.acme.test`, `n01.acme.test` to `n16.acme.test` - resolve to
the loopback, which the PKI needs for http-01 of a name until it resolves
through Hermod's DNSClient (T-S5), and uacme, which takes no CA file, finds
the bench's root in the system's bundle. The system's `/etc/hosts` and CA
bundle are never touched.

Hermod's client against Boulder, Let's Encrypt's own server, needs its
Docker compose stack - several GB of images - and a Docker daemon in WSL:

```
wsl -u root sh build/peers/setup-wsl.sh --with-boulder
```

```
wsl sh build/test-in-wsl.sh -c Release --filter "TestCategory=Docker"
```

The stack takes a few minutes to start, and is stopped after the tests;
`PKICONFORMANCE_KEEP_BOULDER=1` in the environment keeps it running for the
next run.

The interop matrix, [docs/INTEROP-MATRIX.md](docs/INTEROP-MATRIX.md), is
generated from the TRX files of a run - every interop test writes the cell
it is into its output:

```
dotnet run --project InteropReport -- artifacts/
```

A test of several runs in there counts once, as it came out in the last.

## Test categories

| Category | Needs | Run with |
|---|---|---|
| *(none)* | nothing but loopback | the default filter above |
| `WSL` | the peers, inside WSL or natively on Linux | `build/test-in-wsl.sh --filter "TestCategory=WSL"` |
| `Docker` | a Docker daemon and Boulder's stack (`setup-wsl.sh --with-boulder`) | `build/test-in-wsl.sh --filter "TestCategory=Docker"` |
| `Online` | the internet (Let's Encrypt staging) | `--filter "TestCategory=Online"` |
| `KnownIssue` | - | red until the finding is fixed |
| `ToDo` | - | red until the feature is implemented |

## Layout

```
src/PKIConformance.Core/                 servers under test, peers, WSL bridge, gating
src/PKIConformance.Core/RawACME/         the reference codec: no Hermod, no PKI, System.Text.Json
src/PKIConformance.Core/Scripted/        RawACMEClient, ScriptedACMEServer, the bench's web and name servers, CA and clock
src/PKIConformance.Core/Peers/           the peers: clients, servers, BIND, challtestsrv, the recording and its judge
conformance/PKIConformance.ACME.*.Tests/ offline, loopback only
interop/PKIInterop.ACMEClients.Tests/    real clients against the PKI
interop/PKIInterop.ACMEServers.Tests/    Hermod against real servers
InteropReport/                           the TRX files of a run → docs/INTEROP-MATRIX.md
fixtures/                                what real peers wrote, as references: certbot's live/
build/                                   shared MSBuild settings, peers, scripts
libs/                                    the submodules
```

`Directory.Build.rsp` switches off the PKI's npm/webpack frontend build for
every `dotnet build` and `dotnet test` in this tree.

## Conventions

- Every test fixture names the RFC section it verifies, `[Property("RFC", "8555 §7.2")]`,
  and its doc comment quotes the requirement and says why it exists; each test
  says the requirement level, `[Property("Level", "MUST")]`.
- Server tests take the server from `ServersUnderTest`, never a product
  directly: the ACME server is moving from the PKI into Hermod, and the same
  tests will run against both.
- Assertions use the constraint model, and their messages carry the evidence:
  the server, its answer, the peer's output.

## License

Apache License 2.0, see [LICENSE](LICENSE).
