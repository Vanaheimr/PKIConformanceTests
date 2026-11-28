# PKI ACME Conformance & Interoperability Test Suite

[![CI](https://github.com/Vanaheimr/PKIConformanceTests/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanaheimr/PKIConformanceTests/actions/workflows/ci.yml)
[![Nightly](https://github.com/Vanaheimr/PKIConformanceTests/actions/workflows/nightly.yml/badge.svg)](https://github.com/Vanaheimr/PKIConformanceTests/actions/workflows/nightly.yml)

An independent .NET 11 test solution that measures both ends of ACME
(RFC 8555) as this family implements them - **Hermod's ACME client** and **the
PKI's ACME server** - against the RFCs and against real implementations:
lego, certbot, acme.sh, dehydrated, uacme and Python's acme of Linux, and
Posh-ACME and win-acme of Windows, as clients of the server; Pebble,
step-ca, Boulder and Let's Encrypt's staging as servers for the client.

Hermod, the PKI and what they need (Styx, Norn, Urdr, WWCP_Node, WWCP_Core)
are consumed as git submodules under `libs/`, so the suite can act as an
unbiased referee and be run against any revision of them. Every assertion is
checked against something that is neither Hermod nor the PKI: codecs of the
suite's own, RFC vectors, openssl, and the peers.

- [PLAN.md](PLAN.md) - what is tested, how, in which order, and the ToDos
- [FINDINGS.md](FINDINGS.md) - where the implementations deviate from the RFCs
- [MUTATION.md](MUTATION.md) - what the suite would notice: the mutation
  sweep of the PKI's ACME code, survivor by survivor

**State (2026-11-28, PKI `ba8324a9`, Hermod `0a93a6fb`):** phases 0 to 3
and 5 to 7 done, phase 4 nearly. Natively in WSL 765 ✅ · 129 ❌ · 2 skipped
of 896 (87 codec, 310 server, 40 validation, 168 client, 183 interop of six
real clients against the PKI - certbot 4.0.0 and 5.10.0, Python's acme
5.10.0, lego 5.7.0, acme.sh 3.1.1 and 3.1.7, dehydrated 0.7.2, uacme 1.7.6 -
and 108 of Hermod against four real servers - Pebble 2.6.0 and 2.10.3,
step-ca 0.30.2, Boulder in Docker); natively on Windows 45 ✅ · 2 ❌ of 47,
Posh-ACME 4.35.0 and win-acme 2.4.1 against the PKI; and, opt-in, 4 ✅ of
Hermod against Let's Encrypt's staging. Cell by cell in
[docs/INTEROP-MATRIX.md](docs/INTEROP-MATRIX.md), generated from the runs:
327 ✅ · 15 ❌ of 342 interop tests. Every red one is a finding or a ToDo:
**36 findings**, tagged `KnownIssue` - 20 against the PKI's server and
validator, S-1 to S-19 and V-1 (among them dns-01, which never validates -
for three real clients in five versions too, whose records reach BIND - and
six the fuzzer found, S-14 to S-19), 15 against Hermod's client and
certificate manager, C-1 to C-11 and M-1 to M-4 (among them a certificate
chain with a private key in it, which the client takes), and I-1 between
win-acme and the PKI (a commonName of "" in the CSR of an address) - and 13
trackers of ToDos, T-S5 and T-C1 to T-C12, tagged `ToDo`. The real clients
of Linux found nothing new in the PKI, Python's acme neither; the real
servers found one thing in Hermod, M-4 (privkey.pem without the final
newline of certbot's), and saw C-7 again. The mutation sweep of the PKI's
ACME code ([MUTATION.md](MUTATION.md)) has the suite kill 230 of 348
mutants; of the 118 that survive, one is a gap of the suite still open, and
the others change nothing, sit behind V-1, or lie outside an ACME suite's
reach. S-3 and S-19 differ by platform, and their tests are one per leg: the
two skips natively in WSL are their tests of Windows. On Windows those are
red, and the tests of Linux skip; so do the interop tests of Linux (the
Windows firewall keeps WSL out), the test of a certificate dated 0001, which
Windows cannot load, and the one of a key file's POSIX mode.

## Running

```
dotnet test PKIConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=Windows&TestCategory!=Docker&TestCategory!=KnownIssue&TestCategory!=ToDo"
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

The peers of Windows - Posh-ACME and win-acme - run natively on Windows,
against the server in the test process on the loopback, no WSL between
them. They are installed for the current user into
`%LOCALAPPDATA%\pkiconformance`, each download checked against the hash its
publisher publishes, and run with a configuration of their own per test:

```
powershell -ExecutionPolicy Bypass -File build\peers\setup-windows.ps1
```

```
dotnet test PKIConformanceTests.slnx --filter "TestCategory=Windows"
```

Hermod against Let's Encrypt's staging, over the internet - opt-in; a run
opens two accounts there:

```
dotnet test interop\PKIInterop.PublicCAs.Tests --filter "TestCategory=Online"
```

The fuzzer of the server (`conformance/PKIConformance.ACME.Server.Tests/Fuzzing`)
is part of the default run: 200 spoiled requests a case, seeded, and
`PKICONFORMANCE_FUZZ_ITERATIONS` for a deeper one. The mutation sweep of
the PKI's ACME code, which grades the suite itself (`MUTATION.md`), runs a
block at a time, for hours, in a mirror of the checkout:

```
python build\mutation\sweep.py jws
```

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
| `Windows` | Windows, and its peers (`setup-windows.ps1`) | `--filter "TestCategory=Windows"` |
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
interop/PKIInterop.ACMEClients.Tests/    real clients against the PKI - of Linux, and of Windows natively
interop/PKIInterop.PublicCAs.Tests/      Hermod against Let's Encrypt's staging (Online)
interop/PKIInterop.ACMEServers.Tests/    Hermod against real servers
InteropReport/                           the TRX files of a run → docs/INTEROP-MATRIX.md
fixtures/                                what real peers wrote, as references: certbot's live/
build/                                   shared MSBuild settings, peers, scripts, the mutation sweep
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
