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

**State (2026-11-26, PKI `ba8324a9`, Hermod `0a93a6fb`):** phases 0 to 2
done - natively in WSL 329 ✅ · 43 ❌ of 372 (87 codec, 239 server, 40
validation, 6 lego 5.7.0 interop), and every red one is a finding or a ToDo:
**14 findings** against the PKI's server and validator, S-1 to S-13 and V-1 -
among them dns-01, which never validates - tagged `KnownIssue`, and one
tracker of T-S5, tagged `ToDo`. On Windows S-3 is red as well, the 6 lego
tests skip (the Windows firewall keeps WSL out), and so does the one test of
a certificate dated 0001, which Windows cannot load.

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

## Test categories

| Category | Needs | Run with |
|---|---|---|
| *(none)* | nothing but loopback | the default filter above |
| `WSL` | the peers, inside WSL or natively on Linux | `build/test-in-wsl.sh --filter "TestCategory=WSL"` |
| `Docker` | a Docker daemon (Boulder) | `--filter "TestCategory=Docker"` |
| `Online` | the internet (Let's Encrypt staging) | `--filter "TestCategory=Online"` |
| `KnownIssue` | - | red until the finding is fixed |
| `ToDo` | - | red until the feature is implemented |

## Layout

```
src/PKIConformance.Core/                 servers under test, peers, WSL bridge, gating
src/PKIConformance.Core/RawACME/         the reference codec: no Hermod, no PKI, System.Text.Json
src/PKIConformance.Core/Scripted/        RawACMEClient, and the bench's web and name servers
conformance/PKIConformance.ACME.*.Tests/ offline, loopback only
interop/PKIInterop.*.Tests/              real peers
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
