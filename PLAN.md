# PKI ACME Conformance & Interoperability Test Suite — Plan

Goal: an independent .NET 11 test solution that measures both ends of ACME
(RFC 8555) as this family implements them:

- **Hermod's ACME client** (`libs/Hermod/Hermod/ACME`: `ACMEClient`,
  `ACMECertificateManager`, `HTTP01ChallengeResponder`, `DNS01ChallengeResponder`),
- **the PKI's ACME server** (`libs/PKI/PKI`: `HTTPAPI/PKIHTTPAPI.ACME.cs`,
  `Enrollment/ACMEJWS.cs`, `ACMEState.cs`, `ACMEValidator.cs`, `ACMESettings.cs`),

against RFC 8555 and its extensions, and validates them against real-world
implementations: **certbot, lego, acme.sh** (and more) as clients of the PKI,
and **Pebble, step-ca, Boulder** as servers for Hermod.

The suite lives *outside* both repositories (Hermod, PKI and their dependencies
are consumed as git submodules under `libs/`), so it can act as an unbiased
referee and be run against any revision of either.

Status legend: ✅ done · 🔶 in progress · ⬜ planned · 📋 optional / documented only

---

## 0. Decisions (2026-11-26)

1. **All submodules the PKI needs are here**: Styx, Hermod, Norn, Urdr, PKI,
   WWCP_Node, WWCP_Core — pinned to the same commits as `PKICLI`, which builds
   with exactly this set. ✅
2. **The ACME server moves from the PKI into Hermod.** Hermod then holds both
   ends of ACME; the PKI keeps its CAs, its settings and its JSON API and plugs
   its CA into Hermod's server as the issuer. The suite does not wait for this:
   every server test talks to an `IACMEServerUnderTest`, implemented today by
   the in-process PKI (`PKIACMEServer`) and after the move also by Hermod's
   server with a CA of the test (`HermodACMEServer`), the PKI then being one
   issuer among others. With both ends in one library, principle 1 matters
   more, not less. (§7, phase M)
3. **Every name is resolved through Hermod's `DNSClient`** — never through the
   operating system. That covers the validator's http-01 (today the OS
   resolver via `HttpClient`), dns-01 (already the node's `DNSClient`), and the
   ACME client's own connections to the directory. The suite points that
   `DNSClient` at its own authoritative server (BIND or `pebble-challtestsrv`),
   so names like `www.acme.test` work without `/etc/hosts`. Until the code
   does so, the tests that need it are trackers (T-S5, T-C11).
4. **Missing features are ToDos, not findings** (§2.4). Each ToDo gets tracker
   tests tagged `ToDo` that go green the day it is implemented; a finding is
   reserved for something implemented that deviates from the RFC.
5. Open: Let's Encrypt staging (needs a public name and a DNS API), and whether
   certbot and acme.sh gate from Debian's packages or from pinned upstream.

### Learned in phase 0

- **WSL → Windows is closed.** Under WSL's NAT the Windows firewall does not
  let a peer inside WSL reach a server of the Windows test process
  (`curl` exit 28 to `172.23.32.1`). The interop tests then skip with that
  reason; `build/test-in-wsl.sh` runs the suite natively inside WSL from a
  copy of the checkout in the Linux file system instead, which is also what
  the nightly does on Debian.
- **`Directory.Build.rsp`, not props.** Only Hermod and Styx import a
  `Directory.Build.props` from above; the PKI, Norn, Urdr and WWCP_* do not.
  `-p:SkipFrontendBuild=true` in `Directory.Build.rsp` reaches all of them as
  one global property.
- **A shadowed certbot.** On the development WSL a `cryptography` 50.0.0
  installed by pip under `/usr/local/lib/python3.13/dist-packages` shadows
  Debian's 43.0.0, and Debian's certbot 4.0.0 dies on import
  (`module 'lib' has no attribute 'GEN_EMAIL'`). Not the suite's to change;
  the certbot peer will run from a venv of its own (upstream tier) or with
  `/usr/local` taken off its path. A clean Debian 13 (CI) is not affected.
- **lego 5.7.0 has ML-DSA account keys** (`MLDSA44/65/87`), which RFC 8555
  does not know: a free negative test of section 6.2 for every server. The
  PKI refuses them as `badSignatureAlgorithm`, as it should.
- **lego 5 speaks HTTPS only** ("HTTPS is required"), as RFC 8555 §6.1 asks.
  Every server under test is therefore started with HTTPS by a certificate of
  the bench (`BenchTLS`, made with .NET alone, not by the PKI under test), and
  the peers trust the bench's root (`LEGO_CA_CERTIFICATES`, later
  `REQUESTS_CA_BUNDLE` for certbot and `--ca-bundle` for acme.sh).
- **lego 5 always makes a new key on `accounts register`**, and keeps the
  account as `registration.accountURL`/`status`/`contact`/`orders` in
  `account.json` (lego 4 had `registration.uri` and `.body`). "The same key
  finds the same account" (§7.3.1) is therefore a test of `RawACMEClient`
  (phase 2), not of lego.

### Learned in phase 2

- **The PKI's dns-01 never worked** (V-1): Hermod's `DomainName.Parse` is a
  host name's parser and refuses `_acme-challenge`. Phase 1's codec test had
  replaced `LookupTXT` and could not see it. A validator is tested against a
  name server - the bench's, through the server's own `DNSClient` - never
  against a delegate.
- **A negative validation test proves nothing by itself**: a validator that
  never asks refuses every answer, the wrong ones among them. Every negative
  test of http-01 and dns-01 also asserts that the host or the name server
  was asked.
- **One finding, one platform**: `ECDsa.Create(ECParameters)` checks the
  point on Linux (OpenSSL) and not on Windows (CNG), so a "jwk" off its curve
  is badPublicKey on one leg and 500 on the other (S-3). Both legs matter.
- **`System.Buffers.Text.Base64Url` takes padding** (S-1). The decoder RFC
  8555, section 5 asks for has to be written, as `RawBase64Url` is.
- **Hermod's HTTP server answers a method without a handler itself** - 405 and
  a JSON of its own - where ACME wants a problem document of the type
  "malformed" (S-4), and refuses the POST-as-GET of the directory (S-5).
- **The bench**: `ScriptedChallengeHost` (HTTP/1.1 on a `TcpListener`, on
  127.0.0.1 and ::1 at one port, the server's `http01Port` pointed at it),
  `ScriptedDNSServer` (UDP, the server's resolver through Hermod's
  `DNSClient`), and every name proven by http-01 an address of RFC 8738, which
  needs no resolution. `BenchNameServerTests` proves the name server answers
  what dns-01 needs, so that a red dns-01 test is red at the server.

### Learned in phase 3

- **The client's findings are of exactness and of distrust.** Hermod's client
  does every flow right, against a server that is strict where the RFC is;
  what it gets wrong is taking the server's strings as `System.Uri` and
  writing them out re-encoded (C-2), taking a nonce from the pool where the
  RFC names the one to take (C-3), and believing what a server sends: a
  Replay-Nonce of any shape (C-4), a chain with a private key in it (C-1, the
  key replacement attack of RFC 8555, section 11.4 - into fullchain.pem by
  the manager).
- **`CertificateRequest.LoadSigningRequest` reads no extensions** of a CSR
  unless told (`UnsafeLoadCertificateExtensions`); the bench first found no
  names in any CSR, and refused all of them as badCSR. A bench is tested
  against a client of the suite's own first: `BenchACMEServerTests`.
- **A clock that moves only when it is waited on stands still at a wait of
  less than a millisecond**: .NET's `Task.Delay` returns from one at once,
  without a timer. Hermod's manager, due in a few microseconds, then looks at
  the window 25 000 times in 15 s - as it would on a `FakeTimeProvider`. With
  the system clock time passes anyway, so it is no finding; `BenchClock`
  moves a millisecond at every reading, as a real one does.
- **The bench**: `ScriptedACMEServer` (RFC 8555 strict: Content-Type, the
  flattened JWS, nonces, "url" by string, signatures by RawACME; http-01
  asked at the client's port with the name as the Host, dns-01 read from a
  zone the client's responder writes; issuance by `BenchCA`, .NET alone;
  every request kept, every answer replaceable), `BenchClock` (every wait
  written down, none taken).

### Learned in phase 4

- **Five clients of other hands find nothing new in the PKI's server.**
  Every cell they have is green - accounts, EAB, contacts, key rollover,
  http-01 of names and addresses, every key, sixteen names, own CSRs,
  profiles, renewal with "replaces", revocation by account and by key, the
  CRL, the refusals - except dns-01, at V-1. What phase 2 found the hostile
  client finds; the friendly ones never send it.
- **The names of the bench without root.** The PKI resolves http-01 by the
  operating system until T-S5, and a name a client proves has to resolve to
  the loopback: `build/bench-namespace.sh` runs the tests in a user and
  mount namespace of their own with an /etc/hosts of their own (unshare,
  no root). The same namespace lets the bench lay a CA bundle over the
  system's for uacme, which takes no CA file. Inside, the user is "root",
  and /tmp of the real root is nobody's: the run gets a TMPDIR of its own.
- **`named -g` ignores the logging of its configuration** and sends all to
  stderr; `-f` keeps it. The first run saw no TXT record of any client,
  which BIND had taken all along - a bench is tested first
  (`BenchInteropTests`).
- **What the versions of Debian 13 lack** is a grey cell, without a test:
  certbot 4.0.0 has no IP identifiers and no ARI, acme.sh 3.1.1 and
  dehydrated 0.7.2 neither profiles nor ARI, uacme 1.7.6 reads ARI's
  window and sends no "replaces", lego 5.7.0 neither updates nor
  deactivates an account. dehydrated 0.7.2 orders an address as a "dns"
  identifier, which the PKI rightly refuses as malformed.
- **The PKI keeps "replaces" by its own identifier of the certificate**;
  the bench speaks RFC 9773's (`ServerIssued.Replaces`).

---

## 1. Guiding principles

1. **Never test Hermod with Hermod — and never the PKI with Hermod alone.**
   `PKITests/ACMETests` (Hermod's client against the PKI) and
   `HermodTests/ACME/TestACMEServer` (Hermod's client against a server of the
   same hand) agree with each other by construction. Here every assertion is
   checked against an independent reference: `RawACME`, a minimal hand-written
   JWS/JWK/ACME codec in `PKIConformance.Core` that uses neither
   `Hermod.ACME` nor `PKI.Enrollment`; vectors from RFC 7515/7638/8555/9773;
   and the behaviour of Pebble, Boulder, step-ca, certbot, lego and acme.sh.
   Certificates are judged by `openssl` in WSL as well as by .NET's `X509Chain`.
2. **Conformance failures are results, not test bugs.** A deviation from a MUST
   stays red, is tagged `KnownIssue`, and is recorded in `FINDINGS.md` with
   RFC section and verse until the fix lands upstream and the pin advances.
3. **Offline by default, graceful everywhere.** Everything in `conformance/`
   runs on loopback without WSL, Docker or network. Interop tests probe their
   prerequisites in `[OneTimeSetUp]` and `Assert.Ignore` with the exact command
   that would provide them. In CI an interop lane with skips is red.
4. **Every test names its law.** `[Property("RFC", "8555 §6.5")]` plus the
   requirement level (`[Property("Level", "MUST")]`); the fixture's doc comment
   quotes the sentence it encodes.
5. **Both directions, symmetric.** Every third-party client against the PKI,
   Hermod's client against every third-party server, and the diagonal
   Hermod ↔ PKI as a baseline. One matrix, generated from the test results.
6. **Far sides are pinned and named.** Every interop result records the exact
   version of the peer (banner, package version, or SHA-256 of the binary).
7. **A peer that lacks a feature is grey, not red.** certbot has no key
   rollover, acme.sh no profiles in older versions: such a cell is no
   failure of the PKI. It has no test at all - the peer's test class says in
   its remarks what its version lacks, and the matrix shows "—" - so that
   an interop lane stays one in which any skip is red (principle 3).

---

## 2. What is implemented (inventory from code review)

### 2.1 Hermod — ACME client

| Area | Present | RFC |
|---|---|---|
| Directory | fetched once and cached; `meta.externalAccountRequired` honoured | 8555 §7.1.1 |
| Nonces | pool of up to 16 from `Replay-Nonce`, `HEAD new-nonce` when empty, `badNonce` retried 3× | §6.5 |
| JWS | flattened JSON, `alg`/`nonce`/`url` + `jwk` (new-account) or `kid`, `application/jose+json` without charset, POST-as-GET with empty payload | §6.2, §6.3 |
| Account | newAccount (contact `mailto:`, ToS, EAB HS256), `onlyReturnExisting` | §7.3, §7.3.4 |
| Order | dns, wildcard, ip (RFC 8738); `profile` (draft-ietf-acme-profiles); `replaces` (RFC 9773) with fallback on `alreadyReplaced`/`conflict`/`malformed` | §7.4 |
| Challenges | http-01 from a Hermod HTTP server, dns-01 via Publish/Withdraw/IsVisible delegates; clean-up always | §8.3, §8.4 |
| Polling | `Retry-After` (delta and date), poll interval/timeout, `TimeProvider` | §7.5.1 |
| Finalize | own CSR: EC P-256/P-384, RSA 2048/4096; SAN = identifiers, CN = first DNS name ≤ 64 chars | §7.4 |
| Certificate | PEM chain with `Accept: application/pem-certificate-chain` | §7.4.2 |
| Revocation | by the account key, with reason | §7.6 |
| ARI | `renewalInfo` GET, certificate identifier, window, `Retry-After` | RFC 9773 |
| Manager | files laid out "as certbot would", renewal by ARI window or ⅓ lifetime, background loop | — |

What the code does not have yet is listed as ToDos in §2.4.

### 2.2 PKI — ACME server (moving to Hermod, §0.2)

| Area | Present | RFC |
|---|---|---|
| Resources | directory, new-nonce (HEAD 200 / GET 204), new-account, acct/{id}, acct/{id}/orders, key-change, new-order, order, authz, chall, finalize, cert, revoke-cert, renewal-info | 8555 §7.1 |
| Request checks | fresh nonce, `url` = target, `jwk` only for new-account, `kid` elsewhere, ES256/384/512, RS256, PS256, minimum RSA size, never `none`/MAC | §6.2–§6.5 |
| Answers | RFC 7807 problem documents with a fresh nonce on every answer, `Cache-Control: no-store`, `Link: rel="index"`, `rel="up"` on challenges | §6.7, §7.1 |
| Accounts | persisted in `acme/accounts.json`; contacts, deactivation, key change (`conflict` + `Location`), EAB with PKI-made keys, single use | §7.3 |
| Orders | ≤ 100 identifiers, dns/wildcard/ip, profiles, `allowedNames`, no `notBefore`/`notAfter`, authz reuse 30 days, in memory | §7.4 |
| Validation | http-01 on port 80 (configurable `http01Port` on a bench), redirects followed (≤ 10, HTTPS without certificate check), body ≤ 8 KiB, trailing whitespace ignored; dns-01 via the node's `DNSClient` (`LookupTXT` replaceable); wildcard by dns-01 only, ip by http-01 only | §8.3, §8.4, RFC 8738 |
| Issuance | names of the order exactly, CN = first name, only the CSR's key taken | §7.4 |
| Revocation | by the account, by an account that proved every name, by the certificate key; reasons 0, 1, 3, 4, 5 | §7.6 |
| ARI | renewal-info, `replaces`, `alreadyReplaced` | RFC 9773 |
| Admin | JSON API `v1/pki/acme` (settings, accounts, EAB keys), CLI `pkiACME` | — |

Orders do not survive a restart, by design; the restart behaviour is tested.
What the code does not have yet is listed as ToDos in §2.4.

### 2.3 Build dependencies

`libs/PKI/PKI/PKI.csproj` references `..\..\Norn`, `..\..\Urdr`,
`..\..\WWCP_Node`, and `WWCP_Node` references `..\..\WWCP_Core\WWCP_CoreData`.
The submodule set therefore matches `PKICLI`: Styx, Hermod, Norn, Urdr, PKI,
WWCP_Node, WWCP_Core (✅ §0.1). The PKI's frontend build (npm/webpack) is
switched off by `-p:SkipFrontendBuild=true` in `Directory.Build.rsp`: a global
property reaches every project alike, whereas `AdditionalProperties` on one
ProjectReference would build Hermod and the rest twice, once with and once
without it.

### 2.4 ToDos (§0.4)

Each has tracker tests tagged `ToDo` (excluded from CI like `KnownIssue`).

| ID | Where | ToDo | RFC |
|---|---|---|---|
| T-C1 | client | Update the account (contacts) | 8555 §7.3.2 |
| T-C2 | client | Deactivate the account | §7.3.6 |
| T-C3 | client | Key rollover (`keyChange`) | §7.3.5 |
| T-C4 | client | Deactivate an authorization | §7.5.2 |
| T-C5 | client | Revoke with the certificate's own key | §7.6 |
| T-C6 | client | Alternate chains (`Link: rel="alternate"`), choosing a preferred chain | §7.4.2 |
| T-C7 | client | Use `algorithms` of `badSignatureAlgorithm` | §6.2 |
| T-C8 | client | `userActionRequired` and changed terms of service, surfaced | §7.3.3 |
| T-C9 | client | `Retry-After` on `rateLimited`/503 outside polling | §6.6 |
| T-C10 | client | tls-alpn-01 responder | RFC 8737 |
| T-C11 | client | Connections to the ACME server resolved through Hermod's `DNSClient` | §0.3 |
| T-C12 | client | The account's orders list | §7.1.2.1 |
| T-S1 | server | tls-alpn-01 | RFC 8737 |
| T-S2 | server | CAA checking, `meta.caaIdentities` | RFC 8659, 8657; 8555 §7.1.1 |
| T-S3 | server | Alternate chains | §7.4.2 |
| T-S4 | server | Rate limits with `Retry-After` | §6.6 |
| T-S5 | server | http-01 resolved through Hermod's `DNSClient` | §0.3 |
| T-S6 | server | http-01 redirect policy: http/https on ports 80/443 only, as Let's Encrypt (an interpretation, RFC 8555 does not settle it) | §8.3, §10.2 |
| T-S7 | server | `subproblems` for errors of several identifiers | §6.7.1 |
| T-S8 | server | Move into Hermod | §0.2 |
| T-S9 | server | EdDSA (Ed25519) account keys - *"SHOULD implement"*; no tracker yet, as .NET has no Ed25519 to sign one with | §6.2 |

---

## 3. Test taxonomy — four layers

### Layer 1 — Codec conformance (offline, pure)

`RawACME` checked against RFC vectors, then Hermod's and the PKI's codecs
checked against `RawACME` in both directions: a JWS that Hermod signs verifies
in `RawACME`, one that `RawACME` signs verifies in the PKI's `ACMEJWS`.

### Layer 2 — Behavioural conformance (offline, loopback)

- **2a — the PKI as a server**, driven by `RawACMEClient`, a hostile client
  that can get every field wrong on purpose.
- **2b — the PKI's validator**, against `ScriptedChallengeHost` (HTTP and DNS
  answers scripted per test: redirects, ports, sizes, CNAMEs, multiple TXT).
- **2c — Hermod as a client**, against `ScriptedACMEServer`, a server written
  from the RFC (not from `TestACMEServer`) with per-test fault injection.

### Layer 3 — Interoperability (WSL / Linux, Docker)

Real clients against an in-process PKI; Hermod against real servers. Peers are
native Linux binaries run through the `Wsl` bridge (WSL on Windows, directly on
Linux CI), Docker only where nothing else works (Boulder).

### Layer 4 — Live and external (optional)

Let's Encrypt staging (needs a public name and a DNS API), Boulder's full
compose stack, and a mutation sweep that grades the suite itself.

---

## 4. Coverage matrix

### 4.1 Codec (`PKIConformance.ACME.Codec.Tests`) ✅ 87

*Phase 1, 2026-11-26: 87 of 87 natively in WSL; on Windows 86 and one skip
(the example certificate of RFC 9773 is valid from 0001-01-01, which the
certificate store of Windows cannot hold; an equivalent certificate of its
key identifier and serial covers it there). No finding: Hermod's account key
and the PKI's `ACMEJWS` agree with the RFC examples and with `RawACME`
throughout.* What is not reachable at this layer moves on: Hermod's JWS
assembly, its external account binding and its CSR are private to
`ACMEClient` (phase 3, through `ScriptedACMEServer`); the PKI's ARI
identifier parsing and its key change are behind its HTTP resources
(phase 2). Noted on the way for phase 2: the PKI counts the bits of an RSA
modulus by whole octets and does not look at the public exponent (e = 1 or
an even e would be taken), and whether `ECDsa.Create` refuses a point off
the curve on Linux as it does on Windows is a question for both legs - it is
the other way round: Linux refuses it, Windows does not (S-3).

| RFC | Topic | Focus |
|---|---|---|
| 7515 App. A.3/A.4, 7518 | JWS ES256/ES384/ES512, RS256, PS256 | Signature encoding (raw r‖s, not DER), base64url without padding |
| 7638 §3.1 | JWK thumbprint | Example vector; member order and no whitespace; EC coordinates left-padded to the curve size |
| 8555 §8.1 | Key authorization | `token "." thumbprint` |
| 8555 §8.4 | dns-01 digest | base64url(SHA-256(key authorization)) |
| 8555 §7.3.4 | EAB | HS256 over the outer `jwk`, `url` = new-account URL, MAC key with and without padding |
| 8555 §7.3.5 | Key change | Inner JWS: `jwk` of the new key, payload `{account, oldKey}`, same `url` |
| 9773 §4.1 | ARI certificate ID | AKI.serial, serial with leading zero octet, vectors from the RFC |
| 2986, 5280 | CSR | SAN set, CN length, key/signature algorithm, extensions; parsed with .NET's `CertificateRequest`, not Hermod |

### 4.2 Server (`PKIConformance.ACME.Server.Tests`) — `RawACMEClient` → PKI ✅ 224

*Phase 2, 2026-11-26: 224 tests besides phase 0's 15 directory and nonce
tests; 29 red on Windows, 28 natively in WSL, all of them findings S-1 to
S-13 ([FINDINGS.md](FINDINGS.md)), tagged `KnownIssue`.* Not covered yet:
persistence across a restart, the revocation as the CRL and OCSP show it
(by `openssl`), `Accept` variants of the download, rate limits and
`subproblems` (T-S4, T-S7), EdDSA (T-S9).

Grouped by RFC 8555 section; each line is a test cluster of 3–10 tests.

| § | Cluster | Examples |
|---|---|---|
| 6.2 | Request authentication | wrong Content-Type (incl. `; charset=utf-8`), compact and general serialization, two signatures, unprotected header, `alg: none`/`HS256`/`RS1`/`EdDSA` → `badSignatureAlgorithm` **with** `algorithms`, both or neither of `jwk`/`kid`, `jwk` with private members, curve ≠ alg, EC point not on the curve, RSA < 2048 → `badPublicKey`, tampered payload/header |
| 6.3 | POST-as-GET | GET on order/authz/cert → 405, payload `{}` where `""` is required and vice versa |
| 6.4 | URL integrity | `url` differs in scheme, host, port, path case, trailing slash, query |
| 6.5 | Replay protection | missing, reused, foreign, malformed nonce → `badNonce` with a new one; `Replay-Nonce` on **every** answer incl. 404/405/problems; HEAD 200 / GET 204 + `no-store`; 50 parallel requests |
| 6.7 | Errors | `application/problem+json`, `urn:ietf:params:acme:error:` prefix, status codes per type, `subproblems` for multi-identifier failures (§6.7.1) |
| 7.1 | Resources | directory fields absolute URLs, `meta` types, `Link: rel="index"` everywhere, account object incl. `orders`, order `expires`, authz `wildcard`, status values only from §7.1.6 |
| 7.1.6 | State machines | every legal transition driven, every illegal one refused: finalize while pending → `orderNotReady`, finalize twice, challenge after invalid authz, cert of an invalid order |
| 7.3 | Accounts | 201 + Location, existing key → 200 + same Location, `onlyReturnExisting` → `accountDoesNotExist`, ToS required, contacts (`invalidContact`, `unsupportedContact`, hfields, several), update, deactivate → everything after refused |
| 7.3.4 | EAB | wrong MAC, unknown or reused kid, `url` ≠ new-account, payload ≠ outer key, HS384/HS512, missing when required → `externalAccountRequired` |
| 7.3.5 | Key change | inner not signed by the new key, old key wrong, `url` mismatch, new key in use → 409 + Location, inner with and without nonce |
| 7.4 | New order | empty or unknown identifier types → `unsupportedIdentifier`; DNS names: trailing dot, upper case, `_`, U-label vs. A-label, label > 63, name > 253, `*.*.x`, `a.*.x`; IPs: leading zeros, IPv6 compressed vs. full, IP as `dns`; duplicates, 101 identifiers; `notBefore`/`notAfter` |
| 7.4 | Finalize | CSR names subset/superset/case-different, CN not among the SANs, bad CSR signature, CSR key = account key (§11.1), weak and unsupported keys (Ed25519?), padded base64url |
| 7.4.2 | Download | `Accept` variants, chain order leaf → root-1, `Link: rel="up"`, no alternates |
| 7.5.2 | Authz deactivation | deactivate, then a new order needs a new proof |
| 7.6 | Revocation | by the account, by another account with valid authz, by the certificate key (`jwk` = cert key), reasons 2/6/7/8/9/10 → `badRevocationReason`, twice → `alreadyRevoked`, then the revocation is visible in the PKI's CRL/OCSP (judged by `openssl`) |
| 10 | Security | token entropy ≥ 128 bit, nonce entropy, one account cannot read another's order/authz/cert (unauthorized) |
| RFC 8738 | IP identifiers | SAN iPAddress, no CN, dns-01 not offered for IPs, reverse names refused |
| RFC 9773 | ARI | unauthenticated GET, malformed and unknown IDs, `Retry-After`, window start < end, `replaces` of another account's or an unknown certificate, `alreadyReplaced` |
| profiles draft | Profiles | `meta.profiles`, unknown → `invalidProfile`, order echoes profile, certificate fits it |
| — | Persistence | accounts survive a restart, orders do not, and a client that re-orders afterwards succeeds |

### 4.3 Validation (`PKIConformance.ACME.Validation.Tests`) — PKI → `ScriptedChallengeHost` ✅ 40

*Phase 2, 2026-11-26: 40 tests - http-01 green throughout (the request,
whitespace, wrong bodies and statuses, redirects and their loops, a host that
never answers, IPv6); dns-01 red throughout, every test of it at V-1; the
http-01 of a name through the server's `DNSClient` a tracker of T-S5; and
three self-tests of the bench's name server.*

http-01: 404/500, wrong body, trailing whitespace and CRLF (SHOULD ignore),
leading whitespace (must fail), body > 8 KiB, slow body, redirects (to HTTPS
with a bad certificate, to other ports, to other schemes, loops, > 10), Host
header, IPv6 literal, IP identifiers. dns-01: one of several TXT records,
split TXT strings, CNAME to a delegated zone, wildcard on the base name, case,
NXDOMAIN vs. empty answer, timeouts. The *policy* questions (redirect ports,
private addresses) go into the "Interpretations" section of `FINDINGS.md`,
because RFC 8555 does not settle them.

### 4.4 Client (`PKIConformance.ACME.Client.Tests`) — Hermod → `ScriptedACMEServer` ✅ 166

*Phase 3, 2026-11-26: 161 tests of Hermod's client and certificate manager,
and 5 of the bench itself (`BenchACMEServerTests`, by RawACME's client); 43
red, the same on both legs: 31 at the 14 findings of round 2, C-1 to C-11
and M-1 to M-3 ([FINDINGS.md](FINDINGS.md)), tagged `KnownIssue`, and 12
trackers, one for each client ToDo T-C1 to T-C12, tagged `ToDo`. On Windows
the test of the key file's mode skips (POSIX modes).* Not covered yet: the
manager's files against what certbot writes (needs the reference run of
phase 5), an order of an unknown status, several challenges of one type.

| Cluster | Scenarios |
|---|---|
| Wire form | every request checked by `RawACME`: flattened JWS, header members, exact `url` incl. query, `""` for POST-as-GET, Content-Type, no nonce ever used twice, URLs taken from the directory, never constructed |
| Nonces | `badNonce` once → retried with the nonce of the error; always → gives up after 3; nonces from error answers kept; parallel orders share the pool safely |
| Locations | relative `Location`, absolute to another host, missing → clear error |
| Waiting | `Retry-After` delta/date on polls, authz stuck in `processing`, order `processing` after finalize, certificate URL late, timeout honoured (fake `TimeProvider`) |
| Problems | `rateLimited`/503 with `Retry-After`, `badSignatureAlgorithm` + `algorithms`, `userActionRequired` + `Link: rel="terms-of-service"`, `subproblems` carried into `ACMEException`, problem without `type`, HTML error from a proxy |
| Authorizations | already valid (reuse) skipped, `deactivated`/`expired`/`revoked`, several challenges of one type, a token with `../` or `%2F` (responder must not serve outside its prefix) |
| Certificates | alternate chains in `Link`, chains of length 1–4 (as Pebble randomizes), CRLF/extra whitespace in PEM, leaf only |
| Forward compatibility | unknown members, member order, unknown status, extra challenge types |
| CSR | SAN = identifiers exactly, CN rule, IPv6 canonical form, key type and signature as asked |
| ARI | no `renewalInfo`, 404, window in the past → renew now, `Retry-After`; `replaces` sent only where the directory has ARI |
| EAB | kid and MAC as given, padding tolerated |
| Manager | file layout and modes compared with what **certbot itself** writes (`live/`, `archive/`, `cert.pem`, `chain.pem`, `fullchain.pem`, `privkey.pem`) — the reference comes from a real certbot run against Pebble (§4.6) and is kept as a fixture |

### 4.5 Interop A (`PKIInterop.ACMEClients.Tests`) — real clients → PKI 🔶 122

*Phase 4, 2026-11-27, natively in WSL: 122 tests - 111 of the matrix, the 6
account tests of lego of phase 0, 5 of the bench itself - 116 green, 6 red,
all of them dns-01 at V-1. No new finding: every client of the five takes
every cell of the PKI it has, and the refusals reach it in the RFC's words.
V-1 is seen three times over, by three DNS plugins of other hands: their
records arrive in BIND, and the PKI never asks.*

The PKI runs in-process, a server per test, its `http01Port` the port of the
client's own web server or of the bench's web server of a webroot, its
`DNSClient` pointed at a BIND of the test. The clients run as native Linux
programs, natively in WSL (`build/test-in-wsl.sh`) or on Debian (the
nightly), in a namespace of `build/bench-namespace.sh` where the names of
the bench resolve to the loopback. dns-01 goes through **BIND 9 with TSIG
and RFC 2136 updates**, so that each client's *own* DNS plugin is exercised
(`certbot-dns-rfc2136`, lego's `rfc2136`, acme.sh's `dns_nsupdate`). The
second, simpler path through `pebble-challtestsrv` and the clients' hooks is
not built: it would prove nothing BIND does not, until V-1 is fixed.

✅ green · ❌ red, at a finding · — the client's version lacks it (no test,
principle 7) · ⬜ not built yet

| Feature | certbot 4.0.0 | **lego 5.7.0** | acme.sh 3.1.1 | dehydrated 0.7.2 | uacme 1.7.6 |
|---|---|---|---|---|---|
| Account: new + ToS + contact | ✅ | ✅ | ✅ | ✅ | ✅ |
| Account: EAB | ✅ | ✅ | ✅ | ✅ | ✅ |
| Account: new contact / deactivate | ✅ / ✅ | — / — | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
| Account: key rollover (§7.3.5) | — | ✅ | — | — | ✅ |
| Account key types | ⬜ | ✅ EC256/384, RSA2048-4096; ML-DSA refused | ✅ ec-256/384, 2048 | ⬜ | ✅ EC, RSA |
| http-01 own web server / webroot | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ | — / ✅ | — / ✅ |
| dns-01 RFC 2136: record written / certificate | ✅ / ❌ V-1 | ✅ / ❌ V-1 | ✅ / ❌ V-1 | ⬜ hook | ⬜ hook |
| Wildcard / 16 SANs | ❌ V-1 / ✅ | ❌ V-1 / ✅ | ❌ V-1 / ✅ | ⬜ / ✅ | ⬜ / ✅ |
| IP identifiers v4 / v6 (RFC 8738) | — | ✅ / ✅ | ✅ / ✅ | — (sends an address as "dns": refused ✅) | ✅ / ✅ |
| Own CSR | ✅ | ✅ | ✅ | ✅ | ✅ |
| Certificate keys ec256/ec384/rsa2048/3072/4096 | ✅ | ✅ | ✅ | ✅ (no 3072) | ✅ |
| Profiles (preferred / required) | ✅ / ✅ | ✅ | — | — | — |
| Renewal forced / `replaces` (RFC 9773) | ✅ / — | ✅ / ✅ | ✅ / — | ✅ / — | ✅, window read / — |
| Revoke by account, reason, in the CRL / by certificate key | ✅ / ✅ | ✅ / — | ✅ / — | ✅ / ⬜ | ✅ / ✅ |
| tls-alpn-01 only → clean "no challenge for it" | — | ✅ | ✅ | ⬜ | ⬜ |
| Refused: `rejectedIdentifier` / `externalAccountRequired` / wrong answer | ✅ / ✅ / ✅ | ✅ / ✅ / ✅ | ✅ / ✅ / ✅ | ✅ / ⬜ / ✅ | ✅ / ✅ / ✅ |

**lego is a first-class peer**: it implements the most of the extensions the
PKI has (IP identifiers, ARI, profiles, EAB, RFC 2136, key rollover) and
tls-alpn-01, which the PKI does not — so it covers the most cells, positive
and negative. uacme is the second: key rollover, revocation by the
certificate's key, ARI's window.

Every cell asserts, independently of the PKI's own view: the names of the
leaf by .NET, exactly the ones asked for; the chain verified to the PKI's
root by `openssl verify -purpose sslserver`; key type and size as asked;
EKU serverAuth; AKI present; the certificate kept by the PKI as issued (its
state in-process, `ServerIssued`); a revoked certificate held revoked, for
its reason, and listed by the PKI's CRL (`openssl verify -crl_check`). What
the client said - its output, certbot's `letsencrypt.log`, acme.sh's log,
BIND's log - is the evidence of a red cell.

### 4.6 Interop B (`PKIInterop.ACMEServers.Tests`) — Hermod → real servers ⬜

| Feature | Pebble (+ challtestsrv) | step-ca | Boulder |
|---|---|---|---|
| Account, ToS, contact, find by key | ⬜ | ⬜ | ⬜ |
| EAB | ⬜ (config) | ⬜ (provisioner) | 📋 |
| http-01 via `HTTP01ChallengeResponder` | ⬜ | ⬜ | ⬜ |
| dns-01 via `DNS01ChallengeResponder` → challtestsrv `/set-txt` | ⬜ | ⬜ | ⬜ |
| Wildcard, IP identifiers | ⬜ | ⬜ | ⬜ |
| `badNonce` storm (`PEBBLE_WFE_NONCEREJECT=50` and `90`) | ⬜ | — | — |
| Random chain length, alternate roots (Pebble's deliberate variation) | ⬜ | — | — |
| Profiles, ARI, `replaces` | ⬜ | probe | ⬜ |
| Revocation | ⬜ | ⬜ | ⬜ |
| `ACMECertificateManager` end to end, renewal by ARI | ⬜ | ⬜ | ⬜ |
| Reference run: **certbot against Pebble** writes the `live/` layout the manager is compared with | ⬜ | — | — |

Pebble is the gate (it exists to catch client assumptions); step-ca is a
second, unrelated server stack; Boulder is Let's Encrypt's production code and
the strongest evidence that Hermod works against Let's Encrypt — nightly only,
because its compose stack is heavy.

### 4.7 Baseline diagonal — Hermod ↔ PKI ⬜

The existing scenarios of `PKITests/ACMETests` rerun here behind a recording
proxy whose captures `RawACME` judges request by request. Neither side can then
hide a shared misreading of the RFC behind the other.

---

## 5. Solution layout

```
PKIConformanceTests.slnx
README.md  PLAN.md  FINDINGS.md  [MUTATION.md]  LICENSE  SECURITY.md  redo.sh
.gitattributes  .gitignore
build/
  CommonTestSettings.props          net11.0, NUnit 5, analyzers (as DNS/SMTP/NTS)
  test-in-wsl.sh                    the suite natively in WSL, from a copy in the Linux file system
  bench-namespace.sh                a run where the bench's names resolve to the loopback (no root)
  peers/                            setup-wsl.sh (--check), pins.env (versions + SHA-256),
                                    later pebble/*.json, step-ca/*.json,
                                    boulder/compose.override.yml
src/
  PKIConformance.Core/
    RawACME/                        JWS, JWK, thumbprint, EAB, key change, CSR reader, ARI id
    Scripted/                       RawACMEClient, ScriptedChallengeHost, ScriptedDNSServer, ScriptedACMEServer,
                                    BenchCA (issues with .NET alone), BenchClock (a TimeProvider that writes every wait down)
    Servers/                        IACMEServerUnderTest, PKIACMEServer (in-process PKI), BenchTLS
    Peers/                          Peer, Lego, Certbot, AcmeSh, Dehydrated, Uacme, Bind (BIND 9 with RFC 2136);
                                    later PebbleFixture, StepCAFixture, BoulderFixture, RecordingProxy
    Wsl.cs  TestEnvironment.cs  TestCategories.cs  OpenSSL.cs  BenchNames.cs
conformance/
  PKIConformance.ACME.Codec.Tests/
  PKIConformance.ACME.Server.Tests/
  PKIConformance.ACME.Validation.Tests/
  PKIConformance.ACME.Client.Tests/
interop/
  PKIInterop.ACMEClients.Tests/     certbot, lego, acme.sh, dehydrated, uacme → PKI
  PKIInterop.ACMEServers.Tests/     Hermod → Pebble, step-ca, Boulder
  PKIInterop.PublicCAs.Tests/       Let's Encrypt staging (Online, opt-in)
InteropReport/                      .trx → docs/INTEROP-MATRIX.md (as in SSH)
fixtures/                           recorded answers of real servers, certbot's live/ layout
libs/  Styx  Hermod  Norn  Urdr  PKI  WWCP_Node  WWCP_Core
```

No root `Directory.Build.props` (it would leak into the submodules), only
`src/`, `conformance/` and `interop/` props importing
`build/CommonTestSettings.props`. Only `PKIConformance.Core` references the
submodules. The prefix `PKIConformance.ACME.*` leaves room for the PKI's other
enrolment protocols (EST, RFC 7030) later, without renaming anything.

---

## 6. Infrastructure design

- **`PKIACMEFixture`** — a started PKI on fresh ports (`WWCP_Node_TestKit`'s
  `TestPorts`), a root and a sub-CA, ACME settings set per test through
  `PUT v1/pki/acme` (open / `allowedNames` / EAB required / profiles /
  `http01Port`), EAB keys made through `POST v1/pki/acme/eab`, and optionally
  HTTPS with a TLS certificate the PKI issues to itself; the root goes to the
  clients as `REQUESTS_CA_BUNDLE` (certbot), `LEGO_CA_CERTIFICATES` (lego),
  `--ca-bundle` (acme.sh).
- **Name resolution** (§0.3) — the server under test and Hermod's client get a
  Hermod `DNSClient` pointed at the suite's authoritative server (BIND with
  the zone `acme.test`, or `pebble-challtestsrv`), so every name a test uses
  is in a zone the test owns. Until T-S5 and T-C11 are done, the tests that
  need a name other than an address are trackers; everything else uses
  `127.0.0.1` and `::1` as identifiers (RFC 8738), which needs no resolution.
- **Peers** in three tiers, following NTS/SSH. Debian 13.7 candidates, as
  checked on 2026-11-26: certbot 4.0.0 (+ dns-rfc2136 4.0.0), lego **4.9.1**,
  acme.sh 3.1.1, pebble 2.6.0, dehydrated 0.7.2, uacme 1.7.6, bind9 9.20.
  1. *Debian 13 packages* (`apt`) — gating in the nightly for certbot,
     acme.sh, Pebble, dehydrated, uacme and BIND.
  2. *Upstream, pinned* (`build/peers/pins.env` with version + SHA-256): lego
     release binary (v5), certbot in a venv from PyPI with hashes, acme.sh at
     a tag, Pebble and step-ca release binaries. **lego gates from this tier
     from the start**: Debian's 4.9.1 is from 2022 and has neither ARI nor
     profiles. certbot 4.0.0 has profiles but no ARI (that came in 4.1.0), so
     the ARI cells of certbot also need this tier.
  3. *Docker*: Boulder's compose stack at a pinned commit; nightly, `Docker`.
- **Ports** — every peer on a random high port; `http01Port` of the PKI set to
  the client's listener (`--http-01-port`, `--http.port`, `--httpport`). One
  test per client keeps the real port 80 (`asRoot`) to cover the default path.
- **Recording proxy** — a small loopback HTTP proxy in Core that stores every
  exchange as JSON in `artifacts/`; evidence for findings and source of
  `fixtures/`.
- **Categories** — `Loopback`, `WSL`, `Docker`, `Online`, `Slow`, `KnownIssue`
  (an implemented feature deviates), `ToDo` (a feature not implemented yet).

---

## 7. Phases

| Phase | Content | Done when |
|---|---|---|
| 0 ✅ | *Done 2026-11-26, locally on Windows and natively in WSL; CI not run yet.* Submodules Norn, Urdr, WWCP_Node, WWCP_Core; slnx; build on Windows and in WSL with `SkipFrontendBuild`; Core skeleton (`Wsl`, categories, `IACMEServerUnderTest`, PKI fixture); CI skeleton; **spikes**: PKI over HTTPS, PKI in-process reachable from WSL | `dotnet build` green on both legs, one trivial interop test (lego registers an account) green in WSL |
| M | *In Hermod and the PKI, not here:* the ACME server moves into Hermod with an issuer interface; the PKI plugs in its CA; T-S5 on the way. Here: `HermodACMEServer` as a second `IACMEServerUnderTest`, the pins advanced | the server suites green against both implementations |
| 1 ✅ | *Done 2026-11-26: 87 tests, no finding.* `RawACME` (`src/PKIConformance.Core/RawACME`: base64url, JWK, thumbprint, JWS, key authorization, EAB, key change, ARI id) + Codec tests | all RFC vectors green; Hermod ↔ RawACME ↔ PKI sign/verify in every direction |
| 2 ✅ | *Done 2026-11-26: 224 server and 40 validation tests, round 1 of the findings: S-1 to S-13 and V-1, 14 in all.* `RawACMEClient`, `ScriptedChallengeHost`, `ScriptedDNSServer`, `RawCSR`; Server + Validation conformance | ~150 tests; first findings round for the PKI |
| 3 ✅ | *Done 2026-11-26: 166 client tests, round 2 of the findings: C-1 to C-11 and M-1 to M-3, 14 in all; a tracker for every client ToDo.* `ScriptedACMEServer`, `BenchCA`, `BenchClock`; Client conformance | ~80 tests; first findings round for Hermod |
| 4 🔶 | *2026-11-27: 122 interop tests natively in WSL, 116 green, the 6 red ones dns-01 at V-1; no new finding. Not built yet: dns-01 by the hooks of dehydrated and uacme, certbot's account keys, dehydrated's revocation by key, tls-alpn-01 of dehydrated and uacme.* Interop A: certbot, acme.sh, dehydrated, uacme (Debian) and **lego** (pinned upstream v5) → PKI; BIND/RFC 2136; `bench-namespace.sh` | matrix §4.5 filled except the ARI cells of certbot |
| 5 | Interop B: Hermod → Pebble (+ nonce storm), step-ca; certbot-vs-Pebble reference layout; Boulder in Docker | matrix §4.6 filled |
| 6 | Upstream tier with pins; `InteropReport` → `docs/INTEROP-MATRIX.md`; nightly lanes incl. `against-submodule-masters` | matrix generated, nightly green |
| 7 | Optional: Posh-ACME and win-acme on the **Windows** leg (no WSL on hosted runners — real interop there too), Python `acme` driver for what no CLI does (key change, authz deactivation), Let's Encrypt staging, mutation sweep (`MUTATION.md`), JWS/JSON fuzzing of the PKI | as far as useful |

---

## 8. Running the suite

```
dotnet test PKIConformanceTests.slnx --filter "TestCategory!=Online&TestCategory!=WSL&TestCategory!=Docker&TestCategory!=KnownIssue&TestCategory!=ToDo"
dotnet test PKIConformanceTests.slnx --filter "TestCategory=WSL&TestCategory!=KnownIssue&TestCategory!=ToDo"
dotnet test PKIConformanceTests.slnx --filter "TestCategory=Docker"
dotnet test PKIConformanceTests.slnx --filter "TestCategory=KnownIssue|TestCategory=ToDo"
```

`build/peers/setup-wsl.sh --check` lists what is missing in WSL and how to get it.

CI as in the siblings: `ci.yml` on `windows-latest` and `debian:13` with the
offline set; `nightly.yml` with the WSL set natively on Debian (red on any
skip), the upstream tier, the Docker lane (Boulder), `against-submodule-masters`
(Hermod and PKI at master), and `KnownIssue` to report what now passes.

---

## 9. Findings protocol

As in SMTP, with prefixed IDs, because the fixes land in two repositories:
**S-** PKI ACME server, **V-** PKI validator, **C-** Hermod ACME client,
**M-** Hermod certificate manager, **I-** interop-only (a peer's behaviour the
RFC allows and one side does not cope with). Grouped in rounds; each finding
has the RFC quote, the mechanism with `File.cs:line` at the pinned revision,
the tests (`[Property("Finding", "S-3")]`, `KnownIssue` while open), and the PR
that fixed it in `OpenChargingCloud/PKI` or `Vanaheimr/Hermod`. A fix is closed
by a "Pin PKI <sha8>: …" / "Pin Hermod <sha8>: …" commit that removes
`KnownIssue`. Triage of a red test: suite defect, implementation deviation, or
RFC ambiguity — the last goes to "Interpretations" with the reading chosen.

---

## 10. Open decisions

Decided on 2026-11-26: see §0. Still open:

1. **Let's Encrypt staging**: is there a public test name with a DNS API whose
   credentials could live in a CI secret? Without one, Layer 4 stays manual.
2. **Peer tiers**: lego gates from the pinned upstream tier anyway (§6). Should
   certbot and acme.sh do the same, or do their Debian packages gate and
   upstream stays informational?
