# Mutation sweep

What the suite would notice if the PKI's ACME server were wrong: one small
error at a time is planted into the server's code, and the suite is run
against it. A test that fails has **killed** the mutant. A mutant that no
test notices has **survived**: either nothing in the suite is watching that
line, or the change makes no difference (an *equivalent* mutant), and only
reading the line tells the two apart. This file is that reading, at PKI
`ba8324a9`.

Paths below are relative to `libs/PKI/PKI/`. Results, one line per mutant,
are in `build/mutation/results/<block>-<pki commit>.tsv` (pass 1) and
`...-pass2.tsv` (pass 2).

## Method

- **The mutants** (`build/mutation/genmut.py`): DNSConformanceTests'
  catalogue of regular-expression operators, plus three for the way the PKI's
  ACME code is written:
  - `&&` and `||` turned into each other;
  - `==` and `!=` turned into each other;
  - `<`, `<=`, `>` and `>=` moved by one;
  - `true` and `false` turned into each other;
  - **new:** `is null` and `is not null` turned into each other;
  - **new:** a negation taken away, as in `if (!jws.SignedBy(jwk)) throw`.

  Comments and string contents are never mutated. `<` and `>` count only
  with a blank before them, so the angle brackets of generic types are left
  alone. Stryker.NET has not run on this family's code; the regex operators
  are most of its value and none of its ceremony.
- **One block at a time** (`build/mutation/sweep.py`). A block is one file of
  the PKI and its *judge*: the cheapest test project that exercises it.

  | Block | File | Judge |
  |---|---|---|
  | `jws` | `Enrollment/ACMEJWS.cs` | `PKIConformance.ACME.Server.Tests` |
  | `state` | `Enrollment/ACMEState.cs` | `PKIConformance.ACME.Server.Tests` |
  | `api` | `HTTPAPI/PKIHTTPAPI.ACME.cs` | `PKIConformance.ACME.Server.Tests` |
  | `validator` | `Enrollment/ACMEValidator.cs` | `PKIConformance.ACME.Validation.Tests` |

- **The judge leaves out tests tagged `KnownIssue` and `ToDo`**. Those fail
  on the clean PKI already, so a mutant could hide behind them. The baseline
  run must pass in full, or the sweep does not start. The fuzzer runs 20
  requests per case instead of 200 (`PKICONFORMANCE_FUZZ_ITERATIONS`). It is
  seeded as always, and cheaper per mutant.
- **Verdicts**:
  - **KILLED**: a test failed, or the judge ran a different number of tests
    than the baseline.
  - **SURVIVED**: every test passed.
  - **NOT-VIABLE**: the compiler refused the mutant, for example a pattern
    variable used after `||`.
  - **TIMED-OUT**: the run took longer than ten times the clean run. This
    counts as killed, because a server that hangs has been noticed.
  - **STALE-BINARY**: the PKI the judge loads was not rebuilt. None occurred.
- **In a mirror of the repository** (`PKICONFORMANCE_MUTATION_TREE`), synced
  before every block. A block takes hours, and the checkout stays usable
  meanwhile; a sweep cut short never leaves a mutant in `libs/PKI`. A sweep
  measures a commit: it refuses to run while `libs/PKI` has changes of its
  own.
- **Pass 2** (`--survivors`) plants only the survivors of pass 1 again,
  against the tests written since. A gap counts as closed when the test
  written for it kills its mutant.

```
python build\mutation\sweep.py jws
python build\mutation\sweep.py jws --survivors
```

## Results

Pass 1, 2026-11-27 and 28, Windows 11, PKI `ba8324a9`:

| Block | Mutants | Killed | Timed out | Not viable | Survived |
|---|---|---|---|---|---|
| `jws` | 45 | 36 | 0 | 0 | 9 |
| `validator` | 15 | 7 | 0 | 0 | 8 |
| `state` | 74 | 28 | 1 | 1 | 44 |
| `api` | 228 | 141 | 5 | 13 | 69 |
| **all** | **362** | **212** | **6** | **14** | **130** |

Pass 2, 2026-11-28, the same PKI commit, against the tests written for the
gaps of pass 1:

| Block | Survivors of pass 1 | Killed now | Survive |
|---|---|---|---|
| `jws` | 9 | 3 | 6 |
| `validator` | 8 | 1 | 7 |
| `state` | 44 | 0 | 44 |
| `api` | 69 | 8 | 61 |
| **all** | **130** | **12** | **118** |

The 12 mutants killed are exactly the 12 gaps closed: each new test kills the
mutant it was written for, and no other survivor fell to them. Of the 348
mutants the compiler took, 230 are now killed (218 after pass 1). Of the 118
that survive, one is a gap still open; the reading below explains the other
117.

### What survived, by kind

| Kind | `jws` | `validator` | `state` | `api` | All |
|---|---|---|---|---|---|
| Equivalent: no behaviour changes, or only a log line or the text of a problem | 6 | 3 | 9 | 9 | 27 |
| Behind a finding: the code is never reached because of V-1 | | 3 | | 2 | 5 |
| Outside the suite's reach: the operator API, time, persistence, races | | | 33 | 33 | 66 |
| Not stated by the RFCs, or a limit of the PKI's own | | | 2 | 9 | 11 |
| Needs a bench the suite does not have yet: TLS on the challenge host, names it can prove, another configuration | | 1 | | 7 | 8 |
| **Gap, closed by a test** | **3** | **1** | | **8** | **12** |
| **Gap, open** | | | | **1** | **1** |
| **Survived** | **9** | **8** | **44** | **69** | **130** |

## The blocks

### `jws` - `Enrollment/ACMEJWS.cs`

The JWS of every request, its signature, its key and its URL. 36 of 45
mutants were killed: this is the block the suite guards best. Of the 9
survivors:

- **Equivalent (6)**:
  - L141: `IsPostAsGet` is unused by the server; the API looks at the
    payload itself.
  - L170: `#region ... = false`, a region name, which the operator read as
    code.
  - L313, L430, L439: a `return false` that cannot be reached after
    `Check` and `Parse` refused the input.
  - L531: a coordinate of the wrong length is refused by the next check
    either way.
- **Gaps, closed (3)**:
  - L485: no CSR of an RSA key had ever been finalized. The server's check of
    whether a CSR's key is an account's was never walked for RSA. Test:
    `A_CSR_Of_An_RSA_Key_Is_Signed`.
  - L557: an RSA `jwk` with an empty modulus. Test:
    `An_RSA_jwk_Of_An_Empty_Modulus_Is_badPublicKey`.
  - L559: the upper bound of 8192 bits. Test:
    `An_RSA_Key_Of_8192_Bits_Opens_An_Account` (category Slow).

### `validator` - `Enrollment/ACMEValidator.cs`

How the server looks at a challenge: http-01 against the bench's challenge
host, dns-01 against nothing (V-1). 7 of 15 killed. Of the 8 survivors:

- **Behind V-1 (3)**: L102, L238 and L241 are dns-01's lookup and its
  comparison, which no dns-01 ever reaches while `_acme-challenge` is no host
  name to Hermod (FINDINGS.md, V-1). They become reachable with V-1's fix.
- **Equivalent on the bench (3)**:
  - L88 `UseProxy`, L89 `UseCookies`: the bench has no proxy and sets no
    cookies.
  - L186: `<` turned into `<=` in the read loop, which ends at the limit
    either way.
- **Gap, closed (1)**: L145, the timeout of a host that never answers.
  `A_Host_That_Never_Answers_Is_No_Proof` passed for any refusal; it now
  asserts the error type `connection` too.
- **Needs a bench the suite does not have (1)**: L91, the certificate of an
  HTTPS host that a redirect leads to. The PKI follows such a redirect and
  takes any certificate there, as Let's Encrypt does: http-01 is there to
  bootstrap a valid certificate, and it may meet a self-signed or expired one
  on the way. The bench's challenge host speaks no TLS. Closing this needs a
  TLS listener with a certificate nobody trusts on the challenge host.

### `state` - `Enrollment/ACMEState.cs`

What the server keeps: accounts, orders, authorizations, nonces, the keys of
external account bindings, and the file they are saved to. 29 of 74 were
killed (28, plus one timed out). Of the 44 survivors, none is a gap in what
the suite claims to test:

- **Equivalent (9)**:
  - Seven `[NotNullWhen]` attributes (L574, L634, L676, L677, L711, L761,
    L890): nullable annotations, which the runtime does not read.
  - L748 `IssuedFor`: it counts an account's certificates for the
    operator's list. The ACME code that relies on it, `replaces`, is tested
    only by the KnownIssue tests of S-10 and S-11, which the judge leaves
    out.
  - L770: a failed record of an issued certificate is only logged.
- **Outside the suite's reach (33)**:
  - **Time (14)**: when orders and authorizations expire (L285 ×2, L343),
    how long a nonce lives and when old ones are pruned (L512, L513 ×3,
    L535 ×2), and the cleanup of what expired a day ago (L828, L844, L849 ×3).
    The suite runs against a real clock. Hermod's state has a `Now` that a
    test could move, but the bench does not expose it.
  - **Persistence (9)**: the state file read on start (L101) and what happens
    when writing it fails (L619, L622, L648, L699, L729, L773, L898, L932).
    The suite never restarts a server, and never makes its disk fail.
  - **Races (7)**: `TryAdd` asks again under its lock whether a key or a
    binding was taken meanwhile (L580–L605). Only two requests that arrive
    together reach this.
  - **The operator removing a binding's key (3)**: L717, L722, L726, used
    only by `DELETE /api/v1/pki/acme/eab/{kid}`.
- **A limit of the PKI's own (2)**: L878, how many orders of an account are
  pending, for the limit of 300. The suite does not place 300 orders.

### `api` - `HTTPAPI/PKIHTTPAPI.ACME.cs`

Every resource of ACME, and the operator's JSON API beside it. 146 of 228
killed (141, plus 5 timed out); 13 were refused by the compiler. Of the 69
survivors:

- **The operator's JSON API (33)**: L202–L421, all of it.
  `GET/PUT /api/v1/pki/acme`, `GET /api/v1/pki/acme/accounts`,
  `DELETE .../accounts/{id}` and `GET/POST/DELETE /api/v1/pki/acme/eab` speak
  the PKI's own API, not ACME. The bench configures the PKI in-process.
  Every one of these 33 mutants survived, including the ones that take away
  an authorization check (L222, L325, L377, L418). That is no finding of
  this suite. It is a ToDo for the PKI's own tests.
- **Equivalent (9)**:
  - L186: `IdOfACME`'s `> 0` as `>= 0`. Every route that calls it has an
    `{id}`.
  - L861: `> 1` as `>= 1`, after one problem was thrown already.
  - The text of a problem or a log line only: L651, L819, L1167, L1197,
    L1280, L1415, L1681.
- **The commonName of a certificate (5)**: L1265, L1267 ×3 and L1268. The
  server uses the CSR's commonName if it has 64 characters at most (RFC
  5280's upper bound). Otherwise it takes the first ordered name that is no
  wildcard and has 64 characters at most. The bench proves addresses only
  (`ACMEServerFixture`), and no address has more than 39 characters:
  - **behind V-1 (2)**: the negation of L1267, and L1268, pick among
    wildcards, and no wildcard can be proven while dns-01 does not validate;
  - **needs a bench (3)**: L1265, and L1267's `||` and `<`, differ only for a
    name of 64 characters or more, which needs DNS names the bench can
    prove.
- **Needs a bench with another configuration (4)**: L966 ×4. A name is
  refused when neither http-01 nor dns-01 is offered, and the bench always
  offers both.
- **Not stated by the RFCs (6)**:
  - L460: an empty `"profiles": {}` in the directory when there are none.
  - L862: the type of a problem that sums up several.
  - L911: http-01 offered for a wildcard. RFC 8555 does not forbid it; the
    CA/Browser Forum's Baseline Requirements (3.2.2.4.19) do.
  - L1101: whether a response to a challenge that is no longer pending
    starts another validation.
  - L1161: how long a valid authorization holds.
  - L1499: a serial named in ARI without its leading zero, which the server
    accepts as a courtesy.
- **Limits of the PKI's own (3)**: L623 (ten contacts), L830 (100
  identifiers) and L893 (300 pending orders). These are boundaries the RFCs
  do not set.
- **Gaps, closed (8)**:
  - L634, L635 ×2, the checks of a `mailto:` address: three new cases of
    `A_mailto_That_Is_No_Single_Address_Is_invalidContact`:
    - `mailto:@example.org`, no local part;
    - `mailto:admin@`, nothing after the @;
    - `mailto:admin@example.org,`, a comma and no second address.
  - L800, an order that asks for `notBefore` or `notAfter` alone: Hermod
    refuses both together, and a server that refused only that pair passed.
    Test: `An_Order_Of_A_Validity_Is_Refused_Or_Signed_So`. It accepts a
    refusal (a problem document), or a certificate that holds as asked.
  - L1239, the commonName of a CSR: no CSR of the suite had one.
    `A_CSR_Whose_commonName_Is_Not_Of_The_Order_Is_badCSR` sends one CSR with
    a name and one with an address that the order does not have.
  - L1507, ARI looked up by its serial alone.
    `The_Serial_Of_A_Certificate_Under_Another_keyIdentifier_Is_404`.
  - L1647, the account object's `termsOfServiceAgreed`: no test looked at
    it, and a server that said `false` of an account that agreed passed. Now
    `A_New_Account_That_Agrees_Is_Opened` and
    `An_Update_Of_termsOfServiceAgreed_Is_Ignored` check it.
  - L1676, the `error` of an order: one appeared on an order where nothing
    had failed. `A_New_Order_Is_201_With_Its_URL_And_Its_Object` asserts
    none.
- **Gap, open (1)**: L1377. An account that proved every name of a
  certificate may revoke it, and the server asks for at least one name.
  Without that check, a certificate of no names could be revoked by any
  account, because "all names proven" is true of an empty list. The PKI
  signs no certificate without names over ACME. To test this, the bench needs
  to have the PKI sign one outside ACME (`PKIACMEServer` would need a hook
  for it).

## What would close the rest

- **V-1's fix**: makes 5 survivors reachable (L102, L238, L241 in
  `validator`, and the wildcard branches of L1267/L1268 in `api`). Run pass 2
  of both blocks again after it.
- **DNS names the bench can prove**, for example a resolver of the bench's
  own for http-01: the 3 commonName survivors of long names, L1265 and
  L1267, in `api`.
- **A second configuration of the server under test**, offering one
  challenge type or none: L966 ×4 of `api`.
- **A clock the bench can move**: the 14 time survivors of `state`, and
  L1161 of `api`. `PKIACMEServer` would hand the tests the state's `Now`.
- **A restart of the server under test**, and a state file the bench can
  make unwritable: the 9 persistence survivors.
- **A TLS listener on the challenge host**: L91 of `validator`.
- **A certificate signed outside ACME**: L1377 of `api`.
- **The PKI's own tests** of its operator API: 33 survivors, the
  authorization checks among them. They belong in `OpenChargingCloud/PKI`,
  not here.
