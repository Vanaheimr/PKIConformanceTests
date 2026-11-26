# Findings

What the suite found where an implemented feature of Hermod's ACME client or
of the PKI's ACME server deviates from the RFCs - and what became of it.
Features that are not implemented yet are not findings: they are the ToDos of
[PLAN.md](PLAN.md), section 2.4, with tracker tests tagged `ToDo`.

IDs by where the fix lands:

| Prefix | Area | Fixed in |
|---|---|---|
| **S-** | the ACME server (`PKIHTTPAPI.ACME`, `ACMEJWS`, `ACMEState`) | `OpenChargingCloud/PKI` - after the move, `Vanaheimr/Hermod` |
| **V-** | the server's challenge validation (`ACMEValidator`) | as S- |
| **C-** | Hermod's ACME client (`ACMEClient`, the responders) | `Vanaheimr/Hermod` |
| **M-** | Hermod's `ACMECertificateManager` | `Vanaheimr/Hermod` |
| **I-** | interop only: a peer does something the RFC allows and one side does not cope | wherever the side that does not cope lives |

A finding is opened with red tests tagged `KnownIssue` and
`[Property("Finding", "S-1")]`, and closed by the commit that advances the pin
to the fix ("Pin PKI <sha8>: S-1 fixed"), which takes `KnownIssue` away and
keeps the `Finding` property. Each entry: the RFC sentence, the mechanism with
`File.cs:line` at the pinned revision, the tests, the fix.

## Open

None yet.

## Closed

None yet.

## Interpretations

Where RFC 8555 does not settle a question, the reading the suite takes, and why.

None yet.
