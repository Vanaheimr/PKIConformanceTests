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

### Round 1 - the PKI's server and validator (phase 2, 2026-11-26, PKI `ba8324a9`, Hermod `0a93a6fb`)

Paths below are relative to `libs/PKI/PKI/`.

| ID | Level | In short |
|---|---|---|
| [V-1](#v-1) | MUST | dns-01 never validates: `_acme-challenge` is no host name to Hermod's `DomainName` |
| [S-1](#s-1) | MUST | base64url with padding is taken, in the JWS, the CSR and the certificate of a revocation |
| [S-2](#s-2) | MUST | "crit" is not read: the Unencoded Payload Option and unknown critical parameters are taken |
| [S-3](#s-3) | MUST | a "jwk" whose point is off its curve is a 500 serverInternal, not 400 badPublicKey - on Windows |
| [S-4](#s-4) | MUST | a GET of a POST-as-GET resource is 405, but no problem document of the type "malformed" |
| [S-5](#s-5) | MUST | a POST-as-GET of the directory and of newNonce is refused |
| [S-6](#s-6) | MUST | the account object of an external account binding does not have the binding |
| [S-7](#s-7) | MUST | a CSR of another account's key is signed |
| [S-8](#s-8) | MUST | an "xn--" label is not checked to be an A-label |
| [S-9](#s-9) | MUST | an address with a leading zero is read as octal: "010.0.0.1" becomes 8.0.0.1 |
| [S-10](#s-10) | MUST | an order of RFC 9773 does not say what it "replaces" |
| [S-11](#s-11) | SHOULD | "replaces" of a certificate sharing no name, or replaced by a pending order, is taken |
| [S-12](#s-12) | MUST | the "profiles" of the directory are descriptions, not URLs (draft-ietf-acme-profiles-03) |
| [S-13](#s-13) | SHOULD | an order without a profile, where there is no default, is refused instead of given one |

#### V-1

dns-01 never validates. RFC 8555, section 8.4: *"Query for TXT records for
the validation domain name"* - *"_acme-challenge"* below the name.

`Enrollment/ACMEValidator.cs:100` asks `DNSClient.Query(DomainName.Parse(name), ...)`,
and `DomainName.Parse` of Hermod is a host name's parser: it refuses the
underscore of `_acme-challenge` ("The given domain name does not match the
required format!"). Every dns-01 challenge ends invalid with
`dns: the TXT records of '_acme-challenge....' could not be read`, before a
question is ever sent - and wildcards, which the PKI proves by dns-01 alone,
are never issued. Phase 1 did not see it: its codec test replaced `LookupTXT`.

Fix: `DNSServiceName.Parse(name)` (or `DomainName.ParseLenient`), which take
underscore labels - `BenchNameServerTests` asks the bench's name server that
way through the same `DNSClient` and gets every record.

Tests: `DNS01ValidationTests` (all 14; each also checks that the validation
name was asked for, so that none of them passes because nothing was asked).
And by three clients of other hands in five versions, each with its own DNS
plugin writing into BIND by RFC 2136 - the records arrive
(`*_Writes_Its_dns01_Record_By_RFC_2136`, green), the PKI never asks:
`CertbotDebianTests` and `CertbotUpstreamTests` (certbot 4.0.0 and 5.10.0)
`.Certbot_Gets_A_Certificate_By_dns01`, `LegoTests.Lego_Gets_A_Certificate_By_dns01`,
`AcmeShDebianTests` and `AcmeShUpstreamTests` (acme.sh 3.1.1 and 3.1.7)
`.AcmeSh_Gets_A_Certificate_By_dns01` (a name and a wildcard each, 10).

#### S-1

RFC 8555, section 5: *"Trailing '=' characters MUST be stripped. Encoded
values that include trailing '=' characters MUST be rejected as improperly
encoded."*

The PKI decodes with `System.Buffers.Text.Base64Url.DecodeFromChars`, which
takes padding: the protected header, payload and signature
(`Enrollment/ACMEJWS.cs:228-234`), the CSR of finalize
(`HTTPAPI/PKIHTTPAPI.ACME.cs:1211`, a certificate is issued of it) and the
certificate of revoke-cert (`HTTPAPI/PKIHTTPAPI.ACME.cs:1350`) - and, as the
fuzzer found in phase 7, the coordinates of a "jwk"
(`Enrollment/ACMEJWS.cs:528-529`): an account is opened for an "x" padded.
Fix: refuse a value with '=' before decoding it (malformed; badCSR for the
CSR; badPublicKey for the "jwk").

Tests: `RequestAuthenticationTests.A_Part_Of_The_JWS_With_Padding_Is_Refused` (3),
`...A_Coordinate_Of_The_jwk_With_Padding_Is_Refused`,
`FinalizeTests.A_CSR_With_Padding_Is_Refused`,
`RevocationTests.A_Certificate_With_Padding_Is_Refused`.

#### S-2

RFC 8555, section 6.2: *"The JWS Unencoded Payload Option [RFC7797] MUST NOT
be used"*; RFC 7515, section 4.1.11: *"If any of the listed extension Header
Parameters are not understood and supported by the recipient, then the JWS is
invalid."*

`Enrollment/ACMEJWS.cs` reads "alg", "jwk", "kid", "nonce" and "url" and
nothing else of the protected header: a request with `"b64": false,
"crit": ["b64"]` - a JWS of RFC 7797 whose payload is the base64url text
itself - opens an account, as does one with a critical parameter of nobody's.
Fix: refuse every header with "crit" (ACME has no extension that needs one),
and "b64".

Tests: `RequestAuthenticationTests.A_Request_With_The_Unencoded_Payload_Option_Is_Refused`,
`...A_Critical_Header_Parameter_It_Does_Not_Know_Makes_The_Request_Invalid`.

#### S-3

RFC 8555, section 6.2: *"If the server supports the signature algorithm "alg"
but either does not support or chooses to reject the public key "jwk", then
the server MUST return an error with status code 400 (Bad Request) and type
"urn:ietf:params:acme:error:badPublicKey"."* - its example, *""jwk" does not
contain a valid P-256 public key"*.

`Enrollment/ACMEJWS.cs:535` counts on `ECDsa.Create(ECParameters)` to refuse a
point off the curve. On Linux it does (OpenSSL), and the answer is
badPublicKey; on Windows (CNG) it does not throw there - the exception comes
later, in `SignedBy` (`ACMEJWS.cs:281`), which catches nothing, and
`HTTPAPI/PKIHTTPAPI.ACME.cs:1552` answers it 500 serverInternal. **Windows
only**: natively in WSL the answer is badPublicKey, and the test of that leg
gates. Fix: `ecdsa.ExportParameters(false)` after import, or validate the
point (`ECParameters.Validate` does not), or catch `CryptographicException`
in `SignedBy` as badPublicKey.

Tests: `RequestAuthenticationTests.A_Point_Off_The_Curve_Is_badPublicKey_On_Windows`,
which skips elsewhere - the nightly, on Linux, does not see this one closed;
a run on Windows does. `...A_Point_Off_The_Curve_Is_badPublicKey` is the
gating test of the other platforms, and skips on Windows.

#### S-4

RFC 8555, section 6.3: *"Except for the cases described in this section, if
the server receives a GET request, it MUST return an error with status code
405 (Method Not Allowed) and type "malformed"."*

The resources are registered for POST alone (`HTTPAPI/PKIHTTPAPI.ACME.cs:161-171`),
and Hermod's HTTP server answers the GET: 405, `application/json`,
`{"request": ..., "description": "Method not allowed!"}` - no problem document,
no type. Fix: a GET handler of every POST resource that answers the problem
document of section 6.3.

Tests: `PostAsGetTests.A_GET_Is_Answered_405_malformed` (9),
`FinalizeTests.The_Certificate_Is_Downloaded_By_A_POST_as_GET`.

#### S-5

RFC 8555, section 6.3: *"The server MUST allow GET requests for the directory
and newNonce resources (see Section 7.1), in addition to POST-as-GET requests
for these resources."*

`HTTPAPI/PKIHTTPAPI.ACME.cs:156-158` registers GET for the directory, HEAD and
GET for newNonce, and no POST: a POST-as-GET is 405. Fix: POST handlers that
check the JWS (as `ACMEHandle` does) and answer as GET.

Tests: `PostAsGetTests.A_POST_as_GET_Of_The_Directory_Is_Answered_With_The_Directory`,
`...A_POST_as_GET_Of_newNonce_Is_Answered_With_A_Nonce`.

#### S-6

RFC 8555, section 7.3.4: *"The account object the CA returns MUST include an
"externalAccountBinding" field with the same value as the field in the
request."*

`AccountJSON` (`HTTPAPI/PKIHTTPAPI.ACME.cs:1635`) writes status, contact,
orders, createdAt and termsOfServiceAgreed; the binding is checked
(`:549-577`) and only its key's id is kept. Fix: keep the binding's JWS with
the account and write it back.

Tests: `ExternalAccountBindingTests.The_New_Account_Object_Has_The_Binding_As_It_Was_Sent`.

#### S-7

RFC 8555, section 11.1: *"ACME clients and servers MUST verify that a CSR
submitted in a finalize request does not contain a public key for any known
account key pair."*

`HTTPAPI/PKIHTTPAPI.ACME.cs:1253` compares the CSR's key with the key of the
account that finalizes, and no other: a certificate of another account's key
is signed. Fix: `PKI.ACMEState.AccountByThumbprint(thumbprint) is not null`.

Tests: `FinalizeTests.A_CSR_Of_Another_Account_s_Key_Is_Refused`.

#### S-8

RFC 8555, section 7.1.4: *"Servers MUST verify any identifier values that
begin with the ASCII-Compatible Encoding prefix "xn--" as defined in
[RFC5890] are properly encoded."*

`HTTPAPI/PKIHTTPAPI.ACME.cs:955-956` checks a host name's characters; it
refuses "xn--" alone and "xn--abc-", which no Punycode decoder turns into a
U-label, but takes "xn--99999999999999", which overflows (RFC 3492, section
6.4). Fix: decode every "xn--" label (`IdnMapping.GetUnicode`) and encode it
back.

Tests: `NewOrderTests.An_xn_Label_That_Is_No_A_Label_Is_Refused("xn--99999999999999.example.org")`.

#### S-9

RFC 8738, section 3: *"The value field MUST contain the textual form of the
address as defined in Section 2.1 of [RFC1123] for IPv4"* - dotted decimal;
RFC 8555, section 7.4: *"it MUST NOT issue a certificate with contents other
than those requested"*.

`HTTPAPI/PKIHTTPAPI.ACME.cs:976` reads "ip" with `IPAddress.TryParse`, which
takes inet_aton's forms: "010.0.0.1" is octal to it, and the order is for
8.0.0.1 where the client wrote 10.0.0.1. ("127.1", "0x7f.0.0.1" and
"3221225985" end as the address they say.) Fix: take dotted decimal of four
parts and RFC 5952 alone, or refuse a value whose `ToString()` is not itself.

Tests: `NewOrderTests.An_Address_Not_In_Its_Textual_Form_Is_Refused_Or_Read_As_Written("010.0.0.1", ...)`.

#### S-10

RFC 9773, section 5: *"If the server accepts a newOrder request with a
"replaces" field, it MUST reflect that field in the response and in subsequent
requests for the corresponding Order object."*

`OrderJSON` (`HTTPAPI/PKIHTTPAPI.ACME.cs:1653`) has no "replaces"; the order
keeps it as the replaced certificate's id (`ACMEOrder.Replaces`). Fix: keep the
identifier as sent, and write it.

Tests: `RenewalInfoTests.An_Order_That_Replaces_Says_So`.

#### S-11

RFC 9773, section 5: *"Servers SHOULD check that the identified certificate
and the newOrder request correspond to the same ACME Account, that they share
at least one identifier, and that the identified certificate has not already
been marked as replaced by a different Order that is not "invalid"."*

`HTTPAPI/PKIHTTPAPI.ACME.cs:871-889` checks the account, and marks a
certificate replaced once the replacing order is finalized (`IsReplaced`,
`:884`), not when it is placed: a certificate of 127.0.0.1 is "replaced" by an
order of ::1, and by two pending orders at once.

Tests: `RenewalInfoTests.An_Order_Of_None_Of_Its_Names_Does_Not_Replace`,
`...A_Second_Order_Replacing_The_Same_Certificate_Is_Refused`.

#### S-12

draft-ietf-acme-profiles-03, section 3: *"profiles (optional, object): A map
of profile names to URLs."*

`HTTPAPI/PKIHTTPAPI.ACME.cs:462` writes the profile's description, or "A
server's certificate of 7 days." - the draft's -00 and -01 had descriptions,
-02 made them URLs. Fix: a data URI of the description
(`data:text/plain;charset=utf-8,...`), which the draft allows.

Tests: `ProfileTests.The_Directory_Names_Its_Profiles_With_URLs`.

#### S-13

draft-ietf-acme-profiles-03, section 4: *"If the server is advertizing
profiles and receives a newOrder request which does not identify a specific
profile, it is RECOMMENDED that the server select a profile and associate it
with the new Order object."*

A PKI with profiles and no default refuses such an order as invalidProfile
(`HTTPAPI/PKIHTTPAPI.ACME.cs:817-821`). A reading of the PKI's own: "no
default" is a setting that asks every order to name its profile. Fix, if
wanted: the first profile, or one marked as the default.

Tests: `ProfileWithoutDefaultTests.An_Order_Without_A_Profile_Gets_One`.

### Round 2 - Hermod's client and certificate manager (phase 3, 2026-11-26, Hermod `0a93a6fb`)

Against `ScriptedACMEServer`, the suite's own server written from the RFC.
Paths below are relative to `libs/Hermod/Hermod/`.

| ID | Level | In short |
|---|---|---|
| [C-1](#c-1) | MUST | a certificate chain with a private key - or anything else but certificates - in it is taken |
| [C-2](#c-2) | MUST | the "url" and the "kid" are the URL re-encoded by `System.Uri`, not the string the server handed out |
| [C-3](#c-3) | MUST | the retry after a badNonce takes the oldest nonce of the pool, not the one of the badNonce |
| [C-4](#c-4) | MUST | a Replay-Nonce that is no base64url is kept and sent |
| [C-5](#c-5) | MUST NOT | a mailto: contact with hfields, or with two addresses, is sent |
| [C-6](#c-6) | MUST | a RenewalInfo whose window ends when it starts is taken as a window |
| [C-7](#c-7) | SHOULD NOT | a profile the directory does not advertise is asked for |
| [C-8](#c-8) | SHOULD NOT | an authorization is polled before the server's validation request came |
| [C-9](#c-9) | SHOULD | a Retry-After date is read by the system clock, not by the client's TimeProvider |
| [C-10](#c-10) | SHOULD | the User-Agent names the ACME software, not the HTTP client below it |
| [C-11](#c-11) | SHOULD | no Accept-Language is sent |
| [M-1](#m-1) | MUST | the Retry-After of a RenewalInfo is not followed: the window is asked for every six hours |
| [M-2](#m-2) | SHOULD | the window of a renewed certificate is first asked for six hours after its issuance |
| [M-3](#m-3) | SHOULD | the explanationURL of a RenewalInfo reaches nobody |

#### C-1

RFC 8555, section 11.4: *"When processing a file of type
"application/pem-certificate-chain", a client SHOULD verify that the file
contains only encoded certificates. If anything other than a certificate is
found (i.e., if the string "-----BEGIN" is ever followed by anything other
than "CERTIFICATE"), then the client MUST reject the file as invalid."* - the
key replacement attack of the same section: a server puts a private key of
its choosing into the chain.

`ACME/ACMEClient.cs:390` takes the body of the download as it is, and
`TLS/ServerCertificateChain.cs:215` (`X509Certificate2Collection.ImportFromPem`)
skips every block that is no certificate. A "PRIVATE KEY", "EC PRIVATE KEY",
"RSA PRIVATE KEY", "PUBLIC KEY" or "X509 CRL" in the chain is accepted, kept in
`ACMECertificate.FullChainPem` (`ACME/ACMEClient.cs:575`) - and written by the
manager into fullchain.pem, where whatever reads a key out of the
certificate file (a `ServerCertificateFile` without a key path, an nginx with
one file for both) finds the server's key instead of its own. Hermod itself
is safe as long as it passes its own key separately. Fix: refuse the
download unless every "-----BEGIN " is followed by "CERTIFICATE-----".

Tests: `CertificateTests.A_Chain_With_Anything_But_Certificates_Is_Rejected` (5).

#### C-2

RFC 8555, section 6.4: *"the client MUST set the "url" header parameter to
the exact string provided by the server (rather than performing any
re-encoding on the URL)"*; section 6.2: the "kid" *"MUST contain the account
URL received by POSTing to the newAccount resource"*.

Every URL of the server is kept as a `System.Uri` (`ACME/ACMEResources.cs:102`,
`:176-177`, `:251`, `ACME/ACMEClient.cs:881`) and written out with
`Uri.ToString()` (`ACME/ACMEClient.cs:855`, `:861`), which unescapes and
normalizes: `%20` is sent as a space, `%7E` as `~`, and `/./` is dropped. A
server that compares the strings - as section 6.4 says it SHOULD - answers
unauthorized to every request of such a URL, and accountDoesNotExist to every
request of such an account. `%2F`, a lower-case escape and a query survive.
Fix: keep the strings as received (`Uri.OriginalString`, or a string beside
the `Uri`) and send those.

Tests: `WireFormTests.The_url_Is_The_Exact_String_The_Server_Handed_Out` (3 of
7), `WireFormTests.The_kid_Is_The_Exact_Account_URL_The_Server_Handed_Out` (3 of 7).

#### C-3

RFC 8555, section 6.5: *"However, when retrying in response to a "badNonce"
error, the client MUST use the nonce provided in the error response."*

`ACME/ACMEClient.cs:888` retries, and the retry takes its nonce from the pool
(`:962`, `ConcurrentQueue.TryDequeue`: the oldest), while the nonce of the
badNonce answer was put at the end of it (`:874`, `:991`). With one nonce in
the pool the two are the same; with more - which requests at once leave - the
retry sends a nonce of before the badNonce, and against a server that
rejected the nonces of before (a restart, a stale front end) uses up its
three retries on them. Fix: take the Replay-Nonce of the badNonce answer for
the retry, past the pool.

Tests: `NonceTests.The_Retry_After_badNonce_Carries_The_Nonce_Of_The_badNonce`.

#### C-4

RFC 8555, section 6.5.1: *"The value of the Replay-Nonce header field MUST be
an octet string encoded according to the base64url encoding ... Clients MUST
ignore invalid Replay-Nonce values."*

`ACME/ACMEClient.cs:968-972` (the HEAD of newNonce) and `:986-991` (every
answer) take any value that is not empty: "not base64url!", "padded+/base64==",
"a.b" are sent as the nonce of the next request, which the server refuses as
badNonce. Fix: take only `[A-Za-z0-9_-]+`.

Tests: `NonceTests.An_Invalid_Replay_Nonce_Of_A_POST_Is_Ignored` (3),
`NonceTests.An_Invalid_Replay_Nonce_Of_newNonce_Is_Ignored` (2).

#### C-5

RFC 8555, section 7.3: *"Clients MUST NOT provide a "mailto" URL in the
"contact" field that contains "hfields" [RFC6068] or more than one
"addr-spec" in the "to" component."*

`ACME/ACMEClient.cs:232-234` puts "mailto:" before an address without a colon
and passes everything else as it is: "admin@acme.test?subject=renewal",
"mailto:admin@acme.test?cc=boss@acme.test" and "admin@acme.test,boss@acme.test"
are sent, and refused by the server. Fix: refuse a contact with "?" or a
second address in the client, with an ArgumentException.

Tests: `AccountTests.A_mailto_With_hfields_Or_Two_Addresses_Is_Not_Sent` (3).

#### C-6

RFC 9773, section 4.2: *"A RenewalInfo object in which the end timestamp
equals or precedes the start timestamp is invalid. Servers MUST NOT serve
such a response, and clients MUST treat one as though they failed to receive
any response from the server"*.

`ACME/ACMEClient.cs:493` refuses `end < start` and takes `end == start`; the
manager then renews at that one instant instead of on its own schedule.
Fix: `end <= start`.

Tests: `RenewalInfoTests.A_Window_That_Ends_When_Or_Before_It_Starts_Is_No_Window(0)`,
`CertificateManagerTests.A_Window_Of_No_Length_Leaves_The_Manager_s_Own_Schedule`.

#### C-7

draft-ietf-acme-profiles-03, section 4: *"The client SHOULD NOT request a
profile name that is not advertised in the server's Directory metadata
object."*

`ACME/ACMEClient.cs:311-312` sends the profile it is given; the directory's
profiles are read (`ACME/ACMEResources.cs:113`) and not looked at. A server
without profiles, or with others, gets it all the same. Fix: refuse it before
the order (or leave it out, with a word in the exception), unless the caller
says it was agreed out of band.

Tests: `OrderTests.A_Profile_The_Server_Does_Not_Advertise_Is_Not_Asked_For` (2);
against real servers (phase 5) `PebbleUpstreamTests.No_Profile_Pebble_Does_Not_Advertise_Is_Asked_For`
and `BoulderTests.No_Profile_Boulder_Does_Not_Advertise_Is_Asked_For` - both
of them refuse it as invalidProfile, which Hermod hands on.

#### C-8

RFC 8555, section 7.5.1: *"For challenges where the client can tell when the
server has validated the challenge (e.g., by seeing an HTTP or DNS request
from the server), the client SHOULD NOT begin polling until it has seen the
validation request from the server."*

`ACME/ACMEClient.cs:648` answers the challenges and `:655` polls at once,
every `PollInterval`; Hermod's `HTTP01ChallengeResponder` serves the
validation request and could tell. With a validation that comes 1.5 s later,
the client has polled 15 times by then. Fix: a task on
`IACMEChallengeResponder` that completes when the answer was fetched, awaited
(with a timeout) before polling.

Tests: `PollingTests.Polling_Begins_After_The_Validation_Request`.

#### C-9

RFC 9110, section 10.2.3: a Retry-After is *"either an HTTP-date or a number
of seconds to delay after receiving the response"* - the date a time of the
clock the client waits by.

`ACME/ACMEClient.cs:1057` subtracts `DateTimeOffset.UtcNow`, and waits on
`TimeProvider` (`:775`). With the system clock the two are one; with any other
TimeProvider - the one the client's constructor takes for that purpose, a
FakeTimeProvider of a test - a date is waited 0.1 s, or the whole poll
timeout. Fix: `TimeProvider.GetUtcNow()`.

Tests: `PollingTests.A_Retry_After_Date_Is_Read_By_The_Client_s_Clock`.

#### C-10

RFC 8555, section 6.1: *"This header field SHOULD include the name and
version of the ACME software in addition to the name and version of the
underlying HTTP client software."*

`ACME/ACMEClient.cs:165`: "Hermod-ACME/1.0". Fix: a second product, as
".NET/11.0", and the version of the assembly rather than "1.0".

Tests: `WireFormTests.The_User_Agent_Names_The_ACME_Software_And_The_HTTP_Client`.

#### C-11

RFC 8555, section 6.1: *"ACME clients SHOULD send an Accept-Language header
field in accordance with [RFC7231] to enable localization of error
messages."*

None is sent (`ACME/ACMEClient.cs:160-165` sets the User-Agent only). Fix: a
default of "en" or the current UI culture, as a constructor parameter.

Tests: `WireFormTests.An_Accept_Language_Is_Sent`.

#### M-1

RFC 9773, section 4.3.2: *"After an initial fetch of a certificate's
RenewalInfo, clients MUST fetch it again as soon as possible after the time
indicated in the Retry-After header"*, with *"reasonable limits"* - one
minute to one day, the RFC suggests.

`ACME/ACMECertificateManager.cs:472` waits until the renewal is due or
`CheckInterval` (six hours) has passed, whichever is earlier; the RetryAfter
the client reads (`ACMERenewalInfo.RetryAfter`) is never used. A CA that asks
for a look every hour - to move the window of a certificate it is about to
revoke - is asked every six. Fix: wait `min(due - now, clamp(RetryAfter, 1
minute, 1 day))`, and `CheckInterval` only where there is no RenewalInfo.

Tests: `CertificateManagerTests.The_Window_Is_Asked_For_Again_After_Its_Retry_After`.

#### M-2

RFC 9773, section 4.3: *"Clients SHOULD fetch a certificate's RenewalInfo
immediately after issuance."*

`ACME/ACMECertificateManager.cs:468-470` waits `CheckInterval` after a renewal
of its loop, and asks for the new certificate's window six hours later
(only the renewal of `StartAsync` is followed by a look at once, by the loop's
first round). Fix: go round the loop at once after a renewal.

Tests: `CertificateManagerTests.The_Window_Of_A_New_Certificate_Is_Asked_For_At_Once`.

#### M-3

RFC 9773, section 4.2: *"explanationURL (string, optional): A URL pointing to
a page that may explain why the suggested renewal window has its current
value ... Clients SHOULD provide this URL to their operator, if present."*

The client reads it (`ACMERenewalInfo.ExplanationURL`); the manager
(`ACME/ACMECertificateManager.cs:300-313`) keeps the RenewalInfo in a private
field and says it neither to its logger nor through a property or an event.
Fix: log it when the window changes, and expose the RenewalInfo.

Tests: `CertificateManagerTests.The_explanationURL_Reaches_The_Operator`.

### Round 3 - Hermod against real servers (phase 5, 2026-11-27, Hermod `0a93a6fb`)

Against Pebble 2.6.0 (Debian) and 2.10.3, step-ca 0.30.2 and Boulder
v0.20261117.0, and against what certbot 4.0.0 writes. Every cell the four
servers have is green but C-7, which Pebble 2.10.3 and Boulder see as well
(above), and one new finding. Paths below are relative to
`libs/Hermod/Hermod/`.

| ID | Level | In short |
|---|---|---|
| [M-4](#m-4) | — (certbot's layout) | privkey.pem ends without a newline, where certbot's ends with one |

#### M-4

The manager says of itself that it writes *"fullchain.pem and privkey.pem,
the names certbot uses"*, and a server of the world is configured for
certbot's files; certbot ends each of them with a newline (its live/ of a
real run against Pebble, `fixtures/certbot/live-layout.json`). RFC 7468,
section 3 makes the last line end optional - which is why this is the
reference's, not an RFC's - but whatever puts files together by `cat`
depends on it: `cat privkey.pem fullchain.pem > combined.pem`, the one file
HAProxy takes, then has "-----END PRIVATE KEY----------BEGIN CERTIFICATE-----"
on one line, which a PEM reader does not find a certificate in.

`ACME/ACMEClient.cs:824` keeps the key as `ExportPkcs8PrivateKeyPem()`, which
has no newline at its end, and `ACME/ACMECertificateManager.cs:420` writes it
as it is; fullchain.pem ends as the server's download does (with a newline,
at every server tested). Everything else is as certbot's: the names, the
modes (0644 and 0600), the blocks (certificates only, the leaf first; PKCS#8),
LF, the kind of key. Fix: a newline after the key, and after the chain where
the server sent none.

Tests: `CertbotReferenceTests.The_Managers_Files_End_With_A_Newline_As_Certbots`
(against certbot's live/ itself), `CertificateManagerTests.The_Files_End_With_A_Newline_As_Certbot_Writes_Them`
(offline, against the fixture).

### Round 4 - the PKI's server, fuzzed (phase 7, 2026-11-27, PKI `ba8324a9`)

Found by `FuzzTests`: the requests of every resource, spoiled one change at
a time - their payload and their protected header signed as they are, their
serialization not signed again - and each kind of wrong answer pinned by a
test of its own before it became a finding. Python's acme, which asks the
PKI what no client of the command line does (a key change, an authorization
given up, a CSR of other names, a revocation by proof), found nothing.
Paths below are relative to `libs/PKI/PKI/`.

| ID | Level | In short |
|---|---|---|
| [S-14](#s-14) | MUST | base64url with whitespace in it is taken: the signature, a coordinate of the "jwk", the CSR, the certificate of a revocation |
| [S-15](#s-15) | MUST | an "alg", or a member of the "jwk", that is no string is a 500 serverInternal |
| [S-16](#s-16) | MUST | a "jwk" that is no object beside a "kid", or a "kid" of null beside a "jwk", is taken: a request with both |
| [S-17](#s-17) | MUST | a body or a payload cut short of its closing brace, or with a NUL in it, is taken as JSON |
| [S-18](#s-18) | MUST | a "reason" of revokeCert beyond 32 bits is a 500 serverInternal, not badRevocationReason |
| [S-19](#s-19) | SHOULD | a CSR of a key on a curve nobody knows is a 500 serverInternal, not badCSR - and on Windows one of a point off its curve |

#### S-14

RFC 7515, section 2: base64url is *"without the inclusion of any line
breaks, whitespace, or other additional characters"*, and section 5.2, step
7: *"Base64url-decode the encoded representation of the JWS Signature,
following the restriction that no line breaks, whitespace, or other
additional characters have been used."*

`System.Buffers.Text.Base64Url.DecodeFromChars` skips whitespace, as it
takes padding (S-1): the signature (`Enrollment/ACMEJWS.cs:229`), the
coordinates of a "jwk" (`Enrollment/ACMEJWS.cs:528-529`, and `n` and `e` at
554-555), the CSR of finalize (`HTTPAPI/PKIHTTPAPI.ACME.cs:1211`) and the
certificate of revoke-cert (`HTTPAPI/PKIHTTPAPI.ACME.cs:1350`). A request
whose signature has a space, a tab or a line break in it is taken, a CSR or
a certificate with a line break in it is signed or revoked, an account is
opened for a "jwk" whose "x" has a space in it. The protected header and the
payload are safe by accident: the signing input is their text as sent.
Fix: refuse a value with a character outside the alphabet of base64url
before decoding it - S-1's fix with whitespace in it.

Tests: `RequestAuthenticationTests.A_Signature_With_Whitespace_In_It_Is_Refused` (3),
`...A_Coordinate_Of_The_jwk_With_Whitespace_Is_Refused` (2),
`FinalizeTests.A_CSR_With_Whitespace_Is_Refused`,
`RevocationTests.A_Certificate_With_Whitespace_Is_Refused`.

#### S-15

RFC 8555, section 6.2: *"If the client sends a JWS signed with an algorithm
that the server does not support, then the server MUST return an error with
status code 400 (Bad Request) and type
"urn:ietf:params:acme:error:badSignatureAlgorithm"."* and *"If the server
supports the signature algorithm "alg" but either does not support or
chooses to reject the public key "jwk", then the server MUST return an
error with status code 400 (Bad Request) and type
"urn:ietf:params:acme:error:badPublicKey"."*

`Enrollment/ACMEJWS.cs:159` reads "alg" as `Header.Value<String>("alg")`,
which throws for an array, an object or an integer beyond 64 bits - in the
constructor, which `Parse` calls (`:253`) after its try. The members of the
"jwk" are read so as well (`Enrollment/ACMEJWS.cs:380`, `Check`, and
`ECKeyOf` from `:503`). Nothing catches it, and `HTTPAPI/PKIHTTPAPI.ACME.cs:1552`
answers 500 serverInternal - for every resource, as the fuzzer found. A
"jwk" member of a string, a number or null is refused rightly. Fix: take
"alg" and the members of the "jwk" only where they are strings, malformed
or badPublicKey otherwise.

Tests: `RequestAuthenticationTests.An_alg_That_Is_No_String_Is_badSignatureAlgorithm` (4),
`...A_Member_Of_The_jwk_That_Is_No_String_Is_badPublicKey` (4).

#### S-16

RFC 8555, section 6.2: *"The "jwk" and "kid" fields are mutually
exclusive. Servers MUST reject requests that contain both."*

`Enrollment/ACMEJWS.cs:160-161` keeps the "jwk" only where it is an object
and the "kid" only where it is a string, and `:266` asks whether there is
one of them: a "jwk" of `""`, `-1`, `[]` or null beside the "kid" of the
account is no "jwk" to it, and the request is taken as the account's; a
newAccount request with a "kid" of null beside its "jwk" opens an account.
Fix: ask for the members' presence (`Header.ContainsKey`), and refuse a
"jwk" that is no object and a "kid" that is no string as malformed.

Tests: `RequestAuthenticationTests.A_Request_With_A_kid_And_A_jwk_That_Is_No_Key_Is_Refused` (4),
`...A_Request_With_A_jwk_And_A_kid_Of_null_Is_Refused`.

#### S-17

RFC 8555, section 6.2: *"The JWS MUST be in the Flattened JSON
Serialization [RFC7515]"*, and RFC 7515, section 5.2, step 3, of the
protected header: *"Verify that the resulting octet sequence is a
UTF-8-encoded representation of a completely valid JSON object"*. A text
cut short of its closing brace is no JSON text (RFC 8259, section 2), and
neither is one with a NUL between its tokens.

`Enrollment/ACMEJWS.cs:185` reads the body, and `:238` the payload, with
Newtonsoft's `JsonConvert.DeserializeObject`, whose serializer ends an
object where the text ends and reads past a NUL; the protected header's
`JObject.Parse` (`:228`) reads past a NUL between tokens too, and refuses a
header cut short. A request without the closing brace of its body is
taken, and so is a newAccount request whose payload has none. Fix: read
with a `JsonTextReader` that must be at its end afterwards, and refuse a
text with U+0000 in it.

Tests: `RequestAuthenticationTests.A_Body_That_Is_No_JSON_Text_Is_Refused` (2),
`...A_Part_Of_The_JWS_That_Is_No_JSON_Text_Is_Refused` (3).

#### S-18

RFC 8555, section 7.6: *"If a request contains a disallowed reasonCode,
then the server MUST reject it with the error type
"urn:ietf:params:acme:error:badRevocationReason"."*

`HTTPAPI/PKIHTTPAPI.ACME.cs:1401` takes an integer token as
`reasonToken.Value<Int32>()`, which overflows for 2^32 and beyond; the
OverflowException is answered 500 serverInternal. One beyond a double, an
array and an object are refused rightly as badRevocationReason. Fix:
`TryGetInt32`-like reading, badRevocationReason for anything else.

Tests: `RevocationTests.A_Reason_Beyond_Every_reasonCode_Is_badRevocationReason` (2).

#### S-19

RFC 8555, section 7.4: *"In such cases, the problem document returned by
the server SHOULD use error code "badCSR""* - for a CSR the CA is unwilling
to sign, as one of a key that is none: of a curve nobody knows
(1.2.840.10045.3.1.11), or a point off P-256.

`HTTPAPI/PKIHTTPAPI.ACME.cs:1214` catches FormatException and
CryptographicException of `CertificateRequest.LoadSigningRequest`. For a
curve nobody knows, .NET throws a PlatformNotSupportedException on every
platform ("The specified curve '1.2.840.10045.3.1.11' or its parameters are
not valid for this platform" on Linux, "The specified Oid ... is not valid"
on Windows), which is answered 500 serverInternal. For a point off P-256,
OpenSSL throws a CryptographicException ("point is not on curve") and the
answer is badCSR, while CNG throws a PlatformNotSupportedException again:
that half is of **Windows only**, as S-3. Fix: catch
PlatformNotSupportedException there too.

Tests: `FinalizeTests.A_CSR_Of_A_Key_On_A_Curve_Nobody_Knows_Is_badCSR`;
`...A_CSR_Of_A_Point_Off_Its_Curve_Is_badCSR_On_Windows`, which skips
elsewhere, and `...A_CSR_Of_A_Point_Off_Its_Curve_Is_badCSR`, the gating
test of the other platforms, which skips on Windows.

### Round 5 - clients of Windows (phase 7, 2026-11-27, PKI `ba8324a9`)

Posh-ACME 4.35.0 and win-acme 2.4.1 natively on Windows, against the PKI
on the loopback. Every cell of Posh-ACME is green; win-acme's are but its
certificates of addresses, where the two sides do not meet.

| ID | Level | In short |
|---|---|---|
| [I-1](#i-1) | — (interop) | win-acme asks for an address with a commonName of the empty string, which the PKI takes for an identifier |

#### I-1

RFC 5280, Appendix A: *"X520CommonName ::= CHOICE { ... utf8String
UTF8String (SIZE (1..ub-common-name)) ..."* - a commonName has a character
at least. RFC 8555, section 7.4: *"The CSR MUST indicate the exact same set
of requested identifiers as the initial newOrder request."*

win-acme 2.4.1 - built of simple-acme 2.4.1, `src/main.lib/Plugins/CsrPlugins/CsrPlugin.cs`,
`CommonName` - puts a commonName into every CSR, the empty string where the
order has no DNS name, as one of addresses alone. The PKI takes the
commonName of a CSR as an identifier asked for (`HTTPAPI/PKIHTTPAPI.ACME.cs:1238-1246`),
the empty one too, and refuses: badCSR, *"The CSR asks for , 127.0.0.1, and
the order is for 127.0.0.1."* Boulder reads a commonName of "" as none
(`csr/csr.go:109`, `if csr.Subject.CommonName != ""`), so win-acme's
certificate of an address is one Let's Encrypt issues and the PKI does
not. Each side has a part: win-acme's CSR is outside RFC 5280, the PKI
counts what is no identifier. Fix, on either side: the PKI to take an empty
commonName as none, as Boulder does; win-acme to leave the commonName out
where there is no name for it.

Tests: `WinAcmeTests.WinAcme_Gets_A_Certificate_Of_An_Address` (2).

## Closed

None yet.

## Interpretations

Where RFC 8555 does not settle a question, the reading the suite takes, and why.

- **A nonce that is no base64url** (section 6.5.2, *"the verifier MUST reject
  the JWS as malformed"*): "badNonce" is taken as well as "malformed" - it is
  the more specific of the two, Boulder and Pebble answer it, and a client
  retries it with the fresh nonce, which is what helps.
- **"status" of an account update other than "deactivated"** (section 7.3.2,
  *"MUST ignore any updates to [...] the "status" field (except as allowed by
  Section 7.3.6)"*): ignored with 200, or refused as malformed as Boulder
  does; what is tested is that the status does not change.
- **A key of another curve than its algorithm** (section 6.2): badPublicKey
  or badSignatureAlgorithm - the algorithm is supported, the key is not one
  of it; RFC 8555 names both errors and does not say which.
- **dns-01 through a CNAME, and a digest in two strings of one TXT record**
  (section 8.4, *"the contents of one of the TXT records"*): followed and
  joined, as Let's Encrypt does - Level SHOULD.
- **Non-canonical address forms** (RFC 8738, section 3): refused, or kept as
  the address the text says in that form; never read as another (S-9).
- **How often a client retries a badNonce** (RFC 8555, section 6.5, sets no
  number): a few times and then the server's error - a client that retries
  without end hangs its caller. Hermod retries three times.
- **PEM as servers write it** (RFC 7468): CRLF, empty lines and blanks between
  the blocks, the root sent along, the chain root first - all taken, Level
  SHOULD; Hermod finds the leaf by its key.
- **A token outside the base64url alphabet** (RFC 8555, section 8.3, a MUST
  of the server): what a client does with one is not said; the suite asks
  only that the answer is served at no other path than the token's own.
- **"Provide to their operator"** (RFC 9773, section 4.2): through the
  logger, a property or an event - whatever an operator can read (M-3).
- **What a peer's version lacks is no finding of anybody's** (phase 4): a
  client that sends no "replaces" (uacme 1.7.6, a SHOULD of RFC 9773) or
  has no IP identifiers (certbot 4.0.0) is a grey cell of the matrix.
  dehydrated 0.7.2 ordering an address as a "dns" identifier is its own
  mistake, which the PKI answers rightly as malformed - a refusal cell,
  green.
- **A storm of badNonce** (RFC 8555, section 6.5, a SHOULD retry, and
  Pebble refusing half or nine in ten of all good nonces): no client with a
  bound gets through nine in ten reliably, and the RFC sets none. What is
  judged is how Hermod retries - with the nonce of the answer, the same
  request again, no nonce twice - and that it gives up, where it does, after
  its fourth refusal of one request with the server's badNonce in hand.
- **The certificate files of certbot are the reference of the manager's**
  (phase 5): no RFC says how a certificate is kept in files, and servers of
  the world are configured for certbot's live/. A deviation from it that
  breaks a consumer of those files is a finding of the manager (M-4), even
  where RFC 7468 allows it.
- **A directory of plain HTTP** (RFC 8555, section 6.1: *"Each ACME
  function is accomplished by the client sending a sequence of HTTPS
  requests"*): Boulder's stack publishes its WFE at http://localhost:4001
  alone, and Hermod talks to it as it is given; lego 5 refuses one. The
  section describes and does not bid a client refuse - no finding, and the
  Boulder lane is the only one on HTTP.
- **A 5xx for the client's error** (phase 7; RFC 9110, section 15.6: *"the
  server is aware that it has erred"*): the fuzzer counts every one a wrong
  answer. It is a finding of the level of the RFC sentence that names the
  client's error for the request - badSignatureAlgorithm and badPublicKey
  (S-15) and badRevocationReason (S-18) are MUSTs, badCSR (S-19) a SHOULD.
  The fuzzer's own test is of the level SHOULD, and stays green of every
  known finding: their tests are the red ones.
- **A request taken whose text changed and whose content did not** (phase
  7): a signature with a space in it decodes to the same octets, a body
  without its closing brace to the same object. Still a finding (S-14,
  S-17): RFC 7515 and 8555 say how the text is to be, and two parsers that
  read one request apart are where an attack lives - the very thing a
  signature is to rule out.
- **step-ca's CRL against its certificates** (RFC 5280, section 6.3.3): it
  has an issuing distribution point and they have no distribution point to
  match, which openssl's `-crl_check` refuses as "different CRL scope". That
  is step-ca's, not Hermod's; its CRL is judged by its signature and its
  entries.
