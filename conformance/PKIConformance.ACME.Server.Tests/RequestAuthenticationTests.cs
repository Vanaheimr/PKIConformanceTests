using System.Security.Cryptography;
using System.Text;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 6.2: <i>"The server MUST verify the JWS before processing
/// the request."</i> - a flattened JWS of one signature, without an
/// unprotected header, of an algorithm of public keys, with a "jwk" or a
/// "kid" where each belongs, never both; and section 5: base64url without
/// padding.
/// </summary>
/// <remarks>
/// <para>
/// Every request of ACME is authenticated by its JWS alone. A server that
/// lets one through that is not what section 6.2 says lets through what
/// nobody signed: a payload changed after the signature, a key that is not
/// the account's, an algorithm whose "signature" anybody can make.
/// </para>
/// <para>
/// The requests here are new-account requests (signed by their "jwk") and
/// POST-as-GETs of an account (signed as its "kid"), changed in one place
/// each.
/// </para>
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §6.2")]
public class RequestAuthenticationTests(String ServerName) : ACMEServerFixture(ServerName)
{

    private const String Agreed = """{"termsOfServiceAgreed":true}""";

    private String NewAccountURL
        => Client.Resource("newAccount");


    #region Content-Type

    /// <summary>
    /// <i>"Because client requests in ACME carry JWS objects in the Flattened
    /// JSON Serialization, they must have the Content-Type header field set to
    /// "application/jose+json". If a request does not meet this requirement,
    /// then the server MUST return a response with status code 415
    /// (Unsupported Media Type)."</i>
    /// </summary>
    [TestCase("application/json")]
    [TestCase("text/plain")]
    [TestCase("application/jose")]
    [TestCase(null, Description = "no Content-Type at all")]
    [Property("Level", "MUST")]
    public async Task A_Request_Of_Another_Media_Type_Is_Answered_415(String? ContentType)
    {

        using var key = RawKey.Generate("ES256");

        var answer = await Client.PostAsync(key, null, NewAccountURL, Agreed, ContentType: ContentType);

        AssertStatus(answer, 415);

    }

    #endregion

    #region Serialization

    /// <summary>
    /// <i>"The JWS MUST be in the Flattened JSON Serialization"</i> - not in the
    /// compact one.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_In_The_Compact_Serialization_Is_Refused()
    {

        using var key = RawKey.Generate("ES256");

        AssertProblem(await Client.PostAsync(key, null, NewAccountURL, Agreed, Body: jws => jws.ToCompact()), 400, "malformed");

    }

    /// <summary>
    /// <i>"The JWS MUST be in the Flattened JSON Serialization"</i> - not in the
    /// general one, even of a single signature.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_In_The_General_Serialization_Is_Refused()
    {

        using var key = RawKey.Generate("ES256");

        var answer = await Client.PostAsync(key, null, NewAccountURL, Agreed,
                                            Body: jws => RawJson.Object(("payload",    RawJson.Quote(jws.Payload)),
                                                                        ("signatures", "[" + RawJson.Object(("protected", RawJson.Quote(jws.Protected)),
                                                                                                            ("signature", RawJson.Quote(jws.Signature))) + "]")));

        AssertProblem(answer, 400, "malformed");

    }

    /// <summary>
    /// <i>"The JWS MUST NOT have multiple signatures"</i> - the same signature
    /// twice, in the general serialization.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_Of_Two_Signatures_Is_Refused()
    {

        using var key = RawKey.Generate("ES256");

        var answer = await Client.PostAsync(key, null, NewAccountURL, Agreed,
                                            Body: jws => {
                                                var one = RawJson.Object(("protected", RawJson.Quote(jws.Protected)), ("signature", RawJson.Quote(jws.Signature)));
                                                return RawJson.Object(("payload", RawJson.Quote(jws.Payload)), ("signatures", $"[{one},{one}]"));
                                            });

        AssertProblem(answer, 400, "malformed");

    }

    /// <summary>
    /// <i>"The JWS Unprotected Header [RFC7515] MUST NOT be used"</i>.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_With_An_Unprotected_Header_Is_Refused()
    {

        using var key = RawKey.Generate("ES256");

        var answer = await Client.PostAsync(key, null, NewAccountURL, Agreed,
                                            Body: jws => RawJson.Object(("protected", RawJson.Quote(jws.Protected)),
                                                                        ("header",    """{"kid":"unprotected"}"""),
                                                                        ("payload",   RawJson.Quote(jws.Payload)),
                                                                        ("signature", RawJson.Quote(jws.Signature))));

        AssertProblem(answer, 400, "malformed");

    }

    /// <summary>
    /// <i>"The JWS Payload MUST NOT be detached"</i> - no "payload" member.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_Without_Its_Payload_Is_Refused()
    {

        using var key = RawKey.Generate("ES256");

        var answer = await Client.PostAsync(key, null, NewAccountURL, Agreed,
                                            Body: jws => RawJson.Object(("protected", RawJson.Quote(jws.Protected)),
                                                                        ("signature", RawJson.Quote(jws.Signature))));

        AssertProblem(answer, 400, "malformed");

    }

    /// <summary>
    /// <i>"The JWS Unencoded Payload Option [RFC7797] MUST NOT be used"</i> -
    /// a header of "b64": false, made critical as RFC 7797, section 6, asks.
    /// The payload is base64url still and the signature is over it as RFC
    /// 7515 has it: a server that ignores "b64" and "crit" takes the request.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2, 7797 §6")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-2")]
    public async Task A_Request_With_The_Unencoded_Payload_Option_Is_Refused()
    {

        using var key = RawKey.Generate("ES256");

        var answer = await Client.PostAsync(key, null, NewAccountURL, Agreed,
                                            Header: header => header.Set("b64", "false").Set("crit", """["b64"]"""));

        AssertRefused(answer);

    }

    /// <summary>
    /// RFC 7515, section 4.1.11: <i>"If any of the listed extension Header
    /// Parameters are not understood and supported by the recipient, then the
    /// JWS is invalid."</i> - and an invalid JWS is no request.
    /// </summary>
    [Test]
    [Property("RFC", "7515 §4.1.11")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-2")]
    public async Task A_Critical_Header_Parameter_It_Does_Not_Know_Makes_The_Request_Invalid()
    {

        using var key = RawKey.Generate("ES256");

        var answer = await Client.PostAsync(key, null, NewAccountURL, Agreed,
                                            Header: header => header.Set("urn:example:never-heard-of", "true").Set("crit", """["urn:example:never-heard-of"]"""));

        AssertRefused(answer);

    }

    #endregion

    #region Algorithms

    /// <summary>
    /// <i>"If the client sends a JWS signed with an algorithm that the server
    /// does not support, then the server MUST return an error with status code
    /// 400 (Bad Request) and type
    /// "urn:ietf:params:acme:error:badSignatureAlgorithm". The problem document
    /// returned with the error MUST include an "algorithms" field with an
    /// array of supported "alg" values."</i> - and "alg" <i>"MUST NOT contain
    /// "none" or a Message Authentication Code (MAC) algorithm"</i>.
    /// </summary>
    [TestCase("none")]
    [TestCase("HS256")]
    [TestCase("HS512")]
    [TestCase("RS384")]
    [TestCase("RS512")]
    [TestCase("ES256K")]
    [TestCase("RS1")]
    [TestCase("nonsense")]
    [Property("Level", "MUST")]
    public async Task An_Algorithm_It_Does_Not_Support_Is_badSignatureAlgorithm_With_Its_Algorithms(String Algorithm)
    {

        using var key = RawKey.Generate("ES256");

        var answer     = await Client.PostAsync(key, null, NewAccountURL, Agreed, Header: header => header.SetString("alg", Algorithm));
        var algorithms = answer.StringsOf("algorithms");

        Assert.Multiple(() => {
            AssertProblem(answer, 400, "badSignatureAlgorithm");
            Assert.That(answer.Object?["algorithms"],  Is.Not.Null,                                  $"\"algorithms\": {answer}");
            Assert.That(algorithms,                     Is.Not.Empty,                                $"\"algorithms\": {answer}");
            Assert.That(algorithms,                     Does.Not.Contain(Algorithm),                 $"\"algorithms\": {answer}");
            Assert.That(algorithms,                     Does.Not.Contain("none"),                    $"never \"none\": {answer}");
            Assert.That(algorithms,                     Has.None.StartsWith("HS"),                   $"never a MAC: {answer}");
        });

    }

    /// <summary>
    /// <i>"An ACME server MUST implement the "ES256" signature algorithm"</i> -
    /// and every algorithm a server says it supports is one an account can be
    /// opened with.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Every_Algorithm_It_Names_Opens_An_Account_And_ES256_Is_Among_Them()
    {

        using var probe   = RawKey.Generate("ES256");
        var refusal       = await Client.PostAsync(probe, null, NewAccountURL, Agreed, Header: header => header.SetString("alg", "none"));
        var algorithms    = refusal.StringsOf("algorithms");

        Assert.That(algorithms, Does.Contain("ES256"), refusal.ToString());

        using (Assert.EnterMultipleScope())
        {
            foreach (var algorithm in algorithms.Where(algorithm => algorithm is "ES256" or "ES384" or "ES512" or "RS256" or "PS256"))
            {
                using var key = RawKey.Generate(algorithm);
                var (account, answer) = await Client.NewAccountAsync(key);
                Assert.That(account, Is.Not.Null, $"{algorithm}: {answer}");
            }
        }

    }

    #endregion

    #region jwk and kid

    /// <summary>
    /// <i>"The "jwk" and "kid" fields are mutually exclusive. Servers MUST
    /// reject requests that contain both."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_With_Both_jwk_And_kid_Is_Refused()
    {

        var account = await NewAccountAsync();

        var answer  = await Client.PostAsync(account.Key, account.URL, account.URL, null,
                                             Header: header => header.Set("jwk", account.Key.JWK.ToJSON()));

        AssertProblem(answer, 400);

    }

    /// <summary>
    /// <i>"Either "jwk" (JSON Web Key) or "kid" (Key ID)"</i> - one of them.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_With_Neither_jwk_Nor_kid_Is_Refused()
    {

        using var key = RawKey.Generate("ES256");

        AssertProblem(await Client.PostAsync(key, null, NewAccountURL, Agreed, Header: header => header.Remove("jwk")), 400);

    }

    /// <summary>
    /// <i>"For newAccount requests, and for revokeCert requests authenticated
    /// by a certificate key, there MUST be a "jwk" field."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_newAccount_Request_With_A_kid_Is_Refused()
    {

        var account = await NewAccountAsync();

        AssertProblem(await Client.PostAsync(account, NewAccountURL, Agreed), 400);

    }

    /// <summary>
    /// <i>"For all other requests, the request is signed using an existing
    /// account, and there MUST be a "kid" field."</i> - a POST-as-GET of an
    /// account signed with its key as a "jwk".
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_Of_An_Account_With_A_jwk_Is_Refused()
    {

        var account = await NewAccountAsync();

        AssertProblem(await Client.PostAsync(account.Key, null, account.URL, null), 400);

    }

    /// <summary>
    /// <i>"This field MUST contain the account URL received by POSTing to the
    /// newAccount resource."</i> - a "kid" of no account: of the type the
    /// registry has for it (section 6.7).
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2, §6.7")]
    [Property("Level", "SHOULD")]
    public async Task A_kid_Of_No_Account_Is_accountDoesNotExist()
    {

        var account = await NewAccountAsync();
        var nobody  = account.URL + "0";

        var answer  = await Client.PostAsync(account.Key, nobody, account.URL, null);

        AssertProblem(answer, null, "accountDoesNotExist");

    }

    #endregion

    #region Keys

    /// <summary>
    /// <i>"If the server supports the signature algorithm "alg" but either does
    /// not support or chooses to reject the public key "jwk", then the server
    /// MUST return an error with status code 400 (Bad Request) and type
    /// "urn:ietf:params:acme:error:badPublicKey"."</i> - its example: <i>""alg"
    /// is "ES256" but "jwk" does not contain a valid P-256 public key"</i>: a
    /// point that is not on the curve.
    /// </summary>
    /// <remarks>
    /// Where the platform checks the point on import (OpenSSL, on Linux) -
    /// gating. On Windows (CNG) it does not, and the answer is 500 (S-3):
    /// <see cref="A_Point_Off_The_Curve_Is_badPublicKey_On_Windows"/> is the
    /// test of that leg, and this one skips there.
    /// </remarks>
    [Test]
    [Property("Level", "MUST")]
    public Task A_Point_Off_The_Curve_Is_badPublicKey()
    {

        if (OperatingSystem.IsWindows())
            Assert.Ignore("Windows does not check the point on import (S-3) - " +
                          "A_Point_Off_The_Curve_Is_badPublicKey_On_Windows is the test of this leg.");

        return PointOffTheCurveIsBadPublicKeyAsync();

    }

    /// <summary>
    /// <see cref="A_Point_Off_The_Curve_Is_badPublicKey"/> on Windows, whose
    /// CNG takes a point off the curve on import and throws only when it
    /// verifies - which the PKI answers 500 serverInternal (S-3). Skips
    /// elsewhere, so that a run of KnownIssue on Linux does not report S-3
    /// fixed: a fix shows on Windows alone.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-3")]
    public Task A_Point_Off_The_Curve_Is_badPublicKey_On_Windows()
    {

        if (!OperatingSystem.IsWindows())
            Assert.Ignore("S-3 is of Windows alone - A_Point_Off_The_Curve_Is_badPublicKey is the test of this leg, and gates.");

        return PointOffTheCurveIsBadPublicKeyAsync();

    }

    private async Task PointOffTheCurveIsBadPublicKeyAsync()
    {

        using var key   = RawKey.Generate("ES256");
        var y           = RawBase64Url.Decode(key.JWK.Y!);
        y[^1]          ^= 0x01;
        var offCurve    = RawJWK.EC("P-256", key.JWK.X!, RawBase64Url.Encode(y));

        var answer      = await Client.PostAsync(key, null, NewAccountURL, Agreed, Header: header => header.Set("jwk", offCurve.ToJSON()));

        AssertProblem(answer, 400, "badPublicKey");

    }

    /// <summary>
    /// The example of section 6.2: <i>""alg" is "RS256" but the modulus "n" is
    /// too small (e.g., 512-bit)"</i> - a key of 1024 bits, which no CA takes
    /// (CA/Browser Forum Baseline Requirements, section 6.1.5: 2048 at least).
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_RSA_Key_Of_1024_Bits_Is_badPublicKey()
    {

        using var key = RawKey.Generate("RS256", RSABits: 1024);

        AssertProblem(await Client.PostAsync(key, null, NewAccountURL, Agreed), 400, "badPublicKey");

    }

    /// <summary>
    /// A "jwk" of P-384 in a request of "alg" ES256: RFC 7518, section 3.4,
    /// has ES256 on P-256 only. Refused - as badPublicKey (the algorithm is
    /// supported, the key is not one of it) or badSignatureAlgorithm; RFC 8555
    /// does not say which.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2, 7518 §3.4")]
    [Property("Level", "MUST")]
    public async Task A_Key_Of_Another_Curve_Than_Its_Algorithm_Is_Refused()
    {

        using var p384  = RawKey.Generate("ES384");
        using var p256  = RawKey.Generate("ES256");

        var answer      = await Client.PostAsync(p384, null, NewAccountURL, Agreed,
                                                 Header:    header => header.SetString("alg", "ES256"),
                                                 SignWith:  p256);

        AssertProblem(answer, 400, "badPublicKey", "badSignatureAlgorithm");

    }

    #endregion

    #region Signatures

    /// <summary>
    /// <i>"The server MUST verify the JWS before processing the request."</i> -
    /// a payload changed after it was signed.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Payload_Changed_After_The_Signature_Is_Refused()
    {

        using var key  = RawKey.Generate("ES256");

        var answer     = await Client.PostAsync(key, null, NewAccountURL, Agreed,
                                                Body: jws => new RawJWS(jws.Protected, RawBase64Url.Encode("""{"termsOfServiceAgreed":true,"contact":["mailto:mallory@example.org"]}"""), jws.Signature).ToFlattenedJSON());

        AssertProblem(answer, 400);

    }

    /// <summary>
    /// <i>"The server MUST verify the JWS before processing the request."</i> -
    /// a protected header changed after it was signed: another URL.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Protected_Header_Changed_After_The_Signature_Is_Refused()
    {

        var account   = await NewAccountAsync();
        var original  = await Client.SignAsync(account.Key, account.URL, account.URL, null);
        var changed   = RawBase64Url.Encode(original.ProtectedJSON.Replace("\"url\":", "\"x\":0,\"url\":"));

        var answer    = await Client.SendAsync(HttpMethod.Post, account.URL, Encoding.UTF8.GetBytes(new RawJWS(changed, original.Payload, original.Signature).ToFlattenedJSON()));

        AssertProblem(answer, 400);

    }

    /// <summary>
    /// A request in the name of an account - its "kid" - signed by another
    /// key: <i>"signed using the account's private key"</i>, and by nobody
    /// else's.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_Signed_By_Another_Key_Than_The_Account_s_Is_Refused()
    {

        var account     = await NewAccountAsync();
        using var other = RawKey.Generate("ES256");

        var answer      = await Client.PostAsync(account, account.URL, null, SignWith: other);

        AssertRefused(answer);

    }

    /// <summary>
    /// An ECDSA signature in DER, as .NET and OpenSSL make it by default,
    /// where RFC 7518, section 3.4, has R and S of fixed length side by side.
    /// </summary>
    [Test]
    [Property("RFC", "7518 §3.4")]
    [Property("Level", "MUST")]
    public async Task An_ECDSA_Signature_In_DER_Is_Refused()
    {

        using var key  = RawKey.Generate("ES256");
        var jws        = await Client.SignAsync(key, null, NewAccountURL, Agreed);
        var der        = key.Sign(jws.SigningInput, DSASignatureFormat.Rfc3279DerSequence);

        var answer     = await Client.SendAsync(HttpMethod.Post, NewAccountURL,
                                                Encoding.UTF8.GetBytes(new RawJWS(jws.Protected, jws.Payload, RawBase64Url.Encode(der)).ToFlattenedJSON()));

        AssertProblem(answer, 400);

    }

    #endregion

    #region Section 5: base64url without padding

    /// <summary>
    /// Section 5: <i>"Trailing '=' characters MUST be stripped. Encoded values
    /// that include trailing '=' characters MUST be rejected as improperly
    /// encoded."</i> - one of the three parts of the JWS padded, and signed as
    /// it is sent, so that nothing but the padding is wrong with it.
    /// </summary>
    [TestCase("protected")]
    [TestCase("payload")]
    [TestCase("signature")]
    [Property("RFC", "8555 §5")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-1")]
    public async Task A_Part_Of_The_JWS_With_Padding_Is_Refused(String Part)
    {

        using var key   = RawKey.Generate("ES256");
        var nonce       = await Client.NonceAsync();

        // A header and a payload whose base64 needs padding: their lengths are
        // no multiple of three. The payload is 29 octets; the header gets a
        // member that brings it there.
        var payload     = Agreed;
        var header      = "";

        for (var filler = "x"; ; filler += "x")
        {
            header = new JWSHeader().SetString("alg", "ES256").Set("jwk", key.JWK.ToJSON()).SetString("nonce", nonce).SetString("url", NewAccountURL).SetString("filler", filler).ToJSON();
            if (Encoding.UTF8.GetByteCount(header) % 3 != 0)
                break;
        }

        var protectedPart  = Encode(Encoding.UTF8.GetBytes(header),  Padded: Part == "protected");
        var payloadPart    = Encode(Encoding.UTF8.GetBytes(payload), Padded: Part == "payload");
        var signature      = key.Sign(Encoding.ASCII.GetBytes($"{protectedPart}.{payloadPart}"));
        var signaturePart  = Encode(signature,                         Padded: Part == "signature");

        var jws            = new RawJWS(protectedPart, payloadPart, signaturePart);

        Assert.That(jws.Protected + jws.Payload + jws.Signature, Does.Contain("="), "the arrangement pads");

        AssertProblem(await Client.SendAsync(HttpMethod.Post, NewAccountURL, Encoding.UTF8.GetBytes(jws.ToFlattenedJSON())), 400);

    }

    private static String Encode(Byte[] Octets, Boolean Padded)
    {
        var text = RawBase64Url.Encode(Octets);
        return Padded ? text + new String('=', (4 - text.Length % 4) % 4) : text;
    }

    #endregion

}
