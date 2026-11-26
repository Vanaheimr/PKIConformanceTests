using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using PKIConformance.Core.RawACME;

using HermodAccountKey = org.GraphDefined.Vanaheimr.Hermod.ACME.ACMEAccountKey;
using PKIJWS           = cloud.charging.open.PKI.Enrollment.ACMEJWS;
using PKIProblem       = cloud.charging.open.PKI.Enrollment.ACMEProblem;

namespace PKIConformance.ACME.Codec.Tests;

/// <summary>
/// RFC 7515 and RFC 7518, section 3: the signature of a JWS - of the raw
/// reference against the examples of RFC 7515, of Hermod's account key, and
/// as the PKI checks it (RFC 8555, section 6.2).
/// </summary>
/// <remarks>
/// <para>
/// <i>"The ECDSA P-256 SHA-256 digital signature is generated as follows: ...
/// Concatenate the two byte arrays in the order R and then S ... The resulting
/// 64-octet sequence is the JWS Signature value"</i> (RFC 7518, section 3.4).
/// Not DER, which is what most crypto libraries hand out by default - and what
/// a JWS library that forgot the conversion sends, and a lenient verifier
/// takes.
/// </para>
/// </remarks>
[Property("RFC", "7515 §5")]
public class JWSTests
{

    private const String URL   = "https://acme.test/acme/new-account";
    private const String Nonce = "oFvnlFP1wIhRlYS2jTaXbA";

    #region The reference against the RFC

    /// <summary>
    /// RFC 7515, Appendix A.2: RSASSA-PKCS1-v1_5 is deterministic, so the
    /// reference signs the example into exactly the signature printed there.
    /// </summary>
    [Test]
    [Property("RFC", "7515 App. A.2")]
    public void RawACME_Signs_The_RS256_Example_Of_RFC_7515_Appendix_A_2_Exactly()
    {

        using var key = RFCVectors.A2_Key();
        var signature = RawBase64Url.Encode(key.Sign(System.Text.Encoding.ASCII.GetBytes($"{RFCVectors.A2_Protected}.{RFCVectors.RFC7515_Payload}")));

        Assert.That(signature, Is.EqualTo(RFCVectors.A2_Signature));

    }

    [Test]
    [Property("RFC", "7515 App. A.2.2")]
    public void RawACME_Verifies_The_RS256_Example_Of_RFC_7515_Appendix_A_2()
    {

        var jws = new RawJWS(RFCVectors.A2_Protected, RFCVectors.RFC7515_Payload, RFCVectors.A2_Signature);
        var jwk = RawJWK.RSA(RFCVectors.A2_N, RFCVectors.A2_E);

        Assert.Multiple(() => {
            Assert.That(jws.VerifiedBy(jwk),                                                           Is.True);
            Assert.That(new RawJWS(RFCVectors.A2_Protected, "e30", RFCVectors.A2_Signature).VerifiedBy(jwk), Is.False, "another payload");
        });

    }

    [Test]
    [Property("RFC", "7515 App. A.3.2")]
    public void RawACME_Verifies_The_ES256_Example_Of_RFC_7515_Appendix_A_3()
    {

        var jws = new RawJWS(RFCVectors.A3_Protected, RFCVectors.RFC7515_Payload, RFCVectors.A3_Signature);
        var jwk = RawJWK.EC("P-256", RFCVectors.A3_X, RFCVectors.A3_Y);

        Assert.Multiple(() => {
            Assert.That(jws.VerifiedBy(jwk),                                                           Is.True);
            Assert.That(new RawJWS(RFCVectors.A3_Protected, "e30", RFCVectors.A3_Signature).VerifiedBy(jwk), Is.False, "another payload");
            Assert.That(jws.VerifiedBy(jwk, "ES384"),                                                  Is.False, "ES384 is not P-256");
        });

    }

    [Test]
    [Property("RFC", "7515 App. A.3")]
    public void RawACME_Signs_With_The_ES256_Key_Of_RFC_7515_Appendix_A_3_What_Verifies()
    {

        using var key = RFCVectors.A3_Key();
        var jws       = RawJWS.Sign(key, """{"alg":"ES256"}""", """{"iss":"joe"}""");

        Assert.Multiple(() => {
            Assert.That(jws.Protected,                                                       Is.EqualTo(RFCVectors.A3_Protected));
            Assert.That(RawBase64Url.Decode(jws.Signature),                                  Has.Length.EqualTo(64));
            Assert.That(jws.VerifiedBy(RawJWK.EC("P-256", RFCVectors.A3_X, RFCVectors.A3_Y)), Is.True);
        });

    }

    #endregion

    #region Hermod

    /// <summary>
    /// Hermod's ES256 signatures: R and S of 32 octets each - also where one of
    /// them is small enough to need fewer octets, which happens once in 128
    /// signatures - and they verify by its JWK.
    /// </summary>
    [Test]
    [Property("RFC",   "7518 §3.4")]
    [Property("Level", "MUST")]
    public void Hermod_Signs_ES256_As_R_And_S_Of_32_Octets_Each()
    {

        using var key = HermodAccountKey.Generate();
        var       jwk = RawJWK.Parse(key.JWK.ToString());

        Assert.Multiple(() => {

            for (var i = 0; i < 300; i++)
            {

                var jws = RawJWS.Sign(key.Sign,
                                      RawJson.Object(("alg", RawJson.Quote(key.Algorithm)), ("nonce", RawJson.Quote($"n{i}")), ("url", RawJson.Quote(URL))),
                                      "{}");

                Assert.That(RawBase64Url.Decode(jws.Signature), Has.Length.EqualTo(64), $"signature {i}");
                Assert.That(jws.VerifiedBy(jwk, "ES256"),       Is.True,                $"signature {i}");

            }

        });

    }

    #endregion

    #region The PKI

    /// <summary>
    /// A request signed by the reference, with every algorithm the PKI takes,
    /// holds in the PKI - read from the body as a client sends it.
    /// </summary>
    [TestCase("ES256", 0)]
    [TestCase("ES384", 0)]
    [TestCase("ES512", 0)]
    [TestCase("RS256", 2048)]
    [TestCase("RS256", 3072)]
    [TestCase("RS256", 4096)]
    [TestCase("PS256", 2048)]
    [Property("RFC",   "8555 §6.2")]
    [Property("Level", "MUST")]
    public void PKI_Verifies_A_Request_Signed_By_The_Reference(String Algorithm, Int32 RSABits)
    {

        using var key = RawKey.Generate(Algorithm, RSABits == 0 ? 2048 : RSABits);
        var       jws = RawJWS.ACME(key, URL, Nonce, KeyId: null, PayloadJSON: """{"termsOfServiceAgreed":true}""");
        var       pki = PKIJWS.Parse(jws.ToFlattenedJSON());

        Assert.Multiple(() => {
            Assert.That(pki.Algorithm,                                    Is.EqualTo(Algorithm));
            Assert.That(pki.Nonce,                                        Is.EqualTo(Nonce));
            Assert.That(pki.URL,                                          Is.EqualTo(URL));
            Assert.That(pki.SignedBy(pki.JWK!),                           Is.True, jws.ProtectedJSON);
            Assert.That(PKIJWS.Thumbprint(pki.JWK!),                      Is.EqualTo(key.JWK.Thumbprint));
        });

    }

    /// <summary>
    /// The key of RFC 7515, Appendix A.2 in a request of ACME - a signature
    /// the PKI cannot have made itself, because nobody chose it but the RFC.
    /// </summary>
    [Test]
    [Property("RFC",   "7515 App. A.2")]
    [Property("Level", "MUST")]
    public void PKI_Verifies_A_Request_Signed_By_The_Key_Of_RFC_7515_Appendix_A_2()
    {

        using var key = RFCVectors.A2_Key();
        var       pki = PKIJWS.Parse(RawJWS.ACME(key, URL, Nonce, KeyId: null, PayloadJSON: "{}").ToFlattenedJSON());

        Assert.That(pki.SignedBy(JObject.Parse(RawJWK.RSA(RFCVectors.A2_N, RFCVectors.A2_E).ToJSON())), Is.True);

    }

    /// <summary>
    /// A signature over anything but what was sent - the payload changed after
    /// signing - does not hold.
    /// </summary>
    [TestCase("ES256")]
    [TestCase("RS256")]
    [TestCase("PS256")]
    [Property("RFC",   "8555 §6.2")]
    [Property("Level", "MUST")]
    public void PKI_Refuses_A_Signature_Over_Another_Payload(String Algorithm)
    {

        using var key     = RawKey.Generate(Algorithm);
        var       signed  = RawJWS.ACME(key, URL, Nonce, KeyId: null, PayloadJSON: """{"contact":["mailto:a@acme.test"]}""");
        var       changed = new RawJWS(signed.Protected, RawBase64Url.Encode("""{"contact":["mailto:b@acme.test"]}"""), signed.Signature);
        var       pki     = PKIJWS.Parse(changed.ToFlattenedJSON());

        Assert.That(pki.SignedBy(pki.JWK!), Is.False);

    }

    /// <summary>
    /// ECDSA in DER, as a crypto library hands it out and a careless JWS
    /// library passes it on: RFC 7518, section 3.4, has R || S - and the PKI
    /// takes nothing else.
    /// </summary>
    [TestCase("ES256")]
    [TestCase("ES384")]
    [TestCase("ES512")]
    [Property("RFC",   "7518 §3.4")]
    [Property("Level", "MUST")]
    public void PKI_Refuses_An_ECDSA_Signature_In_DER(String Algorithm)
    {

        using var key  = RawKey.Generate(Algorithm);
        var       jws  = RawJWS.Sign(data => key.Sign(data, DSASignatureFormat.Rfc3279DerSequence),
                                     RawJson.Object(("alg",   RawJson.Quote(Algorithm)),
                                                    ("jwk",   key.JWK.ToJSON()),
                                                    ("nonce", RawJson.Quote(Nonce)),
                                                    ("url",   RawJson.Quote(URL))),
                                     "{}");
        var       pki  = PKIJWS.Parse(jws.ToFlattenedJSON());

        Assert.That(pki.SignedBy(pki.JWK!), Is.False);

    }

    /// <summary>
    /// The padding is part of the algorithm: PKCS#1 v1.5 under "PS256", PSS
    /// under "RS256", does not hold.
    /// </summary>
    [TestCase("RS256", "PS256")]
    [TestCase("PS256", "RS256")]
    [Property("RFC",   "7518 §3.3, §3.5")]
    [Property("Level", "MUST")]
    public void PKI_Refuses_An_RSA_Signature_Of_The_Other_Padding(String Said, String SignedWith)
    {

        using var key  = RawKey.Generate(SignedWith);
        var       jws  = RawJWS.Sign(key,
                                     RawJson.Object(("alg",   RawJson.Quote(Said)),
                                                    ("jwk",   key.JWK.ToJSON()),
                                                    ("nonce", RawJson.Quote(Nonce)),
                                                    ("url",   RawJson.Quote(URL))),
                                     "{}");
        var       pki  = PKIJWS.Parse(jws.ToFlattenedJSON());

        Assert.That(pki.SignedBy(pki.JWK!), Is.False);

    }

    /// <summary>
    /// An algorithm of another curve than the key's - ES384 said, P-256 signed
    /// with SHA-384 - is refused: RFC 7518, section 3.4, ties each to its curve.
    /// Refused as badSignatureAlgorithm, or as a signature that does not hold.
    /// </summary>
    [TestCase("ES384", "ES256")]
    [TestCase("ES256", "ES384")]
    [TestCase("ES512", "ES256")]
    [Property("RFC",   "7518 §3.4")]
    [Property("Level", "MUST")]
    public void PKI_Refuses_An_ECDSA_Algorithm_Of_Another_Curve(String Said, String KeyOf)
    {

        using var key   = RawKey.Generate(KeyOf);
        var       hash  = Said switch { "ES384" => HashAlgorithmName.SHA384, "ES512" => HashAlgorithmName.SHA512, _ => HashAlgorithmName.SHA256 };
        var       jws   = RawJWS.Sign(data => ((ECDsa) key.Key).SignData(data, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
                                      RawJson.Object(("alg",   RawJson.Quote(Said)),
                                                     ("jwk",   key.JWK.ToJSON()),
                                                     ("nonce", RawJson.Quote(Nonce)),
                                                     ("url",   RawJson.Quote(URL))),
                                      "{}");
        var       pki   = PKIJWS.Parse(jws.ToFlattenedJSON());

        Boolean holds;

        try
        {
            holds = pki.SignedBy(pki.JWK!);
        }
        catch (PKIProblem problem)
        {
            Assert.That(problem.Type, Is.EqualTo("badSignatureAlgorithm").Or.EqualTo("badPublicKey"), problem.Message);
            return;
        }

        Assert.That(holds, Is.False, $"{Said} over a key of {KeyOf} holds");

    }

    #endregion

}
