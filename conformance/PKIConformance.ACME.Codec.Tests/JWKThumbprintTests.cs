using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using PKIConformance.Core.RawACME;

using HermodAccountKey = org.GraphDefined.Vanaheimr.Hermod.ACME.ACMEAccountKey;
using PKIJWS           = cloud.charging.open.PKI.Enrollment.ACMEJWS;

namespace PKIConformance.ACME.Codec.Tests;

/// <summary>
/// RFC 7638: the thumbprint of a JWK - and RFC 7518, section 6: the JWK it is
/// taken of.
/// </summary>
/// <remarks>
/// <para>
/// The thumbprint is the second half of every key authorization (RFC 8555,
/// section 8.1). A client and a server that compute it differently disagree
/// about every challenge, and the client never proves a name - however
/// right everything else is.
/// </para>
/// <para>
/// <i>"The length of this octet string MUST be the full size of a coordinate
/// for the curve specified in the "crv" parameter"</i> (RFC 7518, sections
/// 6.2.1.2 and 6.2.1.3). A coordinate whose first octet is zero - one key in
/// 128 on P-256, one in two on P-521 - is where an encoder that strips leading
/// zeros parts from the others, and so where it is looked for.
/// </para>
/// </remarks>
[Property("RFC", "7638 §3")]
public class JWKThumbprintTests
{

    #region The reference against the RFC

    [Test]
    [Property("RFC", "7638 §3.1")]
    public void RawACME_Computes_The_Thumbprint_Of_RFC_7638_Section_3_1()
    {

        var jwk = RawJWK.Parse(RFCVectors.RFC7638_JWK);

        Assert.Multiple(() => {
            Assert.That(jwk.Canonical,  Is.EqualTo($$"""{"e":"AQAB","kty":"RSA","n":"{{RFCVectors.RFC7638_N}}"}"""));
            Assert.That(jwk.Thumbprint, Is.EqualTo(RFCVectors.RFC7638_Thumbprint));
        });

    }

    [TestCase("ES256", 32)]
    [TestCase("ES384", 48)]
    [TestCase("ES512", 66)]
    [Property("RFC", "7518 §6.2.1.2")]
    public void RawACME_Writes_Coordinates_Of_The_Full_Size_Of_The_Curve(String Algorithm, Int32 Size)
    {

        // P-521 has a leading zero octet in one coordinate of two, P-256 in one of 256.
        var found = 0;

        for (var i = 0; i < 4000 && found < 3; i++)
        {

            using var key = RawKey.Generate(Algorithm);
            var x         = ((ECDsa) key.Key).ExportParameters(false).Q.X!;

            Assert.That(RawBase64Url.Decode(key.JWK.X!), Has.Length.EqualTo(Size));

            if (x[0] == 0)
                found++;

        }

        Assert.That(found, Is.GreaterThan(0), "no key with a leading zero octet in x came up - nothing was shown");

    }

    #endregion

    #region Hermod

    /// <summary>
    /// Hermod's account key: a JWK of exactly the members of RFC 7518 for EC,
    /// and the thumbprint of RFC 7638 - as the reference computes it.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public void Hermod_Account_Key_Has_The_Thumbprint_Of_RFC_7638()
    {

        Assert.Multiple(() => {

            for (var i = 0; i < 50; i++)
            {

                using var key = HermodAccountKey.Generate();
                var       jwk = RawJWK.Parse(key.JWK.ToString());

                Assert.That(key.JWK.Properties().Select(member => member.Name).Order(), Is.EqualTo(new[] { "crv", "kty", "x", "y" }), key.JWK.ToString());
                Assert.That(key.Thumbprint, Is.EqualTo(jwk.Thumbprint), key.JWK.ToString());

            }

        });

    }

    /// <summary>
    /// Hermod's account key on a coordinate with a leading zero octet: the JWK
    /// keeps all 32 octets, and the thumbprint is of those.
    /// </summary>
    [Test]
    [Property("RFC",   "7518 §6.2.1.2")]
    [Property("Level", "MUST")]
    public void Hermod_Account_Key_Keeps_Coordinates_With_Leading_Zero_Octets_At_Full_Size()
    {

        var found = 0;

        for (var i = 0; i < 6000 && found < 2; i++)
        {

            using var key   = HermodAccountKey.Generate();
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(key.ToPem());

            var q = ecdsa.ExportParameters(false).Q;

            if (q.X![0] != 0 && q.Y![0] != 0)
                continue;

            found++;

            var expected = RawJWK.Of(ecdsa);

            Assert.Multiple(() => {
                Assert.That(key.JWK.Value<String>("x"), Is.EqualTo(expected.X),          $"x of {key.JWK}");
                Assert.That(key.JWK.Value<String>("y"), Is.EqualTo(expected.Y),          $"y of {key.JWK}");
                Assert.That(key.Thumbprint,              Is.EqualTo(expected.Thumbprint), $"the thumbprint of {key.JWK}");
            });

        }

        Assert.That(found, Is.GreaterThan(0), "no key with a leading zero octet came up - nothing was shown");

    }

    #endregion

    #region The PKI

    /// <summary>
    /// The PKI's thumbprint of the example of RFC 7638 - as printed there,
    /// with "alg" and "kid", which do not count.
    /// </summary>
    [Test]
    [Property("RFC",   "7638 §3.1")]
    [Property("Level", "MUST")]
    public void PKI_Computes_The_Thumbprint_Of_RFC_7638_Section_3_1()
        => Assert.That(PKIJWS.Thumbprint(JObject.Parse(RFCVectors.RFC7638_JWK)), Is.EqualTo(RFCVectors.RFC7638_Thumbprint));

    /// <summary>
    /// The PKI's thumbprint of keys of every kind it takes, as the reference
    /// computes it - from the JWK as a client sends it, members in any order.
    /// </summary>
    [TestCase("ES256")]
    [TestCase("ES384")]
    [TestCase("ES512")]
    [TestCase("RS256")]
    [Property("Level", "MUST")]
    public void PKI_Computes_The_Thumbprint_As_RFC_7638_Has_It(String Algorithm)
    {

        Assert.Multiple(() => {

            for (var i = 0; i < 10; i++)
            {

                using var key = RawKey.Generate(Algorithm);

                // The members reversed, and one that does not count in between.
                var sent      = new JObject(JObject.Parse(key.JWK.ToJSON()).Properties().Reverse());
                sent.AddFirst(new JProperty("use", "sig"));

                Assert.That(PKIJWS.Thumbprint(sent), Is.EqualTo(key.JWK.Thumbprint), sent.ToString());

            }

        });

    }

    /// <summary>
    /// The PKI's JWK of a certificate's key - what it holds the key of a CSR
    /// against the account's with (RFC 8555, section 11.1) - is the JWK of
    /// RFC 7518: coordinates at full size, on P-521 too, where every other
    /// key has a leading zero octet.
    /// </summary>
    [TestCase("ES256")]
    [TestCase("ES384")]
    [TestCase("ES512")]
    [TestCase("RS256")]
    [Property("RFC",   "7518 §6.2.1.2")]
    [Property("Level", "MUST")]
    public void PKI_Writes_The_JWK_Of_A_Public_Key_As_RFC_7518_Has_It(String Algorithm)
    {

        Assert.Multiple(() => {

            for (var i = 0; i < 20; i++)
            {

                using var key   = RawKey.Generate(Algorithm);
                var publicKey   = key.Key switch {
                                      ECDsa ec => new PublicKey(ec),
                                      RSA  rsa => new PublicKey(rsa),
                                      _        => throw new InvalidOperationException()
                                  };

                var jwk         = PKIJWS.JWKOf(publicKey);

                Assert.That(jwk, Is.Not.Null, $"the PKI makes no JWK of a key of {Algorithm}");
                Assert.That(RawJWK.Parse(jwk!.ToString()).Canonical, Is.EqualTo(key.JWK.Canonical));

            }

        });

    }

    #endregion

}
