using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using PKIConformance.Core.RawACME;

using PKIJWS     = cloud.charging.open.PKI.Enrollment.ACMEJWS;
using PKIProblem = cloud.charging.open.PKI.Enrollment.ACMEProblem;

namespace PKIConformance.ACME.Codec.Tests;

/// <summary>
/// The JWS inside a JWS: RFC 8555, section 7.3.4, the external account
/// binding - a MAC over the account key with a key the CA gave out of band -
/// and section 7.3.5, the inner JWS of a key change.
/// </summary>
[Property("RFC", "8555 §7.3.4")]
public class AccountJWSTests
{

    private const String NewAccount = "https://acme.test/acme/new-account";
    private const String KeyChange  = "https://acme.test/acme/key-change";
    private const String Account    = "https://acme.test/acme/acct/evOfKhNU60wg";

    #region The reference

    /// <summary>
    /// The binding of the reference: "alg", "kid" and "url" - <i>"The "nonce"
    /// field MUST NOT be present"</i> - and the account key's JWK as payload.
    /// </summary>
    [Test]
    public void RawACME_Binds_As_Section_7_3_4_Has_It()
    {

        using var key = RawKey.Generate("ES256");
        var       eab = RawAccountJWS.ExternalAccountBinding("kid-1", RandomNumberGenerator.GetBytes(32), key.JWK, NewAccount);

        Assert.Multiple(() => {
            Assert.That(eab.Header("alg"),    Is.EqualTo("\"HS256\""));
            Assert.That(eab.Header("kid"),    Is.EqualTo("\"kid-1\""));
            Assert.That(eab.Header("url"),    Is.EqualTo($"\"{NewAccount}\""));
            Assert.That(eab.Header("nonce"),  Is.Null);
            Assert.That(eab.Header("jwk"),    Is.Null);
            Assert.That(eab.PayloadJSON,      Is.EqualTo(key.JWK.ToJSON()));
        });

    }

    /// <summary>
    /// The inner JWS of the reference: the new key's "jwk", the outer "url",
    /// no nonce, signed by the new key, with the account and the old key.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.5")]
    public void RawACME_Changes_Keys_As_Section_7_3_5_Has_It()
    {

        using var oldKey = RawKey.Generate("ES256");
        using var newKey = RawKey.Generate("ES384");
        var       inner  = RawAccountJWS.KeyChange(newKey, Account, oldKey.JWK, KeyChange);
        var       body   = JObject.Parse(inner.PayloadJSON);

        Assert.Multiple(() => {
            Assert.That(RawJWK.Parse(inner.Header("jwk")!).Thumbprint,      Is.EqualTo(newKey.JWK.Thumbprint));
            Assert.That(inner.Header("url"),                                Is.EqualTo($"\"{KeyChange}\""));
            Assert.That(inner.Header("nonce"),                              Is.Null);
            Assert.That(inner.VerifiedBy(newKey.JWK),                       Is.True);
            Assert.That(inner.VerifiedBy(oldKey.JWK, "ES256"),              Is.False);
            Assert.That(body.Value<String>("account"),                      Is.EqualTo(Account));
            Assert.That(RawJWK.Parse(body["oldKey"]!.ToString()).Thumbprint, Is.EqualTo(oldKey.JWK.Thumbprint));
        });

    }

    #endregion

    #region The PKI

    /// <summary>
    /// A binding of the reference holds in the PKI by its MAC key, for every
    /// MAC of RFC 7518 - and by no other key.
    /// </summary>
    [TestCase("HS256")]
    [TestCase("HS384")]
    [TestCase("HS512")]
    [Property("Level", "MUST")]
    public void PKI_Checks_The_MAC_Of_A_Binding(String Algorithm)
    {

        using var key     = RawKey.Generate("ES256");
        var       macKey  = RandomNumberGenerator.GetBytes(32);
        var       eab     = RawAccountJWS.ExternalAccountBinding("kid-1", macKey, key.JWK, NewAccount, Algorithm);
        var       pki     = PKIJWS.Parse(eab.ToFlattenedJSON(), MACAllowed: true);

        Assert.Multiple(() => {
            Assert.That(pki.Algorithm,                                  Is.EqualTo(Algorithm));
            Assert.That(pki.KeyId,                                      Is.EqualTo("kid-1"));
            Assert.That(pki.URL,                                        Is.EqualTo(NewAccount));
            Assert.That(pki.MACHolds(macKey),                           Is.True);
            Assert.That(pki.MACHolds(RandomNumberGenerator.GetBytes(32)), Is.False);
        });

    }

    /// <summary>
    /// <i>"The "alg" field MUST indicate a MAC-based algorithm"</i>: a binding
    /// signed with a key of its own is no binding.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public void PKI_Refuses_A_Binding_That_Is_Not_A_MAC()
    {

        using var key  = RawKey.Generate("ES256");
        var       eab  = RawJWS.Sign(key,
                                     RawJson.Object(("alg", RawJson.Quote("ES256")), ("kid", RawJson.Quote("kid-1")), ("url", RawJson.Quote(NewAccount))),
                                     key.JWK.ToJSON());

        Assert.That(() => PKIJWS.Parse(eab.ToFlattenedJSON(), MACAllowed: true), Throws.InstanceOf<PKIProblem>());

    }

    #endregion

}
