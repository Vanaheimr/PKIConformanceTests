using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// RFC 8555, section 7.4: the CSR of a finalization - <i>"csr (required,
/// string): A CSR encoding the parameters for the certificate being requested
/// [RFC2986]. The CSR is sent in the base64url-encoded version of the DER
/// format."</i> - read with .NET by the server, never by Hermod: its names,
/// its common name, its key, and section 11.1, <i>"ACME clients and servers
/// MUST verify that a CSR submitted in a finalize request does not contain a
/// public key for any known account key"</i>.
/// </summary>
[TestFixture]
[Property("RFC", "8555 §7.4; 2986")]
public class CSRTests : ClientFixture
{

    private async Task<(ScriptedCSR CSR, ACMECertificate Certificate)> CSROfAsync(ACMEKeyType KeyType, params String[] Names)
    {

        var client      = await ClientWithAccountAsync();
        ValidateByTheResponder();

        var certificate = await client.ObtainCertificateAsync(Names.Length > 0 ? Names : [ Name ], Responders, KeyType);

        return (Server.Orders.Last().CSR!, certificate);

    }


    /// <summary>
    /// Section 7.4: <i>"The CSR MUST indicate the exact same set of requested
    /// identifiers as the initial newOrder request."</i> - names and
    /// addresses, as subject alternative names.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_CSR_Is_For_Exactly_The_Identifiers_Of_The_Order()
    {

        var (csr, _) = await CSROfAsync(ACMEKeyType.ECDSA_P256, "www.acme.test", "acme.test", "*.acme.test", "127.0.0.1", "::1");

        Assert.That(csr.Names.Select(name => name.ToString()),
                    Is.EquivalentTo(Server.Orders.Last().Identifiers.Select(identifier => identifier.ToString())));

    }

    /// <summary>
    /// RFC 5280, Appendix A.1: <i>"ub-common-name INTEGER ::= 64"</i> - a
    /// common name, where there is one, is one of the names and not longer;
    /// a first name too long for it is passed over, and a certificate of
    /// addresses only has none.
    /// </summary>
    [TestCase("www.acme.test", "www.acme.test")]
    [TestCase("a-name-of-more-than-sixty-four-characters-is-too-long-for-a-cn.acme.test|short.acme.test", "short.acme.test")]
    [TestCase("127.0.0.1", null)]
    [Property("RFC", "5280 App. A.1")]
    [Property("Level", "MUST")]
    public async Task The_Common_Name_Is_One_Of_The_Names_That_Fits(String Names, String? CommonName)
    {

        var (csr, _) = await CSROfAsync(ACMEKeyType.ECDSA_P256, Names.Split('|'));

        Assert.That(csr.CommonName, Is.EqualTo(CommonName));

    }

    /// <summary>
    /// The key of the kind asked for, signed as that kind is: ECDSA P-256 with
    /// SHA-256, P-384 with SHA-384, RSA 2048 and 4096 with sha256WithRSA.
    /// </summary>
    [TestCase(ACMEKeyType.ECDSA_P256, "EC",  256,  "P-256", "1.2.840.10045.4.3.2")]
    [TestCase(ACMEKeyType.ECDSA_P384, "EC",  384,  "P-384", "1.2.840.10045.4.3.3")]
    [TestCase(ACMEKeyType.RSA_2048,   "RSA", 2048, null,    "1.2.840.113549.1.1.11")]
    [TestCase(ACMEKeyType.RSA_4096,   "RSA", 4096, null,    "1.2.840.113549.1.1.11")]
    [Property("RFC", "2986 §4.2; 5758 §3.2; 4055")]
    [Property("Level", "MUST")]
    public async Task The_Key_Is_Of_The_Kind_Asked_For(ACMEKeyType KeyType, String Algorithm, Int32 Size, String? Curve, String Signature)
    {

        var (csr, _) = await CSROfAsync(KeyType);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(csr.KeyAlgorithm,        Is.EqualTo(Algorithm));
            Assert.That(csr.KeySize,             Is.EqualTo(Size));
            Assert.That(csr.Curve,               Is.EqualTo(Curve));
            Assert.That(csr.SignatureAlgorithm,  Is.EqualTo(Signature));
        }

    }

    /// <summary>
    /// Section 11.1: <i>"ACME clients and servers MUST verify that a CSR
    /// submitted in a finalize request does not contain a public key for any
    /// known account key."</i> - and every certificate a key of its own.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §11.1")]
    [Property("Level", "MUST")]
    public async Task The_Key_Of_The_CSR_Is_No_Account_Key_And_New_Every_Time()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);
        await ObtainAsync(client, "other.acme.test");

        var keys   = Server.Orders.Select(order => order.CSR!.JWK.Thumbprint).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(keys,                                          Is.Unique);
            Assert.That(keys,                                          Has.None.EqualTo(Server.Accounts.Single().Key.Thumbprint));
        }

    }

    /// <summary>
    /// The private key handed out with the certificate is the one of the CSR
    /// - and so of the certificate.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Private_Key_Is_The_Key_Of_The_CSR()
    {

        var (csr, certificate) = await CSROfAsync(ACMEKeyType.ECDSA_P256);

        using var key = ECDsa.Create();
        key.ImportFromPem(certificate.PrivateKeyPem);

        Assert.That(RawJWK.Of(key).Thumbprint, Is.EqualTo(csr.JWK.Thumbprint));

    }

    /// <summary>
    /// Section 7.4: <i>"The CSR is sent in the base64url-encoded version of the
    /// DER format. (Note: Because this field uses base64url, and does not
    /// include headers, it is different from PEM.)"</i> - and section 5: no
    /// padding.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, §5")]
    [Property("Level", "MUST")]
    public async Task The_CSR_Is_base64url_Of_DER_Without_Padding()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);

        var csr    = Server.RequestsOf("finalize").Single().PayloadObject!["csr"]!.GetValue<String>();

        Assert.That(RawBase64Url.TryDecode(csr, out var der, out var whyNot), Is.True, whyNot);
        Assert.That(ScriptedACMEServer.ReadCSR(der).DER,                      Is.EqualTo(der), "DER, read by .NET");

    }

}
