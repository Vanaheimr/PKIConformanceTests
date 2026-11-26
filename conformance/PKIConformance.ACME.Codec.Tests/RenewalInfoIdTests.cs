using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using PKIConformance.Core.RawACME;

using HermodClient = org.GraphDefined.Vanaheimr.Hermod.ACME.ACMEClient;

namespace PKIConformance.ACME.Codec.Tests;

/// <summary>
/// RFC 9773, section 4.1: the unique identifier of a certificate in ACME
/// Renewal Information - <i>"the base64url encoding of the keyIdentifier field
/// of the certificate's Authority Key Identifier (AKI) extension, the period
/// character ".", and the base64url encoding of the DER-encoded Serial Number
/// field (without the tag and length bytes)"</i>.
/// </summary>
/// <remarks>
/// <para>
/// The serial number is the trap: as DER content octets it keeps the zero
/// octet in front of a serial whose first bit is set (0x87654321 is
/// 00 87 65 43 21), which an integer of a programming language drops. A client
/// that drops it asks about a certificate that does not exist, and is never
/// told when to renew.
/// </para>
/// <para>
/// The PKI's side - which certificate an identifier names - is a question of
/// its renewal-info resource, and so of the server tests.
/// </para>
/// </remarks>
[Property("RFC", "9773 §4.1")]
public class RenewalInfoIdTests
{

    [Test]
    public void RawACME_Computes_The_Identifier_Of_The_Example_Of_RFC_9773()
        => Assert.That(RawARI.CertificateId(RFCVectors.RFC9773_CertificateDER()), Is.EqualTo(RFCVectors.RFC9773_CertificateId));

    /// <summary>
    /// The example certificate of RFC 9773 itself - where the platform loads
    /// it: it is valid from 0001-01-01, and the certificate store of Windows
    /// knows no time before 1601 ("The requested object was not found").
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public void Hermod_Computes_The_Identifier_Of_The_Example_Of_RFC_9773()
    {

        X509Certificate2 certificate;

        try
        {
            certificate = X509CertificateLoader.LoadCertificate(RFCVectors.RFC9773_CertificateDER());
        }
        catch (CryptographicException e) when (OperatingSystem.IsWindows())
        {
            Assert.Ignore($"Windows does not load the example of RFC 9773, valid from 0001-01-01: {e.Message} - " +
                          "Hermod_Computes_The_Identifier_Of_RFC_9773_For_Its_Key_Identifier_And_Serial covers it here.");
            return;
        }

        using (certificate)
            Assert.That(HermodClient.CertificateIdentifier(certificate), Is.EqualTo(RFCVectors.RFC9773_CertificateId));

    }

    /// <summary>
    /// A certificate of the example's key identifier (69:88:5B:...:D4) and
    /// serial number (0x87654321, DER 00 87 65 43 21), made here - and so
    /// loaded on every platform: its identifier is the one RFC 9773 prints.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public void Hermod_Computes_The_Identifier_Of_RFC_9773_For_Its_Key_Identifier_And_Serial()
    {

        using var key         = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var issuerKey   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       request     = new CertificateRequest("CN=example.com", key, HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(
                                              Convert.FromHexString("69885B6B87464041E1B37B847BA0AE2CDE01C8D4")));

        using var certificate = request.Create(new X500DistinguishedName("CN=Example CA"),
                                               X509SignatureGenerator.CreateForECDsa(issuerKey),
                                               DateTimeOffset.UtcNow.AddDays(-1),
                                               DateTimeOffset.UtcNow.AddDays(1),
                                               Convert.FromHexString("87654321"));

        Assert.Multiple(() => {
            Assert.That(RawARI.CertificateId(certificate.RawData),       Is.EqualTo(RFCVectors.RFC9773_CertificateId), "the reference");
            Assert.That(HermodClient.CertificateIdentifier(certificate), Is.EqualTo(RFCVectors.RFC9773_CertificateId), "Hermod");
        });

    }

    /// <summary>
    /// Hermod and the reference agree on certificates of serial numbers that
    /// need a leading zero octet, that are a single octet, and that are as
    /// long as RFC 5280 allows.
    /// </summary>
    [TestCase("87654321")]
    [TestCase("01")]
    [TestCase("7F")]
    [TestCase("80")]
    [TestCase("FF00")]
    [TestCase("0102030405060708090A0B0C0D0E0F1011121314")]
    [TestCase("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")]
    [Property("Level", "MUST")]
    public void Hermod_Computes_The_Identifier_As_The_Reference_Does(String SerialHex)
    {

        using var certificate = Certificate(Convert.FromHexString(SerialHex), WithKeyIdentifier: true);
        var       expected    = RawARI.CertificateId(certificate.RawData);

        Assert.Multiple(() => {
            Assert.That(expected,                                        Is.Not.Null);
            Assert.That(HermodClient.CertificateIdentifier(certificate), Is.EqualTo(expected), $"serial {SerialHex}, as .NET reads it: {certificate.SerialNumber}");
        });

    }

    /// <summary>
    /// A certificate without an Authority Key Identifier has no identifier:
    /// <i>"This document assumes that the certificates being issued by the ACME
    /// server ... contain the Authority Key Identifier extension and the
    /// keyIdentifier field within that extension."</i>
    /// </summary>
    [Test]
    public void Hermod_Has_No_Identifier_For_A_Certificate_Without_AKI()
    {

        using var certificate = Certificate([ 0x42 ], WithKeyIdentifier: false);

        Assert.Multiple(() => {
            Assert.That(RawARI.CertificateId(certificate.RawData),       Is.Null);
            Assert.That(HermodClient.CertificateIdentifier(certificate), Is.Null);
        });

    }

    /// <summary>
    /// A certificate of the given serial number - with an AKI of a key
    /// identifier where asked - issued by a CA made for it.
    /// </summary>
    private static X509Certificate2 Certificate(Byte[]   Serial,
                                                Boolean  WithKeyIdentifier)
    {

        using var caKey   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       caReq   = new CertificateRequest("CN=ARI Test CA", caKey, HashAlgorithmName.SHA256);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(caReq.PublicKey, false));

        using var ca      = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));

        using var key     = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       request = new CertificateRequest("CN=ari.acme.test", key, HashAlgorithmName.SHA256);

        if (WithKeyIdentifier)
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        return request.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(5), Serial);

    }

}
