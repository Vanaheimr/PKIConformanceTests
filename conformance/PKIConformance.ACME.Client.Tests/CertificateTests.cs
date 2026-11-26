using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// RFC 8555, sections 7.4.2 and 9.1: the certificate as the client downloads
/// it - <i>"The default format of the certificate is
/// application/pem-certificate-chain"</i> - chains of every length, PEM as
/// servers write it, and section 11.4: <i>"If anything other than a
/// certificate is found (i.e., if the string "-----BEGIN" is ever followed by
/// anything other than "CERTIFICATE"), then the client MUST reject the file
/// as invalid."</i> - and its revocation, section 7.6.
/// </summary>
[TestFixture]
[Property("RFC", "8555 §7.4.2, §9.1")]
public class CertificateTests : ClientFixture
{

    /// <summary>
    /// Section 7.4.2: <i>"The default format of the certificate is
    /// application/pem-certificate-chain (see Section 9)."</i> - asked for,
    /// and what comes is the certificate the server issued, with its chain.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4.2")]
    [Property("Level", "SHOULD")]
    public async Task The_Certificate_Is_Downloaded_As_The_Chain_The_Server_Issued()
    {

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);
        var issued      = Server.Certificates.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Server.RequestsOf("certificate").Single().Header("Accept"), Is.EqualTo("application/pem-certificate-chain"), Log);
            Assert.That(certificate.Certificate.RawData,                            Is.EqualTo(issued.DER));
            Assert.That(certificate.FullChainPem,                                   Is.EqualTo(issued.ChainPEM));
        }

    }

    /// <summary>
    /// Chains of one to four certificates - the leaf alone, issued by the
    /// root; one, two, three intermediates - as Pebble varies them on
    /// purpose: the leaf is the leaf, the rest its intermediates, in order.
    /// </summary>
    [TestCase(0)]
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    [Property("RFC", "8555 §9.1")]
    [Property("Level", "MUST")]
    public async Task A_Chain_Of_Any_Length_Is_Taken(Int32 Intermediates)
    {

        UseServer(ScriptedACMEServer.Start(Intermediates));

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(certificate.Certificate.RawData,                                                 Is.EqualTo(Server.Certificates.Single().DER));
            Assert.That(certificate.Chain.Intermediates.OfType<X509Certificate2>().Select(c => c.Thumbprint), Is.EqualTo(Server.CA.Intermediates.Select(c => c.Thumbprint)));
        }

    }

    /// <summary>
    /// PEM as it comes from servers: CRLF line endings, empty lines and
    /// trailing blanks between the blocks (RFC 7468, section 3: <i>"parsers
    /// ... MUST ignore whitespace"</i> at line ends), the root sent along, the
    /// chain root first.
    /// </summary>
    [TestCase("CRLF")]
    [TestCase("empty lines")]
    [TestCase("trailing blanks")]
    [TestCase("root sent along")]
    [TestCase("root first")]
    [Property("RFC", "8555 §9.1; 7468 §2, §3")]
    [Property("Level", "SHOULD")]
    public async Task PEM_As_Servers_Write_It_Is_Taken(String How)
    {

        Server.RewriteChain = (issued, pem) => How switch {
                                                   "CRLF"             => pem.Replace("\n", "\r\n"),
                                                   "empty lines"      => pem.Replace("-----END CERTIFICATE-----\n", "-----END CERTIFICATE-----\n\n\n"),
                                                   "trailing blanks"  => pem.Replace("-----END CERTIFICATE-----\n", "-----END CERTIFICATE-----  \t\n"),
                                                   "root sent along"  => pem + Server.CA.Root.ExportCertificatePem() + "\n",
                                                   _                  => BenchCA.Pem([ Server.CA.Root, .. Server.CA.Intermediates.Reverse(), issued.Leaf ])
                                               };

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        Assert.That(certificate.Certificate.RawData, Is.EqualTo(Server.Certificates.Single().DER));

    }

    /// <summary>
    /// Section 11.4: <i>"A malicious ACME server could cause a client to use a
    /// private key of its choosing by including the key in the PEM file
    /// returned in response to a query for a certificate URL. When processing
    /// a file of type "application/pem-certificate-chain", a client SHOULD
    /// verify that the file contains only encoded certificates. If anything
    /// other than a certificate is found (i.e., if the string "-----BEGIN" is
    /// ever followed by anything other than "CERTIFICATE"), then the client
    /// MUST reject the file as invalid."</i>
    /// </summary>
    [TestCase("PRIVATE KEY")]
    [TestCase("EC PRIVATE KEY")]
    [TestCase("RSA PRIVATE KEY")]
    [TestCase("PUBLIC KEY")]
    [TestCase("X509 CRL")]
    [Property("RFC", "8555 §11.4")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-1")]
    public async Task A_Chain_With_Anything_But_Certificates_Is_Rejected(String Label)
    {

        using var malicious = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var block = Label switch {
                        "PRIVATE KEY"      => malicious.ExportPkcs8PrivateKeyPem(),
                        "EC PRIVATE KEY"   => malicious.ExportECPrivateKeyPem(),
                        "RSA PRIVATE KEY"  => RSA.Create(2048).ExportRSAPrivateKeyPem(),
                        "PUBLIC KEY"       => malicious.ExportSubjectPublicKeyInfoPem(),
                        _                  => $"-----BEGIN X509 CRL-----\n{Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))}\n-----END X509 CRL-----"
                    };

        Server.RewriteChain = (_, pem) => pem + block + "\n";

        var client = await ClientWithAccountAsync();

        try
        {
            var certificate = await ObtainAsync(client);
            Assert.Fail($"The chain with a block of \"{Label}\" was taken: {certificate.FullChainPem.Length} characters of PEM, the {Label} in them" +
                        (certificate.FullChainPem.Contains($"BEGIN {Label}") ? " - and in fullchain.pem, should it be written." : "."));
        }
        catch (Exception e) when (e is ACMEException or CryptographicException)
        {
            Assert.Pass($"Rejected: {e.Message}");
        }

    }


    #region Revocation (section 7.6)

    /// <summary>
    /// Section 7.6: <i>"certificate (required, string): The certificate to be
    /// revoked, in the base64url-encoded version of the DER format. ...
    /// reason (optional, int): One of the revocation reasonCodes defined in
    /// Section 5.3.1 of [RFC5280]"</i> - signed by the account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    public async Task A_Revocation_Is_The_DER_And_The_Reason_Signed_By_The_Account()
    {

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        await client.RevokeCertificateAsync(certificate.Certificate, Reason: 4);

        var request = Server.RequestsOf("revokeCert").Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(RawBase64Url.TryDecode(request.PayloadObject!["certificate"]!.GetValue<String>(), out var der, out var whyNot), Is.True, whyNot);
            Assert.That(der,                                                     Is.EqualTo(certificate.Certificate.RawData));
            Assert.That(request.PayloadObject["reason"]?.GetValue<Int32>(),      Is.EqualTo(4));
            Assert.That(request.Kid,                                             Is.EqualTo(Server.Accounts.Single().URL));
            Assert.That(Server.Certificates.Single().Revoked,                    Is.True);
        }

    }

    /// <summary>
    /// Without a reason, none is sent: <i>"reason (optional, int)"</i>.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MAY")]
    public async Task A_Revocation_Without_A_Reason_Sends_None()
    {

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        await client.RevokeCertificateAsync(certificate.Certificate);

        Assert.That(Server.RequestsOf("revokeCert").Single().PayloadObject!.ContainsKey("reason"), Is.False, Log);

    }

    /// <summary>
    /// A directory without "revokeCert" - which RFC 8555 lists as required -
    /// is a clear error, not a request to nowhere.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.1")]
    [Property("Level", "SHOULD")]
    public async Task A_Directory_Without_revokeCert_Is_A_Clear_Error()
    {

        Server.RewriteDirectory = directory => directory.Remove("revokeCert");

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        var refused     = await Assert.ThrowsAsync<ACMEException>(() => client.RevokeCertificateAsync(certificate.Certificate));

        Assert.That(refused!.Message, Does.Contain("revoke"), refused.Message);

    }

    #endregion

    #region ToDos

    /// <summary>
    /// ToDo T-C5: section 7.6, <i>"the request ... signed using the private key
    /// corresponding to the public key in the certificate ... the JWS uses the
    /// "jwk" header"</i> - revoking without the account, by the certificate's
    /// own key.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MAY")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C5")]
    public async Task A_Certificate_Is_Revoked_By_Its_Own_Key()
    {

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        var revoke      = typeof(ACMEClient).GetMethods().
                                             FirstOrDefault(method => method.Name.StartsWith("Revoke", StringComparison.Ordinal) &&
                                                                      method.GetParameters().Any(parameter => parameter.ParameterType == typeof(ACMECertificate) ||
                                                                                                              parameter.ParameterType == typeof(AsymmetricAlgorithm) ||
                                                                                                              parameter.Name?.Contains("Key", StringComparison.OrdinalIgnoreCase) == true));

        if (revoke is null)
            Assert.Fail("T-C5: the client cannot revoke a certificate by its own key (RFC 8555, section 7.6) yet.");

        await Trackers.InvokeAsync(revoke!, NewClient(), certificate, certificate.Certificate);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Server.RequestsOf("revokeCert").Last().JWK, Is.Not.Null, Log);
            Assert.That(Server.Certificates.Single().Revoked,       Is.True);
        }

    }

    /// <summary>
    /// ToDo T-C6: section 7.4.2, <i>"The server MAY provide one or more link
    /// relation header fields [RFC8288] with relation "alternate". Each such
    /// field SHOULD express an alternative certificate chain"</i> - which the
    /// client lets its user choose among, by the issuer at its top.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4.2")]
    [Property("Level", "MAY")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C6")]
    public async Task An_Alternate_Chain_Can_Be_Chosen()
    {

        Server.AlternateChains = 1;

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        var choice      = typeof(ACMEClient).GetMethod(nameof(ACMEClient.ObtainCertificateAsync))!.
                                             GetParameters().
                                             FirstOrDefault(parameter => parameter.Name is "PreferredChain" or "PreferredIssuer" or "Chain");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(choice,                          Is.Not.Null,      "T-C6: no preferred chain can be asked for yet.");
            Assert.That(Server.RequestsOf("alternate"),  Is.Not.Empty,     "T-C6: the alternate chain is never fetched.");
            Assert.That(Trackers.Property(typeof(ACMECertificate), "AlternateChains", "Alternates"), Is.Not.Null, "T-C6: the certificate does not tell of alternate chains.");
        }

    }

    #endregion

}
