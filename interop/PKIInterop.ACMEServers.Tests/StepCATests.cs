using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Peers;

namespace PKIInterop.ACMEServers.Tests;

/// <summary>
/// Hermod's ACME client and certificate manager against step-ca - a second
/// ACME server, of a stack that shares nothing with Let's Encrypt's.
/// </summary>
/// <remarks>
/// <para>
/// Every test starts a step-ca of its own, issuing by a root and an
/// intermediate the bench made with .NET, its http-01 at the port of Hermod's
/// responder (<c>--insecure --acme-http-port</c>), its names and dns-01
/// through a challtestsrv of its own (<c>--resolver</c>). A revocation is
/// judged by step-ca's CRL, by openssl.
/// </para>
/// <para>
/// What step-ca 0.30 lacks has no test (principle 7): renewal information
/// (RFC 9773) and profiles; its directory has no "meta" at all. External
/// account binding it has, with keys made through its admin API, which needs
/// the step CLI - not built yet.
/// </para>
/// </remarks>
[Category(TestCategories.Wsl)]
[Property("RFC", "8555 §7, §8; 8738")]
public sealed class StepCATests : ServerFixture
{

    #region Bench

    /// <inheritdoc/>
    protected override String[] Tools
        => [ "step-ca", "pebble-challtestsrv", "openssl", "dig" ];

    private StepCA StartStepCA(StepCAOptions? Options = null)
        => Use(StepCA.Start(HTTP01Port, Options));

    #endregion


    #region Accounts (RFC 8555, section 7.3)

    [Test, Property("RFC", "8555 §7.3"), Property("Level", "MUST")]
    public async Task An_Account_Is_Opened_With_A_Contact()
    {

        StartStepCA();

        var client  = NewClient();
        var account = await client.CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(account.Created,   Is.True,             Evidence);
            Assert.That(account.Status,    Is.EqualTo("valid"), Evidence);
            Assert.That(client.AccountURL, Is.EqualTo(account.URL), Evidence);
        }

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.3.1"), Property("Level", "MUST")]
    public async Task The_Same_Key_Finds_The_Same_Account()
    {

        StartStepCA();

        using var key    = ACMEAccountKey.Generate();
        var       opened = await NewClient(key).CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);
        var       found  = await NewClient(key).FindAccountAsync();

        Assert.That(found?.URL, Is.EqualTo(opened.URL), $"onlyReturnExisting finds it: {Evidence}");

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.3.1"), Property("Level", "MUST")]
    public async Task A_Key_Without_An_Account_Finds_None()
    {

        StartStepCA();

        Assert.That(await NewClient().FindAccountAsync(), Is.Null, Evidence);

    }

    #endregion


    #region http-01 and dns-01 (RFC 8555, sections 8.3 and 8.4; RFC 8738)

    [Test, Property("RFC", "8555 §8.3"), Property("Level", "MUST")]
    public async Task A_Name_By_http01()
    {

        StartStepCA();

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), Name);

        await AssertIssuedAsync(certificate, [ Name ]);

        Assert.That(HTTP01.Open, Is.Zero, "the answers taken away again");

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.4"), Property("Level", "MUST")]
    public async Task Sixteen_Names_By_http01()
    {

        StartStepCA();

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), [ .. BenchNames.Numbered ]);

        await AssertIssuedAsync(certificate, BenchNames.Numbered);

    }

    [Test, Property("RFC", "8555 §8.4"), Property("Level", "MUST")]
    public async Task A_Name_By_dns01()
    {

        StartStepCA();

        var certificate = await (await ClientWithAccountAsync()).ObtainCertificateAsync([ Name ], [ DNS01 ]);

        await AssertIssuedAsync(certificate, [ Name ]);

        Assert.That(Server.DNS.Query($"_acme-challenge.{Name}", "TXT"), Is.Empty, $"the record taken away again: {Server.DNS.Log}");

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.1.3"), Property("Level", "MUST")]
    public async Task A_Wildcard_By_dns01_And_Its_Base_By_http01()
    {

        StartStepCA();

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), "*.acme.test", "acme.test");

        await AssertIssuedAsync(certificate, [ "*.acme.test", "acme.test" ]);

    }

    [Test, Property("RFC", "8738 §3"), Property("Level", "MUST")]
    public async Task An_IPv4_Address_By_http01()
    {

        StartStepCA();

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), "127.0.0.1");

        await AssertIssuedAsync(certificate, [ "127.0.0.1" ]);

    }

    [Test, Property("RFC", "8738 §3"), Property("Level", "MUST")]
    public async Task An_IPv6_Address_By_http01()
    {

        Assume.That(Port80v6, Is.Not.Null, "no Hermod HTTP server at [::1]");

        StartStepCA();

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), "::1");

        await AssertIssuedAsync(certificate, [ "::1" ]);

    }

    [TestCase(ACMEKeyType.ECDSA_P256, "EC",  256)]
    [TestCase(ACMEKeyType.ECDSA_P384, "EC",  384)]
    [TestCase(ACMEKeyType.RSA_2048,   "RSA", 2048)]
    [TestCase(ACMEKeyType.RSA_4096,   "RSA", 4096)]
    [Property("RFC", "8555 §7.4"), Property("Level", "MUST")]
    public async Task Every_Kind_Of_Certificate_Key(ACMEKeyType KeyType, String Algorithm, Int32 Size)
    {

        StartStepCA();

        var certificate = await (await ClientWithAccountAsync()).ObtainCertificateAsync([ Name ], Responders, KeyType);

        await AssertIssuedAsync(certificate, [ Name ], Algorithm, Size);

    }

    #endregion


    #region Revocation (RFC 8555, section 7.6)

    [Test, Property("RFC", "8555 §7.6"), Property("Level", "MUST")]
    public async Task A_Revocation_With_A_Reason_Is_In_The_CRL()
    {

        var stepCA      = StartStepCA();
        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client, Name);

        await client.RevokeCertificateAsync(certificate.Certificate, Reason: 4);

        // Not "openssl verify -crl_check": step-ca's CRL has an issuing distribution
        // point, its certificates no distribution point to match it - a "different
        // CRL scope" to openssl. The CRL is judged by its signature and its entries.
        var crl         = await stepCA.CRLAsync();
        var chain       = new X509Certificate2Collection();
        chain.ImportFromPem(certificate.FullChainPem);

        var signed      = OpenSSL.VerifyCRL(crl, chain[1].ExportCertificatePem() + "\n");
        var listed      = OpenSSL.CRLEntries(crl);
        var serial      = certificate.Certificate.SerialNumber.TrimStart('0');

        using (Assert.EnterMultipleScope())
        {
            Assert.That(signed.StdOut,                     Does.Contain("verify OK"),   $"{OpenSSL.Version}: the CRL signed by the intermediate of Hermod's chain: {signed}");
            Assert.That(listed,                            Does.ContainKey(serial),     $"the CRL lists it: {String.Join(", ", listed.Keys)}");
            Assert.That(listed.GetValueOrDefault(serial),  Is.EqualTo("Superseded"),    "for the reason given");
        }

        AssertWire();

    }

    #endregion


    #region The certificate manager

    [Test, Property("Level", "—")]
    public async Task The_Manager_Keeps_A_Certificate_In_Files()
    {

        StartStepCA();

        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-manager-{Guid.NewGuid():N}")).FullName;

        try
        {

            await using var manager = new ACMECertificateManager(await ClientWithAccountAsync(), [ Name ], Responders, Directory: directory);

            Assert.That(await manager.StartAsync(), Is.True, $"{manager.LastError}: {Evidence}");

            var kept = ACMECertificate.FromPem(File.ReadAllText(manager.FullChainPath!), File.ReadAllText(manager.PrivateKeyPath!));

            await AssertIssuedAsync(kept, [ Name ]);

        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }

    }

    /// <summary>
    /// Where the server says nothing of a window, the manager renews when a
    /// third of the certificate's lifetime is left.
    /// </summary>
    [Test, Property("Level", "—")]
    public async Task Without_A_Window_The_Manager_Renews_By_The_Lifetime()
    {

        StartStepCA();

        await using var manager = new ACMECertificateManager(await ClientWithAccountAsync(), [ Name ], Responders);

        Assert.That(await manager.StartAsync(), Is.True, $"{manager.LastError}: {Evidence}");

        var certificate = manager.Certificate!;
        var due         = await manager.WhenDueAsync();

        Assert.That(due, Is.EqualTo(certificate.NotAfter - (certificate.NotAfter - certificate.NotBefore) / 3).Within(TimeSpan.FromSeconds(1)),
                    $"step-ca has no renewalInfo; the certificate is for {certificate.NotBefore:u} to {certificate.NotAfter:u}");

    }

    #endregion

}
