using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// dehydrated - Debian 13's 0.7.2 - against the ACME server under test, its
/// row in the matrix of PLAN.md, section 4.5: certificates by http-01
/// through a webroot the bench serves (dehydrated has no web server of its
/// own), of names and addresses, of every kind of key, of sixteen names and
/// of its own CSR; an external account binding; a new contact and a
/// deactivated account; a forced renewal; revocation; and the refusals.
/// </summary>
/// <remarks>
/// Grey for dehydrated 0.7.2, and so without a test here: profiles, ARI, key
/// rollover, and dns-01 but by a hook of one's own.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.4, §8")]
public class DehydratedTests(String ServerName) : InteropFixture(ServerName)
{

    protected override String[] Tools    => [ "dehydrated", "curl", "openssl" ];

    protected override String   PeerName => Dehydrated.Name;

    private Dehydrated NewDehydrated(String KeyAlgorithm = "prime256v1", Int32 KeySize = 2048, String Email = "dehydrated@acme.test", String? More = null)
    {
        var dehydrated = Keep(new Dehydrated(Server.TLS.RootFile));
        dehydrated.Configure(DirectoryURL, WellKnownPath, KeyAlgorithm, KeySize, Email, More);
        return dehydrated;
    }

    private static String Domains(params String[] Names)
        => String.Join(" ", Names.Select(name => $"-d '{name}'"));


    [OneTimeSetUp]
    public void RequireNames()
        => TestEnvironment.RequireBenchNames();


    #region http-01

    /// <summary>
    /// A certificate by http-01 through the webroot.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.Http01Webroot)]
    public async Task Dehydrated_Gets_A_Certificate_By_http01()
    {

        await StartAsync(Webroot: true);

        var dehydrated = NewDehydrated();
        var register   = dehydrated.Run("--register --accept-terms");
        var result     = dehydrated.Run($"-c {Domains(BenchNames.WWW)}");

        AssertIssued(dehydrated.Certificate(BenchNames.WWW, "fullchain.pem"), [ BenchNames.WWW ], "EC", 256, $"{register}\n{result}");

    }

    /// <summary>
    /// dehydrated 0.7.2 has no identifiers of RFC 8738: it orders an address
    /// as a DNS name, which an address is not - and the server says so, as
    /// malformed or rejectedIdentifier, instead of signing a dNSName of
    /// "127.0.0.1".
    /// </summary>
    [Test]
    [Property("RFC", "8738 §3; 8555 §9.7.7")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RefusedAddressAsName)]
    public async Task An_Address_Ordered_As_A_DNS_Name_Is_Refused()
    {

        await StartAsync(Webroot: true);

        var dehydrated = NewDehydrated();
        dehydrated.Run("--register --accept-terms");
        var result     = dehydrated.Run($"-c {Domains("127.0.0.1")}");

        AssertRefused(result, "", "malformed", "rejectedIdentifier");

    }

    /// <summary>
    /// A certificate of every kind of key dehydrated makes.
    /// </summary>
    [TestCase("prime256v1", 2048, "EC",  256)]
    [TestCase("secp384r1",  2048, "EC",  384)]
    [TestCase("rsa",        2048, "RSA", 2048)]
    [TestCase("rsa",        4096, "RSA", 4096)]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.CertificateKeys)]
    public async Task Dehydrated_Gets_A_Certificate_Of_The_Key_Asked_For(String KeyAlgorithm, Int32 KeySize, String Algorithm, Int32 Size)
    {

        await StartAsync(Webroot: true);

        var dehydrated = NewDehydrated(KeyAlgorithm, KeySize);
        var register   = dehydrated.Run("--register --accept-terms");
        var result     = dehydrated.Run($"-c {Domains(BenchNames.WWW)}", TimeSpan.FromMinutes(4));

        AssertIssued(dehydrated.Certificate(BenchNames.WWW, "fullchain.pem"), [ BenchNames.WWW ], Algorithm, Size, $"{register}\n{result}");

    }

    /// <summary>
    /// A certificate of sixteen names.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.SixteenNames)]
    public async Task Dehydrated_Gets_A_Certificate_Of_Sixteen_Names()
    {

        TestEnvironment.RequireBenchNames();
        await StartAsync(Webroot: true);

        var dehydrated = NewDehydrated();
        var register   = dehydrated.Run("--register --accept-terms");
        var result     = dehydrated.Run($"-c {Domains([ .. BenchNames.Numbered ])}", TimeSpan.FromMinutes(4));

        AssertIssued(dehydrated.Certificate(BenchNames.Numbered[0], "fullchain.pem"), BenchNames.Numbered, "EC", 256, $"{register}\n{result}");

    }

    /// <summary>
    /// Section 7.4: a CSR of the client's own, openssl's - dehydrated signs it
    /// and puts out the chain.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.OwnCSR)]
    public async Task Dehydrated_Gets_A_Certificate_For_Its_Own_CSR()
    {

        await StartAsync(Webroot: true);

        var dehydrated  = NewDehydrated();
        var register    = dehydrated.Run("--register --accept-terms");
        var (csr, _, _) = CSR(dehydrated, BenchNames.WWW);
        var result      = dehydrated.Run($"--signcsr '{csr}' --full-chain");

        AssertIssued(result.StdOut[Math.Max(0, result.StdOut.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))..], [ BenchNames.WWW ], "EC", 256, $"{register}\n{result}");

    }

    #endregion

    #region Accounts

    /// <summary>
    /// Section 7.3.4: an account bound to an external account of the CA -
    /// EAB_KID and EAB_HMAC_KEY of dehydrated's configuration.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountEAB)]
    public async Task Dehydrated_Opens_An_Account_By_An_External_Account_Binding()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true), Webroot: true);

        var (keyId, mac) = await ExternalAccountAsync();
        var dehydrated   = NewDehydrated(Email: "eab@acme.test", More: $"EAB_KID=\"{keyId}\"\nEAB_HMAC_KEY=\"{mac}\"");
        var result       = dehydrated.Run("--register --accept-terms");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Success,                              Is.True,          result.ToString());
            Assert.That(AccountOf("eab@acme.test")?.ExternalAccount, Is.EqualTo(keyId), "bound to the external account");
        }

    }

    /// <summary>
    /// Section 7.3.2: a new contact for the account - dehydrated's --account,
    /// with the CONTACT_EMAIL of its configuration changed.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountContact)]
    public async Task Dehydrated_Updates_The_Contact_Of_Its_Account()
    {

        await StartAsync(Webroot: true);

        var dehydrated = NewDehydrated();
        var register   = dehydrated.Run("--register --accept-terms");
        dehydrated.Configure(DirectoryURL, WellKnownPath, Email: "new-dehydrated@acme.test");
        var update     = dehydrated.Run("--account");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(register.Success,                      Is.True,     register.ToString());
            Assert.That(update.Success,                        Is.True,     update.ToString());
            Assert.That(AccountOf("new-dehydrated@acme.test"), Is.Not.Null, $"the new contact: {String.Join(", ", Server.Accounts().SelectMany(account => account.Contacts))}");
        }

    }

    /// <summary>
    /// Section 7.3.6: dehydrated deactivates its account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountDeactivated)]
    public async Task Dehydrated_Deactivates_Its_Account()
    {

        await StartAsync(Webroot: true);

        var dehydrated = NewDehydrated();
        var register   = dehydrated.Run("--register --accept-terms");
        var deactivate = dehydrated.Run("--deactivate");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(register.Success,                          Is.True,                   register.ToString());
            Assert.That(deactivate.Success,                        Is.True,                   deactivate.ToString());
            Assert.That(AccountOf("dehydrated@acme.test")?.Status, Is.EqualTo("deactivated"), "the account's status");
        }

    }

    #endregion

    #region Renewal, revocation

    /// <summary>
    /// A forced renewal: a new certificate of the same name.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RenewalForced)]
    public async Task Dehydrated_Renews_When_Forced()
    {

        await StartAsync(Webroot: true);

        var dehydrated = NewDehydrated();
        var register   = dehydrated.Run("--register --accept-terms");
        var first      = dehydrated.Run($"-c {Domains(BenchNames.WWW)}");
        var before     = AssertIssued(dehydrated.Certificate(BenchNames.WWW, "fullchain.pem"), [ BenchNames.WWW ], "EC", 256, $"{register}\n{first}");
        var renewal    = dehydrated.Run($"-c {Domains(BenchNames.WWW)} --force");
        var after      = AssertIssued(dehydrated.Certificate(BenchNames.WWW, "fullchain.pem"), [ BenchNames.WWW ], "EC", 256, renewal);

        Assert.That(after.Thumbprint, Is.Not.EqualTo(before.Thumbprint), $"a new certificate: {renewal}");

    }

    /// <summary>
    /// Section 7.6: dehydrated revokes its certificate, and the CRL says so.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RevokedByAccount)]
    public async Task Dehydrated_Revokes_Its_Certificate()
    {

        await StartAsync(Webroot: true);

        var dehydrated = NewDehydrated();
        var register   = dehydrated.Run("--register --accept-terms");
        var issued     = dehydrated.Run($"-c {Domains(BenchNames.WWW)}");
        var chain      = dehydrated.Certificate(BenchNames.WWW, "fullchain.pem");
        var leaf       = AssertIssued(chain, [ BenchNames.WWW ], "EC", 256, $"{register}\n{issued}");
        var result     = dehydrated.Run($"--revoke '{dehydrated.WslPathOf($"certs/{BenchNames.WWW}/cert.pem")}'");

        Assert.That(result.Success, Is.True, result.ToString());

        AssertRevoked(leaf, chain!, null, result);

    }

    #endregion

    #region Refusals

    /// <summary>
    /// A name the server does not sign for: rejectedIdentifier.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, §6.7")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RefusedName)]
    public async Task Dehydrated_Is_Told_Of_A_Name_Not_Signed_For()
    {

        await StartAsync(new ACMEServerOptions(AllowedNames: [ "acme.test", "127.0.0.0/8" ]), Webroot: true);

        var dehydrated = NewDehydrated();
        dehydrated.Run("--register --accept-terms");
        var result     = dehydrated.Run($"-c {Domains("refused.example")}");

        AssertRefused(result, "", "rejectedIdentifier");

    }

    /// <summary>
    /// A wrong answer at the token's path: the challenge is invalid, and
    /// dehydrated is told why.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, §7.5.1")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RefusedWrongAnswer)]
    public async Task Dehydrated_Is_Told_Of_A_Wrong_Answer()
    {

        await StartAsync(Webroot: true);
        Webroot!.Fallback = _ => PKIConformance.Core.Scripted.HostAnswer.Text("not the key authorization");

        var dehydrated = NewDehydrated();
        dehydrated.Run("--register --accept-terms");
        var result     = dehydrated.Run($"-c {Domains(BenchNames.WWW)}");

        AssertRefused(result, "", "incorrectResponse", "unauthorized", "invalid");

    }

    #endregion

}
