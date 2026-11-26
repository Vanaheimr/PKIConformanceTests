using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// acme.sh - Debian 13's 3.1.1 - against the ACME server under test, the row
/// of acme.sh in the matrix of PLAN.md, section 4.5: certificates by http-01
/// from its own web server (socat) and by a webroot, of names and addresses,
/// of every kind of key, of sixteen names and of its own CSR; account keys
/// of both kinds; an external account binding; a new contact and a
/// deactivated account; a forced renewal; revocation; tls-alpn-01 alone;
/// dns-01 by dns_nsupdate into BIND; and the refusals.
/// </summary>
/// <remarks>
/// Grey for acme.sh 3.1.1, and so without a test here: profiles and ARI.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.4, §8")]
public class AcmeShTests(String ServerName) : InteropFixture(ServerName)
{

    protected override String[] Tools => [ "acme.sh", "socat", "openssl" ];

    private AcmeSh NewAcmeSh()
        => Keep(new AcmeSh(Server.TLS.RootFile));

    private String Common(String Email = "acmesh@acme.test")
        => $"--server '{DirectoryURL}' --accountemail {Email}";

    private String Standalone
        => $"--standalone --httpport {HTTP01Port}";

    private static String Domains(params String[] Names)
        => String.Join(" ", Names.Select(name => $"-d '{name}'"));

    private static String Evidence(Wsl.Result Result, AcmeSh AcmeSh)
        => $"{Result}\n--- acme.sh.log ---\n{AcmeSh.Log[^Math.Min(AcmeSh.Log.Length, 6000)..]}";


    #region http-01

    /// <summary>
    /// A certificate by http-01: acme.sh's own web server, or files in a
    /// webroot the bench serves - for a name, or for an address of RFC 8738.
    /// </summary>
    [TestCase("standalone", "127.0.0.1")]
    [TestCase("standalone", "::1")]
    [TestCase("standalone", BenchNames.WWW)]
    [TestCase("webroot",    "127.0.0.1")]
    [TestCase("webroot",    BenchNames.WWW)]
    [Property("RFC", "8555 §8.3; 8738")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Gets_A_Certificate_By_http01(String Mode, String Name)
    {

        if (!IPAddress.TryParse(Name, out _))
            TestEnvironment.RequireBenchNames();

        await StartAsync(Webroot: Mode == "webroot");

        var acme   = NewAcmeSh();
        // acme.sh's web server (socat) listens on IPv4 alone unless told.
        var result = acme.Run($"--issue {Common()} {Domains(Name)} --keylength ec-256 " + (Mode == "webroot" ? $"-w '{WebrootPath}'" : Standalone + (Name.Contains(':') ? " --listen-v6" : "")));

        AssertIssued(acme.FullChain(Name), [ Name ], "EC", 256, Evidence(result, acme));

    }

    /// <summary>
    /// A certificate of every kind of key acme.sh makes.
    /// </summary>
    [TestCase("ec-256", "EC",  256)]
    [TestCase("ec-384", "EC",  384)]
    [TestCase("2048",   "RSA", 2048)]
    [TestCase("3072",   "RSA", 3072)]
    [TestCase("4096",   "RSA", 4096)]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Gets_A_Certificate_Of_The_Key_Asked_For(String KeyLength, String Algorithm, Int32 Size)
    {

        await StartAsync();

        var acme   = NewAcmeSh();
        var result = acme.Run($"--issue {Common()} {Domains("127.0.0.1")} --keylength {KeyLength} {Standalone}", Timeout: TimeSpan.FromMinutes(4));

        AssertIssued(acme.FullChain("127.0.0.1"), [ "127.0.0.1" ], Algorithm, Size, Evidence(result, acme));

    }

    /// <summary>
    /// Accounts of both kinds of key acme.sh makes: RS256 and ES256 on the
    /// wire.
    /// </summary>
    [TestCase("ec-256", "EC",  "P-256")]
    [TestCase("ec-384", "EC",  "P-384")]
    [TestCase("2048",   "RSA", "2048")]
    [Property("RFC", "8555 §6.2, §7.3")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Opens_An_Account_Of_The_Key_Asked_For(String KeyLength, String KeyType, String Detail)
    {

        await StartAsync();

        var acme    = NewAcmeSh();
        var result  = acme.Run($"--register-account {Common()} --accountkeylength {KeyLength}");
        var account = AccountOf("acmesh@acme.test");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Success,     Is.True,           Evidence(result, acme));
            Assert.That(account?.KeyType,   Is.EqualTo(KeyType), "the kind of account key");
            Assert.That(account?.KeyDetail, Is.EqualTo(Detail),  "its curve or size");
        }

    }

    /// <summary>
    /// A certificate of sixteen names.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Gets_A_Certificate_Of_Sixteen_Names()
    {

        TestEnvironment.RequireBenchNames();
        await StartAsync();

        var acme   = NewAcmeSh();
        var result = acme.Run($"--issue {Common()} {Domains([ .. BenchNames.Numbered ])} --keylength ec-256 {Standalone}", Timeout: TimeSpan.FromMinutes(4));

        AssertIssued(acme.FullChain(BenchNames.Numbered[0]), BenchNames.Numbered, "EC", 256, Evidence(result, acme));

    }

    /// <summary>
    /// Section 7.4: a CSR of the client's own, openssl's.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Gets_A_Certificate_For_Its_Own_CSR()
    {

        await StartAsync();

        var acme        = NewAcmeSh();
        var (csr, _, _) = CSR(acme, "127.0.0.1");
        var result      = acme.Run($"--signcsr {Common()} --csr '{csr}' {Standalone}");
        var chain       = acme.Files("fullchain.cer").Select(file => file.Content).FirstOrDefault();

        AssertIssued(chain, [ "127.0.0.1" ], "EC", 256, Evidence(result, acme));

    }

    #endregion

    #region Accounts

    /// <summary>
    /// Section 7.3.4: an account bound to an external account of the CA.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Opens_An_Account_By_An_External_Account_Binding()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var (keyId, mac) = await ExternalAccountAsync();
        var acme         = NewAcmeSh();
        var result       = acme.Run($"--register-account {Common("eab@acme.test")} --eab-kid '{keyId}' --eab-hmac-key '{mac}'");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Success,                              Is.True,          Evidence(result, acme));
            Assert.That(AccountOf("eab@acme.test")?.ExternalAccount, Is.EqualTo(keyId), "bound to the external account");
        }

    }

    /// <summary>
    /// Section 7.3.2: a new contact for the account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Updates_The_Contact_Of_Its_Account()
    {

        await StartAsync();

        var acme     = NewAcmeSh();
        var register = acme.Run($"--register-account {Common()}");
        var update   = acme.Run($"--update-account {Common("new-acmesh@acme.test")}");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(register.Success,                  Is.True,     Evidence(register, acme));
            Assert.That(update.Success,                    Is.True,     Evidence(update, acme));
            Assert.That(AccountOf("new-acmesh@acme.test"), Is.Not.Null, $"the new contact: {String.Join(", ", Server.Accounts().SelectMany(account => account.Contacts))}");
        }

    }

    /// <summary>
    /// Section 7.3.6: acme.sh deactivates its account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.6")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Deactivates_Its_Account()
    {

        await StartAsync();

        var acme       = NewAcmeSh();
        var register   = acme.Run($"--register-account {Common()}");
        var deactivate = acme.Run($"--deactivate-account --server '{DirectoryURL}'");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(register.Success,                      Is.True,                   Evidence(register, acme));
            Assert.That(deactivate.Success,                    Is.True,                   Evidence(deactivate, acme));
            Assert.That(AccountOf("acmesh@acme.test")?.Status, Is.EqualTo("deactivated"), "the account's status");
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
    public async Task AcmeSh_Renews_When_Forced()
    {

        await StartAsync();

        var acme    = NewAcmeSh();
        var first   = acme.Run($"--issue {Common()} {Domains("127.0.0.1")} --keylength ec-256 {Standalone}");
        var before  = AssertIssued(acme.FullChain("127.0.0.1"), [ "127.0.0.1" ], "EC", 256, Evidence(first, acme));
        var renewal = acme.Run($"--renew {Common()} {Domains("127.0.0.1")} --ecc --force");
        var after   = AssertIssued(acme.FullChain("127.0.0.1"), [ "127.0.0.1" ], "EC", 256, Evidence(renewal, acme));

        Assert.That(after.Thumbprint, Is.Not.EqualTo(before.Thumbprint), $"a new certificate: {Evidence(renewal, acme)}");

    }

    /// <summary>
    /// Section 7.6: acme.sh revokes its certificate for a reason, and the CRL
    /// says so.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Revokes_Its_Certificate_For_A_Reason()
    {

        await StartAsync();

        var acme   = NewAcmeSh();
        var issued = acme.Run($"--issue {Common()} {Domains("127.0.0.1")} --keylength ec-256 {Standalone}");
        var chain  = acme.FullChain("127.0.0.1");
        var leaf   = AssertIssued(chain, [ "127.0.0.1" ], "EC", 256, Evidence(issued, acme));
        var result = acme.Run($"--revoke {Common()} {Domains("127.0.0.1")} --ecc --revoke-reason 4");

        Assert.That(result.Success, Is.True, Evidence(result, acme));

        AssertRevoked(leaf, chain!, 4, Evidence(result, acme));

    }

    #endregion

    #region Refusals

    /// <summary>
    /// A name the server does not sign for: rejectedIdentifier.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, §6.7")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Is_Told_Of_A_Name_Not_Signed_For()
    {

        await StartAsync(new ACMEServerOptions(AllowedNames: [ "acme.test", "127.0.0.0/8" ]));

        var acme   = NewAcmeSh();
        var result = acme.Run($"--issue {Common()} {Domains("refused.example")} {Standalone}");

        AssertRefused(result, acme.Log, "rejectedIdentifier");

    }

    /// <summary>
    /// A server that requires an external account binding says so.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "SHOULD")]
    public async Task AcmeSh_Is_Told_An_External_Account_Binding_Is_Required()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var acme   = NewAcmeSh();
        var result = acme.Run($"--register-account {Common()}");

        AssertRefused(result, acme.Log, "externalAccountRequired", "external account", "eab");

    }

    /// <summary>
    /// A wrong answer at the token's path: the challenge is invalid, and
    /// acme.sh is told why.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, §7.5.1")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Is_Told_Of_A_Wrong_Answer()
    {

        await StartAsync(Webroot: true);
        Webroot!.Fallback = _ => PKIConformance.Core.Scripted.HostAnswer.Text("not the key authorization");

        var acme   = NewAcmeSh();
        var result = acme.Run($"--issue {Common()} {Domains("127.0.0.1")} -w '{WebrootPath}'");

        AssertRefused(result, acme.Log, "incorrectResponse", "unauthorized", "invalid");

    }

    /// <summary>
    /// acme.sh with tls-alpn-01 alone, against a server that offers none
    /// (T-S1): a clean failure.
    /// </summary>
    [Test]
    [Property("RFC", "8737; 8555 §7.5")]
    [Property("Level", "SHOULD")]
    public async Task AcmeSh_With_tls_alpn_01_Alone_Is_Told_There_Is_No_Challenge_For_It()
    {

        await StartAsync();

        var acme   = NewAcmeSh();
        var result = acme.Run($"--issue {Common()} {Domains("127.0.0.1")} --alpn --tlsport {FreeTcpPort()}");

        AssertRefused(result, acme.Log, "tls-alpn-01");

    }

    #endregion

    #region dns-01 (RFC 2136, BIND)

    private String NSUpdate
        => $"NSUPDATE_SERVER=127.0.0.1 NSUPDATE_SERVER_PORT={DNS!.Port} NSUPDATE_KEY='{DNS.KeyFile}' NSUPDATE_ZONE={BenchNames.Zone}";

    /// <summary>
    /// dns_nsupdate writes the TXT record of dns-01 into BIND, TSIG-signed -
    /// whatever the server makes of it.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.4; 2136; 8945")]
    [Property("Level", "MUST")]
    public async Task AcmeSh_Writes_Its_dns01_Record_By_RFC_2136()
    {

        await StartAsync(DNS: true);

        var acme   = NewAcmeSh();
        var result = acme.Run($"--issue {Common()} {Domains(BenchNames.WWW)} --dns dns_nsupdate --dnssleep 1", NSUpdate);

        Assert.That(DNS!.AddedTXT, Has.Some.Contains($"_acme-challenge.{BenchNames.WWW}"), $"BIND took no TXT record of acme.sh's:\n{DNS.Log}\n{Evidence(result, acme)}");

    }

    /// <summary>
    /// A certificate by dns-01 - and a wildcard, which only dns-01 proves.
    /// </summary>
    [TestCase(BenchNames.WWW)]
    [TestCase("*.acme.test")]
    [Property("RFC", "8555 §8.4, §7.1.3")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "V-1")]
    public async Task AcmeSh_Gets_A_Certificate_By_dns01(String Name)
    {

        await StartAsync(DNS: true);

        var acme   = NewAcmeSh();
        var result = acme.Run($"--issue {Common()} {Domains(Name)} --keylength ec-256 --dns dns_nsupdate --dnssleep 1", NSUpdate);

        AssertIssued(acme.FullChain(Name), [ Name ], "EC", 256, $"{Evidence(result, acme)}\n{DNS!.Log}");

    }

    #endregion

}
