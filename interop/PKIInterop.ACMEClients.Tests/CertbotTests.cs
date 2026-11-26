using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// certbot - Debian 13's 4.0.0 - against the ACME server under test, the row
/// of certbot in the matrix of PLAN.md, section 4.5: certificates by http-01
/// from its own web server and by a webroot, of every kind of key, of sixteen
/// names and of its own CSR; an external account binding; a new contact and a
/// deactivated account; profiles; a forced renewal; revocation by the account
/// and by the certificate's key; dns-01 by certbot-dns-rfc2136 into BIND; and
/// the refusals it is to be told of.
/// </summary>
/// <remarks>
/// Grey for certbot 4.0.0, and so without a test here: IP identifiers (5.x),
/// ARI and "replaces" (4.1.0), key rollover (none).
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.4, §8")]
public class CertbotTests(String ServerName) : InteropFixture(ServerName)
{

    protected override String[] Tools => [ "python3", "openssl" ];

    [OneTimeSetUp]
    public void RequireCertbot()
    {
        if (!Certbot.Version.StartsWith("certbot ", StringComparison.Ordinal))
            Assert.Ignore($"certbot does not start: {Certbot.Version}");
        TestEnvironment.RequireBenchNames();
    }

    private Certbot NewCertbot()
        => Keep(new Certbot(Server.TLS.RootFile));

    private String Common(String Email = "certbot@acme.test")
        => $"--server '{DirectoryURL}' --agree-tos -m {Email} --no-eff-email";

    private String Standalone
        => $"--standalone --http-01-port {HTTP01Port}";

    private static String Domains(params String[] Names)
        => String.Join(" ", Names.Select(name => $"-d '{name}'"));

    private static String Evidence(Wsl.Result Result, Certbot Certbot)
        => $"{Result}\n--- letsencrypt.log ---\n{Certbot.Log[^Math.Min(Certbot.Log.Length, 6000)..]}";


    #region http-01

    /// <summary>
    /// A certificate by http-01: certbot's own web server, or files in a
    /// webroot the bench serves.
    /// </summary>
    [TestCase("standalone")]
    [TestCase("webroot")]
    [Property("RFC", "8555 §8.3")]
    [Property("Level", "MUST")]
    public async Task Certbot_Gets_A_Certificate_By_http01(String Mode)
    {

        await StartAsync(Webroot: Mode == "webroot");

        var certbot = NewCertbot();
        var result  = certbot.Run($"certonly {Common()} {Domains(BenchNames.WWW)} --key-type ecdsa --elliptic-curve secp256r1 " +
                                  (Mode == "webroot" ? $"--webroot -w '{WebrootPath}'" : Standalone));

        AssertIssued(certbot.Live(BenchNames.WWW, "fullchain.pem"), [ BenchNames.WWW ], "EC", 256, Evidence(result, certbot));

    }

    /// <summary>
    /// A certificate of every kind of key certbot makes.
    /// </summary>
    [TestCase("--key-type ecdsa --elliptic-curve secp256r1", "EC",  256)]
    [TestCase("--key-type ecdsa --elliptic-curve secp384r1", "EC",  384)]
    [TestCase("--key-type rsa --rsa-key-size 2048",          "RSA", 2048)]
    [TestCase("--key-type rsa --rsa-key-size 3072",          "RSA", 3072)]
    [TestCase("--key-type rsa --rsa-key-size 4096",          "RSA", 4096)]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task Certbot_Gets_A_Certificate_Of_The_Key_Asked_For(String Key, String Algorithm, Int32 Size)
    {

        await StartAsync();

        var certbot = NewCertbot();
        var result  = certbot.Run($"certonly {Common()} {Domains(BenchNames.WWW)} {Key} {Standalone}", TimeSpan.FromMinutes(4));

        AssertIssued(certbot.Live(BenchNames.WWW, "fullchain.pem"), [ BenchNames.WWW ], Algorithm, Size, Evidence(result, certbot));

    }

    /// <summary>
    /// A certificate of sixteen names.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task Certbot_Gets_A_Certificate_Of_Sixteen_Names()
    {

        await StartAsync();

        var certbot = NewCertbot();
        var result  = certbot.Run($"certonly {Common()} {Domains([ .. BenchNames.Numbered ])} --key-type ecdsa {Standalone}", TimeSpan.FromMinutes(4));

        AssertIssued(certbot.Live(BenchNames.Numbered[0], "fullchain.pem"), BenchNames.Numbered, "EC", 256, Evidence(result, certbot));

    }

    /// <summary>
    /// Section 7.4: a CSR of the client's own - openssl's - and certbot
    /// writes the certificate where it is told.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task Certbot_Gets_A_Certificate_For_Its_Own_CSR()
    {

        await StartAsync();

        var certbot      = NewCertbot();
        var (csr, _, _)  = CSR(certbot, BenchNames.WWW);
        var result       = certbot.Run($"certonly {Common()} --csr '{csr}' {Standalone} " +
                                       $"--cert-path '{certbot.WslPathOf("own-cert.pem")}' --fullchain-path '{certbot.WslPathOf("own-fullchain.pem")}' " +
                                       $"--chain-path '{certbot.WslPathOf("own-chain.pem")}'");

        AssertIssued(certbot.Read("own-fullchain.pem"), [ BenchNames.WWW ], "EC", 256, Evidence(result, certbot));

    }

    #endregion

    #region Accounts

    /// <summary>
    /// Section 7.3.4: an account bound to an external account of the CA.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "MUST")]
    public async Task Certbot_Opens_An_Account_By_An_External_Account_Binding()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var (keyId, mac) = await ExternalAccountAsync();
        var certbot      = NewCertbot();
        var result       = certbot.Run($"register {Common("eab@acme.test")} --eab-kid '{keyId}' --eab-hmac-key '{mac}'");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Success,                              Is.True,          Evidence(result, certbot));
            Assert.That(AccountOf("eab@acme.test")?.ExternalAccount, Is.EqualTo(keyId), "bound to the external account");
        }

    }

    /// <summary>
    /// Section 7.3.4: a server that requires a binding says so, and certbot
    /// says it on.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "SHOULD")]
    public async Task Certbot_Is_Told_An_External_Account_Binding_Is_Required()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var certbot = NewCertbot();
        var result  = certbot.Run($"register {Common()}");

        AssertRefused(result, certbot.Log, "externalAccountRequired", "external account");

    }

    /// <summary>
    /// Section 7.3.2: a new contact for the account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    public async Task Certbot_Updates_The_Contact_Of_Its_Account()
    {

        await StartAsync();

        var certbot  = NewCertbot();
        var register = certbot.Run($"register {Common()}");
        var update   = certbot.Run($"update_account --server '{DirectoryURL}' -m new-certbot@acme.test --no-eff-email");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(register.Success,                   Is.True,     Evidence(register, certbot));
            Assert.That(update.Success,                     Is.True,     Evidence(update, certbot));
            Assert.That(AccountOf("new-certbot@acme.test"), Is.Not.Null, $"the new contact: {String.Join(", ", Server.Accounts().SelectMany(account => account.Contacts))}");
        }

    }

    /// <summary>
    /// Section 7.3.6: certbot deactivates its account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.6")]
    [Property("Level", "MUST")]
    public async Task Certbot_Deactivates_Its_Account()
    {

        await StartAsync();

        var certbot    = NewCertbot();
        var register   = certbot.Run($"register {Common()}");
        var unregister = certbot.Run($"unregister --server '{DirectoryURL}'");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(register.Success,                       Is.True,                 Evidence(register, certbot));
            Assert.That(unregister.Success,                     Is.True,                 Evidence(unregister, certbot));
            Assert.That(AccountOf("certbot@acme.test")?.Status, Is.EqualTo("deactivated"), "the account's status");
        }

    }

    #endregion

    #region Profiles, renewal, revocation

    /// <summary>
    /// draft-ietf-acme-profiles: the profile certbot asks for, preferred or
    /// required, and a certificate that holds as long as it says.
    /// </summary>
    [TestCase("--preferred-profile shortlived")]
    [TestCase("--required-profile shortlived")]
    [Property("RFC", "draft-ietf-acme-profiles-03 §4")]
    [Property("Level", "MUST")]
    public async Task Certbot_Gets_A_Certificate_Of_The_Profile_Asked_For(String Profile)
    {

        await StartAsync(new ACMEServerOptions(Profiles: new Dictionary<String, Int32> { ["classic"] = 90, ["shortlived"] = 7 }));

        var certbot = NewCertbot();
        var result  = certbot.Run($"certonly {Common()} {Domains(BenchNames.WWW)} --key-type ecdsa {Profile} {Standalone}");
        var leaf    = AssertIssued(certbot.Live(BenchNames.WWW, "fullchain.pem"), [ BenchNames.WWW ], "EC", 256, Evidence(result, certbot));

        Assert.That((leaf.NotAfter - leaf.NotBefore).TotalDays, Is.InRange(6, 8), "the seven days of \"shortlived\"");

    }

    /// <summary>
    /// A forced renewal: a new certificate of the same names.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task Certbot_Renews_When_Forced()
    {

        await StartAsync();

        var certbot = NewCertbot();
        var first   = certbot.Run($"certonly {Common()} {Domains(BenchNames.WWW)} --key-type ecdsa {Standalone}");
        var before  = AssertIssued(certbot.Live(BenchNames.WWW, "fullchain.pem"), [ BenchNames.WWW ], "EC", 256, Evidence(first, certbot));
        var renewal = certbot.Run($"renew --force-renewal --cert-name {BenchNames.WWW} --no-random-sleep-on-renew");
        var after   = AssertIssued(certbot.Live(BenchNames.WWW, "fullchain.pem"), [ BenchNames.WWW ], "EC", 256, Evidence(renewal, certbot));

        Assert.That(after.Thumbprint, Is.Not.EqualTo(before.Thumbprint), $"a new certificate: {Evidence(renewal, certbot)}");

    }

    /// <summary>
    /// Section 7.6: certbot revokes its certificate for a reason - by its
    /// account, or by the certificate's own key ("jwk") - and the CRL says so.
    /// </summary>
    [TestCase("account")]
    [TestCase("certificate key")]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    public async Task Certbot_Revokes_Its_Certificate(String By)
    {

        await StartAsync();

        var certbot = NewCertbot();
        var issued  = certbot.Run($"certonly {Common()} {Domains(BenchNames.WWW)} --key-type ecdsa {Standalone}");
        var chain   = certbot.Live(BenchNames.WWW, "fullchain.pem");
        var leaf    = AssertIssued(chain, [ BenchNames.WWW ], "EC", 256, Evidence(issued, certbot));
        var cert    = certbot.WslPathOf($"config/live/{BenchNames.WWW}/cert.pem");
        var key     = certbot.WslPathOf($"config/live/{BenchNames.WWW}/privkey.pem");
        var result  = certbot.Run($"revoke --server '{DirectoryURL}' --cert-path '{cert}' --reason keycompromise --no-delete-after-revoke" +
                                  (By == "certificate key" ? $" --key-path '{key}'" : ""));

        Assert.That(result.Success, Is.True, Evidence(result, certbot));

        AssertRevoked(leaf, chain!, 1, Evidence(result, certbot));

    }

    #endregion

    #region Refusals

    /// <summary>
    /// A name the server does not sign for: rejectedIdentifier.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, §6.7")]
    [Property("Level", "MUST")]
    public async Task Certbot_Is_Told_Of_A_Name_Not_Signed_For()
    {

        await StartAsync(new ACMEServerOptions(AllowedNames: [ "acme.test", "127.0.0.0/8" ]));

        var certbot = NewCertbot();
        var result  = certbot.Run($"certonly {Common()} {Domains("refused.example")} {Standalone}");

        AssertRefused(result, certbot.Log, "rejectedIdentifier");

    }

    /// <summary>
    /// A wrong answer at the token's path: the challenge is invalid, and
    /// certbot is told why.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, §7.5.1")]
    [Property("Level", "MUST")]
    public async Task Certbot_Is_Told_Of_A_Wrong_Answer()
    {

        await StartAsync(Webroot: true);
        Webroot!.Fallback = _ => PKIConformance.Core.Scripted.HostAnswer.Text("not the key authorization");

        var certbot = NewCertbot();
        var result  = certbot.Run($"certonly {Common()} {Domains(BenchNames.WWW)} --webroot -w '{WebrootPath}'");

        AssertRefused(result, certbot.Log, "incorrectResponse", "unauthorized", "invalid");

    }

    #endregion

    #region dns-01 (RFC 2136, BIND)

    private String Credentials(Certbot Certbot)
    {
        var ini = Certbot.Write("rfc2136.ini", $"""
                                               dns_rfc2136_server = 127.0.0.1
                                               dns_rfc2136_port = {DNS!.Port}
                                               dns_rfc2136_name = {Bind.KeyName}
                                               dns_rfc2136_secret = {DNS.KeySecret}
                                               dns_rfc2136_algorithm = HMAC-SHA256
                                               """ + "\n");
        Wsl.Run($"chmod 600 '{ini}'", TimeSpan.FromSeconds(10));
        return $"--dns-rfc2136 --dns-rfc2136-credentials '{ini}' --dns-rfc2136-propagation-seconds 1";
    }

    /// <summary>
    /// certbot-dns-rfc2136 writes the TXT record of dns-01 into BIND,
    /// TSIG-signed - whatever the server makes of it.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.4; 2136; 8945")]
    [Property("Level", "MUST")]
    public async Task Certbot_Writes_Its_dns01_Record_By_RFC_2136()
    {

        await StartAsync(DNS: true);

        var certbot = NewCertbot();
        var result  = certbot.Run($"certonly {Common()} {Domains(BenchNames.WWW)} {Credentials(certbot)}");

        Assert.That(DNS!.AddedTXT, Has.Some.Contains($"_acme-challenge.{BenchNames.WWW}"), $"BIND took no TXT record of certbot's:\n{DNS.Log}\n{Evidence(result, certbot)}");

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
    public async Task Certbot_Gets_A_Certificate_By_dns01(String Name)
    {

        await StartAsync(DNS: true);

        var certbot = NewCertbot();
        var result  = certbot.Run($"certonly {Common()} {Domains(Name)} --key-type ecdsa --cert-name dns01 {Credentials(certbot)}");

        AssertIssued(certbot.Live("dns01", "fullchain.pem"), [ Name ], "EC", 256, $"{Evidence(result, certbot)}\n{DNS!.Log}");

    }

    #endregion

}
