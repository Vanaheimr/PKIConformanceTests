using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// uacme - Debian 13's 1.7.6 - against the ACME server under test, its row in
/// the matrix of PLAN.md, section 4.5: certificates by http-01 through its
/// hook into a webroot the bench serves, of names and addresses, of every
/// kind of key, of sixteen names and of its own CSR; account keys of both
/// kinds; an external account binding; a new contact, a key rollover and a
/// deactivated account; a forced renewal, having read the window of ARI;
/// revocation by the account and by the certificate's key; and the
/// refusals.
/// </summary>
/// <remarks>
/// uacme takes no CA file: it trusts the system's bundle, which the bench
/// lays over in the namespace of the run (TestEnvironment.TrustSystemWide).
/// Grey for uacme 1.7.6: profiles, and "replaces" - it reads ARI and says
/// nothing of what a renewal replaces.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.4, §8")]
public class UacmeTests(String ServerName) : InteropFixture(ServerName)
{

    protected override String[] Tools    => [ "uacme", "openssl" ];

    protected override String   PeerName => Uacme.Name;

    private async Task<Uacme> StartUacmeAsync(ACMEServerOptions? Options = null)
    {
        await StartAsync(Options, Webroot: true);
        TestEnvironment.TrustSystemWide(Server.TLS.RootFile);
        return Keep(new Uacme(Server.TLS.RootFile));
    }

    private static String Hook
        => $"-h {Uacme.Hook}";

    private Wsl.Result New(Uacme Uacme, String Email = "uacme@acme.test", String? Options = null)
        => Uacme.Run(DirectoryURL, $"-y {Options} new {Email}");

    private Wsl.Result Issue(Uacme Uacme, String Options, params String[] Names)
        => Uacme.Run(DirectoryURL, $"{Hook} {Options} issue {String.Join(" ", Names.Select(name => $"'{name}'"))}", WellKnownPath, TimeSpan.FromMinutes(4));


    #region http-01

    /// <summary>
    /// A certificate by http-01, for a name or an address of RFC 8738.
    /// </summary>
    [TestCase("127.0.0.1")]
    [TestCase("::1")]
    [TestCase(BenchNames.WWW)]
    [Property("RFC", "8555 §8.3; 8738")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.IPv4, Argument = "127.0.0.1")]
    [Cell(InteropCells.IPv6, Argument = "::1")]
    [Cell(InteropCells.Http01Webroot)]
    public async Task Uacme_Gets_A_Certificate_By_http01(String Name)
    {

        if (!IPAddress.TryParse(Name, out _))
            TestEnvironment.RequireBenchNames();

        var uacme   = await StartUacmeAsync();
        var account = New(uacme);
        var result  = Issue(uacme, "-t EC -b 256", Name);

        AssertIssued(uacme.Certificate(Name), [ Name ], "EC", 256, $"{account}\n{result}");

    }

    /// <summary>
    /// A certificate of every kind of key uacme makes.
    /// </summary>
    [TestCase("EC",  256)]
    [TestCase("EC",  384)]
    [TestCase("RSA", 2048)]
    [TestCase("RSA", 3072)]
    [TestCase("RSA", 4096)]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.CertificateKeys)]
    public async Task Uacme_Gets_A_Certificate_Of_The_Key_Asked_For(String Type, Int32 Bits)
    {

        var uacme   = await StartUacmeAsync();
        var account = New(uacme);
        var result  = Issue(uacme, $"-t {Type} -b {Bits}", "127.0.0.1");

        AssertIssued(uacme.Certificate("127.0.0.1"), [ "127.0.0.1" ], Type, Bits, $"{account}\n{result}");

    }

    /// <summary>
    /// Accounts of both kinds of key uacme makes.
    /// </summary>
    [TestCase("EC",  256,  "P-256")]
    [TestCase("RSA", 2048, "2048")]
    [Property("RFC", "8555 §6.2, §7.3")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountKeys)]
    public async Task Uacme_Opens_An_Account_Of_The_Key_Asked_For(String Type, Int32 Bits, String Detail)
    {

        var uacme   = await StartUacmeAsync();
        var result  = New(uacme, Options: $"-t {Type} -b {Bits}");
        var account = AccountOf("uacme@acme.test");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Success,     Is.True,          result.ToString());
            Assert.That(account?.KeyType,   Is.EqualTo(Type),   "the kind of account key");
            Assert.That(account?.KeyDetail, Is.EqualTo(Detail), "its curve or size");
        }

    }

    /// <summary>
    /// A certificate of sixteen names.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.SixteenNames)]
    public async Task Uacme_Gets_A_Certificate_Of_Sixteen_Names()
    {

        TestEnvironment.RequireBenchNames();

        var uacme   = await StartUacmeAsync();
        var account = New(uacme);
        var result  = Issue(uacme, "-t EC -b 256", [ .. BenchNames.Numbered ]);

        AssertIssued(uacme.Certificate(BenchNames.Numbered[0]), BenchNames.Numbered, "EC", 256, $"{account}\n{result}");

    }

    /// <summary>
    /// Section 7.4: a CSR of the client's own, openssl's.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.OwnCSR)]
    public async Task Uacme_Gets_A_Certificate_For_Its_Own_CSR()
    {

        var uacme       = await StartUacmeAsync();
        var account     = New(uacme);
        var (csr, _, _) = CSR(uacme, "127.0.0.1");
        var result      = uacme.Run(DirectoryURL, $"{Hook} issue '{csr}'", WellKnownPath);
        // uacme keeps the certificate of a CSR beside it: own.csr, own-cert.pem.
        var chain       = uacme.Read("own-cert.pem");

        AssertIssued(chain, [ "127.0.0.1" ], "EC", 256, $"{account}\n{result}\n{String.Join("\n", Directory.EnumerateFiles(uacme.Directory, "*", SearchOption.AllDirectories))}");

    }

    #endregion

    #region Accounts

    /// <summary>
    /// Section 7.3.4: an account bound to an external account of the CA.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountEAB)]
    public async Task Uacme_Opens_An_Account_By_An_External_Account_Binding()
    {

        var uacme        = await StartUacmeAsync(new ACMEServerOptions(ExternalAccountRequired: true));
        var (keyId, mac) = await ExternalAccountAsync();
        var result       = New(uacme, "eab@acme.test", $"-e '{keyId}:{mac}'");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Success,                              Is.True,          result.ToString());
            Assert.That(AccountOf("eab@acme.test")?.ExternalAccount, Is.EqualTo(keyId), "bound to the external account");
        }

    }

    /// <summary>
    /// Section 7.3.2: a new contact for the account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountContact)]
    public async Task Uacme_Updates_The_Contact_Of_Its_Account()
    {

        var uacme   = await StartUacmeAsync();
        var account = New(uacme);
        var update  = uacme.Run(DirectoryURL, "-y update new-uacme@acme.test");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(account.Success,                  Is.True,     account.ToString());
            Assert.That(update.Success,                   Is.True,     update.ToString());
            Assert.That(AccountOf("new-uacme@acme.test"), Is.Not.Null, $"the new contact: {String.Join(", ", Server.Accounts().SelectMany(candidate => candidate.Contacts))}");
        }

    }

    /// <summary>
    /// Section 7.3.5: uacme rolls its account key over.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.5")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountKeyRollover)]
    public async Task Uacme_Rolls_Its_Account_Key_Over()
    {

        var uacme    = await StartUacmeAsync();
        var account  = New(uacme, Options: "-t EC -b 256");
        var before   = AccountOf("uacme@acme.test");
        var rollover = uacme.Run(DirectoryURL, "-y -t EC -b 384 newkey");
        var after    = AccountOf("uacme@acme.test");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(account.Success,   Is.True,               account.ToString());
            Assert.That(rollover.Success,  Is.True,               rollover.ToString());
            Assert.That(after?.Id,         Is.EqualTo(before?.Id), "the same account");
            Assert.That(after?.KeyDetail,  Is.Not.EqualTo(before?.KeyDetail), $"another key: {rollover}");
        }

    }

    /// <summary>
    /// Section 7.3.6: uacme deactivates its account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountDeactivated)]
    public async Task Uacme_Deactivates_Its_Account()
    {

        var uacme      = await StartUacmeAsync();
        var account    = New(uacme);
        var deactivate = uacme.Run(DirectoryURL, "-y deactivate");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(account.Success,                      Is.True,                   account.ToString());
            Assert.That(deactivate.Success,                   Is.True,                   deactivate.ToString());
            Assert.That(AccountOf("uacme@acme.test")?.Status, Is.EqualTo("deactivated"), "the account's status");
        }

    }

    #endregion

    #region Renewal, revocation

    /// <summary>
    /// A forced renewal, after uacme read the certificate's window of RFC
    /// 9773 at the server - the RenewalInfo of the PKI, read by a client of
    /// another hand. (uacme 1.7.6 reads ARI and sends no "replaces": that
    /// cell is grey.)
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4; 9773 §4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RenewalForced)]
    public async Task Uacme_Renews_When_Forced_Having_Read_The_Window()
    {

        var uacme   = await StartUacmeAsync();
        var account = New(uacme);
        var first   = Issue(uacme, "-t EC -b 256", "127.0.0.1");
        var before  = AssertIssued(uacme.Certificate("127.0.0.1"), [ "127.0.0.1" ], "EC", 256, $"{account}\n{first}");
        var renewal = Issue(uacme, "-f -t EC -b 256", "127.0.0.1");
        var after   = AssertIssued(uacme.Certificate("127.0.0.1"), [ "127.0.0.1" ], "EC", 256, renewal);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(renewal.StdOut,   Does.Contain("certificate renewal window: start="), $"uacme read the window: {renewal}");
            Assert.That(after.Thumbprint, Is.Not.EqualTo(before.Thumbprint),                  $"a new certificate: {renewal}");
        }

    }

    /// <summary>
    /// Section 7.6: uacme revokes its certificate for a reason - by its
    /// account, or by the certificate's own key - and the CRL says so.
    /// </summary>
    [TestCase("account")]
    [TestCase("certificate key")]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RevokedByAccount, Argument = "account")]
    [Cell(InteropCells.RevokedByCertificateKey, Argument = "certificate key")]
    public async Task Uacme_Revokes_Its_Certificate(String By)
    {

        var uacme   = await StartUacmeAsync();
        var account = New(uacme);
        var issued  = Issue(uacme, "-t EC -b 256", "127.0.0.1");
        var chain   = uacme.Certificate("127.0.0.1");
        var leaf    = AssertIssued(chain, [ "127.0.0.1" ], "EC", 256, $"{account}\n{issued}");
        var result  = uacme.Run(DirectoryURL, $"-r 4 revoke '{uacme.WslPathOf("127.0.0.1/cert.pem")}'" +
                                              (By == "certificate key" ? $" '{uacme.WslPathOf("private/127.0.0.1/key.pem")}'" : ""));

        Assert.That(result.Success, Is.True, result.ToString());

        AssertRevoked(leaf, chain!, 4, result);

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
    public async Task Uacme_Is_Told_Of_A_Name_Not_Signed_For()
    {

        var uacme  = await StartUacmeAsync(new ACMEServerOptions(AllowedNames: [ "acme.test", "127.0.0.0/8" ]));
        New(uacme);
        var result = Issue(uacme, "", "refused.example");

        AssertRefused(result, "", "rejectedIdentifier");

    }

    /// <summary>
    /// A server that requires an external account binding says so.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "SHOULD")]
    [Cell(InteropCells.RefusedNoEAB)]
    public async Task Uacme_Is_Told_An_External_Account_Binding_Is_Required()
    {

        var uacme  = await StartUacmeAsync(new ACMEServerOptions(ExternalAccountRequired: true));
        var result = New(uacme);

        AssertRefused(result, "", "externalAccountRequired", "external account", "external credentials");

    }

    /// <summary>
    /// A wrong answer at the token's path: the challenge is invalid, and
    /// uacme is told why.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, §7.5.1")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RefusedWrongAnswer)]
    public async Task Uacme_Is_Told_Of_A_Wrong_Answer()
    {

        var uacme = await StartUacmeAsync();
        Webroot!.Fallback = _ => PKIConformance.Core.Scripted.HostAnswer.Text("not the key authorization");

        New(uacme);
        var result = Issue(uacme, "", "127.0.0.1");

        AssertRefused(result, "", "incorrectResponse", "unauthorized", "invalid");

    }

    #endregion

}
