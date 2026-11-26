using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// lego 5 against the ACME server under test - the row of lego in the matrix
/// of PLAN.md, section 4.5: certificates by http-01 from its own web server
/// and by a webroot, of names and of addresses (RFC 8738), of every kind of
/// key, of sixteen names and of its own CSR; an external account binding;
/// profiles; a renewal that says what it replaces (RFC 9773); revocation;
/// a key rollover; dns-01 by its RFC 2136 provider into BIND; and the
/// refusals it is to be told of.
/// </summary>
/// <remarks>
/// lego is the peer with the most of the extensions the PKI has, and with
/// tls-alpn-01, which the PKI has not (T-S1) - PLAN.md, section 4.5.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.4, §8")]
public class LegoTests(String ServerName) : InteropFixture(ServerName)
{

    protected override String[] Tools => [ "lego", "openssl" ];

    private Lego NewLego()
        => Keep(new Lego(Server.TLS.RootFile));

    private String Common(String Email = "lego@acme.test")
        => $"--server '{DirectoryURL}' --accept-tos --email {Email}";

    private String Standalone
        => $"--http --http.address :{HTTP01Port}";

    private static String Domains(params String[] Names)
        => String.Join(" ", Names.Select(name => $"--domains '{name}'"));


    #region http-01

    /// <summary>
    /// A certificate by http-01 - lego's own web server, or files in a webroot
    /// the bench serves - for a name, or for an address of RFC 8738.
    /// </summary>
    [TestCase("standalone", "127.0.0.1")]
    [TestCase("standalone", "::1")]
    [TestCase("standalone", BenchNames.WWW)]
    [TestCase("webroot",    "127.0.0.1")]
    [TestCase("webroot",    BenchNames.WWW)]
    [Property("RFC", "8555 §8.3; 8738")]
    [Property("Level", "MUST")]
    public async Task Lego_Gets_A_Certificate_By_http01(String Mode, String Name)
    {

        if (!IPAddress.TryParse(Name, out _))
            TestEnvironment.RequireBenchNames();

        await StartAsync(Webroot: Mode == "webroot");

        var lego   = NewLego();
        var result = lego.Run($"run {Common()} {Domains(Name)} --key-type EC256 " +
                              (Mode == "webroot" ? $"--http --http.webroot '{WebrootPath}'" : Standalone));

        AssertIssued(lego.Certificate(Name), [ Name ], "EC", 256, result);

    }

    /// <summary>
    /// A certificate of every kind of key lego makes.
    /// </summary>
    [TestCase("EC256",   "EC",  256)]
    [TestCase("EC384",   "EC",  384)]
    [TestCase("RSA2048", "RSA", 2048)]
    [TestCase("RSA3072", "RSA", 3072)]
    [TestCase("RSA4096", "RSA", 4096)]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task Lego_Gets_A_Certificate_Of_The_Key_Asked_For(String KeyType, String Algorithm, Int32 Size)
    {

        await StartAsync();

        var lego   = NewLego();
        var result = lego.Run($"run {Common()} {Domains("127.0.0.1")} --key-type {KeyType} {Standalone}", Timeout: TimeSpan.FromMinutes(4));

        AssertIssued(lego.Certificate("127.0.0.1"), [ "127.0.0.1" ], Algorithm, Size, result);

    }

    /// <summary>
    /// A certificate of sixteen names - an order of sixteen authorizations.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task Lego_Gets_A_Certificate_Of_Sixteen_Names()
    {

        TestEnvironment.RequireBenchNames();
        await StartAsync();

        var lego   = NewLego();
        var result = lego.Run($"run {Common()} {Domains([ .. BenchNames.Numbered ])} --key-type EC256 {Standalone}", Timeout: TimeSpan.FromMinutes(4));

        AssertIssued(lego.Certificate(BenchNames.Numbered[0]), BenchNames.Numbered, "EC", 256, result);

    }

    /// <summary>
    /// Section 7.4: the CSR is the client's - one of openssl's, of lego's
    /// own key.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task Lego_Gets_A_Certificate_For_Its_Own_CSR()
    {

        await StartAsync();

        var lego       = NewLego();
        var (csr, _, _) = CSR(lego, "127.0.0.1");
        var result     = lego.Run($"run {Common()} --csr '{csr}' {Standalone}");

        AssertIssued(lego.Certificate("127.0.0.1"), [ "127.0.0.1" ], "EC", 256, result);

    }

    #endregion

    #region Accounts

    /// <summary>
    /// Section 7.3.4: an account bound to an external account of the CA - the
    /// key identifier and the MAC key it handed out.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "MUST")]
    public async Task Lego_Opens_An_Account_By_An_External_Account_Binding()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var (keyId, mac) = await ExternalAccountAsync();
        var lego         = NewLego();
        var result       = lego.Run($"accounts register {Common("eab@acme.test")} --eab --eab.kid '{keyId}' --eab.hmac '{mac}'");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Success,                             Is.True,          result.ToString());
            Assert.That(AccountOf("eab@acme.test")?.ExternalAccount, Is.EqualTo(keyId), $"bound to the external account: {result}");
        }

    }

    /// <summary>
    /// Section 7.3.4: a server that requires a binding says so - and lego
    /// says it on: externalAccountRequired.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "SHOULD")]
    public async Task Lego_Is_Told_An_External_Account_Binding_Is_Required()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var lego   = NewLego();
        var result = lego.Run($"accounts register {Common()}");

        AssertRefused(result, "", "externalAccountRequired", "external account");

    }

    /// <summary>
    /// Section 7.3.5: lego rolls its account key over - the account is the
    /// same, its key a new one.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.5")]
    [Property("Level", "MUST")]
    public async Task Lego_Rolls_Its_Account_Key_Over()
    {

        await StartAsync();

        var lego     = NewLego();
        var register = lego.Run($"accounts register {Common()} --key-type EC256");
        var before   = AccountOf("lego@acme.test");
        var rollover = lego.Run($"accounts keyrollover --server '{DirectoryURL}' --email lego@acme.test --key-type EC384", Answer: "y");
        var after    = AccountOf("lego@acme.test");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(register.Success,  Is.True,              register.ToString());
            Assert.That(rollover.Success,  Is.True,              rollover.ToString());
            Assert.That(after?.Id,         Is.EqualTo(before?.Id), "the same account");
            Assert.That(before?.KeyDetail, Is.EqualTo("P-256"),  "the key before");
            Assert.That(after?.KeyDetail,  Is.EqualTo("P-384"),  $"the key after: {rollover}");
        }

    }

    #endregion

    #region Profiles, renewal, revocation

    /// <summary>
    /// draft-ietf-acme-profiles: the profile lego asks for, and a certificate
    /// that holds as long as the profile says.
    /// </summary>
    [Test]
    [Property("RFC", "draft-ietf-acme-profiles-03 §4")]
    [Property("Level", "MUST")]
    public async Task Lego_Gets_A_Certificate_Of_The_Profile_Asked_For()
    {

        await StartAsync(new ACMEServerOptions(Profiles: new Dictionary<String, Int32> { ["classic"] = 90, ["shortlived"] = 7 }));

        var lego   = NewLego();
        var result = lego.Run($"run {Common()} {Domains("127.0.0.1")} --key-type EC256 --profile shortlived {Standalone}");
        var leaf   = AssertIssued(lego.Certificate("127.0.0.1"), [ "127.0.0.1" ], "EC", 256, result);

        Assert.That((leaf.NotAfter - leaf.NotBefore).TotalDays, Is.InRange(6, 8), "the seven days of \"shortlived\"");

    }

    /// <summary>
    /// RFC 9773, section 5: a renewal says which certificate it replaces -
    /// <i>"Clients SHOULD include this field in newOrder requests if there is
    /// a clear predecessor certificate"</i> - and the server keeps it so.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD")]
    public async Task Lego_Renews_Saying_Which_Certificate_It_Replaces()
    {

        await StartAsync();

        var lego    = NewLego();
        var first   = lego.Run($"run {Common()} {Domains("127.0.0.1")} --key-type EC256 {Standalone}");
        var before  = AssertIssued(lego.Certificate("127.0.0.1"), [ "127.0.0.1" ], "EC", 256, first);
        var renewal = lego.Run($"run {Common()} {Domains("127.0.0.1")} --key-type EC256 --renew-force --no-random-sleep {Standalone}");
        var after   = AssertIssued(lego.Certificate("127.0.0.1"), [ "127.0.0.1" ], "EC", 256, renewal);

        Assert.That(Server.Issued().Single(issued => issued.DER.AsSpan().SequenceEqual(after.RawData)).Replaces,
                    Is.EqualTo(PKIConformance.Core.RawACME.RawARI.CertificateId(before.RawData)), $"replaces the one before: {renewal}");

    }

    /// <summary>
    /// Section 7.6: lego revokes its certificate, for a reason - and the
    /// server's CRL says so.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    public async Task Lego_Revokes_Its_Certificate_For_A_Reason()
    {

        await StartAsync();

        var lego   = NewLego();
        var issued = lego.Run($"run {Common()} {Domains("127.0.0.1")} --key-type EC256 {Standalone}");
        var chain  = lego.Certificate("127.0.0.1");
        var leaf   = AssertIssued(chain, [ "127.0.0.1" ], "EC", 256, issued);
        var result = lego.Run($"certificates revoke --server '{DirectoryURL}' --email lego@acme.test --cert.name 127.0.0.1 --reason 4 --keep");

        Assert.That(result.Success, Is.True, result.ToString());

        AssertRevoked(leaf, chain!, 4, result);

    }

    #endregion

    #region Refusals

    /// <summary>
    /// A name the server does not sign for: lego is told, rejectedIdentifier.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, §6.7")]
    [Property("Level", "MUST")]
    public async Task Lego_Is_Told_Of_A_Name_Not_Signed_For()
    {

        await StartAsync(new ACMEServerOptions(AllowedNames: [ "acme.test", "127.0.0.0/8" ]));

        var lego   = NewLego();
        var result = lego.Run($"run {Common()} {Domains("refused.example")} {Standalone}");

        AssertRefused(result, "", "rejectedIdentifier");

    }

    /// <summary>
    /// A wrong answer at the token's path: the challenge is invalid, and lego
    /// is told why.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, §7.5.1")]
    [Property("Level", "MUST")]
    public async Task Lego_Is_Told_Of_A_Wrong_Answer()
    {

        await StartAsync(Webroot: true);
        Webroot!.Fallback = _ => PKIConformance.Core.Scripted.HostAnswer.Text("not the key authorization");

        var lego   = NewLego();
        var result = lego.Run($"run {Common()} {Domains("127.0.0.1")} --http --http.webroot '{WebrootPath}'");

        AssertRefused(result, "", "incorrectResponse", "unauthorized", "invalid");

    }

    /// <summary>
    /// lego with tls-alpn-01 alone, against a server that offers none (T-S1):
    /// a clean failure that says there is no challenge to solve.
    /// </summary>
    [Test]
    [Property("RFC", "8737; 8555 §7.5")]
    [Property("Level", "SHOULD")]
    public async Task Lego_With_tls_alpn_01_Alone_Is_Told_There_Is_No_Challenge_For_It()
    {

        await StartAsync();

        var lego   = NewLego();
        var result = lego.Run($"run {Common()} {Domains("127.0.0.1")} --tls --tls.address :{FreeTcpPort()}");

        AssertRefused(result, "", "tls-alpn-01", "no solver", "unable to find a solver");

    }

    #endregion

    #region dns-01 (RFC 2136, BIND)

    private String RFC2136
        => $"RFC2136_NAMESERVER=127.0.0.1:{DNS!.Port} RFC2136_TSIG_KEY={Bind.KeyName}. RFC2136_TSIG_SECRET='{DNS.KeySecret}' " +
           $"RFC2136_TSIG_ALGORITHM=hmac-sha256. RFC2136_PROPAGATION_TIMEOUT=10 RFC2136_POLLING_INTERVAL=1";

    private String DNSOptions
        => $"--dns rfc2136 --dns.resolvers 127.0.0.1:{DNS!.Port} --dns.propagation.wait 1s";

    /// <summary>
    /// lego's RFC 2136 provider writes the TXT record of dns-01 into BIND,
    /// TSIG-signed - whatever the server makes of it.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.4; 2136; 8945")]
    [Property("Level", "MUST")]
    public async Task Lego_Writes_Its_dns01_Record_By_RFC_2136()
    {

        await StartAsync(DNS: true);

        var lego   = NewLego();
        var result = lego.Run($"run {Common()} {Domains(BenchNames.WWW)} {DNSOptions}", RFC2136);

        Assert.That(DNS!.AddedTXT, Has.Some.Contains($"_acme-challenge.{BenchNames.WWW}"), $"BIND took no TXT record of lego's:\n{DNS.Log}\n{result}");

    }

    /// <summary>
    /// A certificate by dns-01: the record in BIND, the server reading it
    /// through its DNSClient pointed there.
    /// </summary>
    [TestCase(BenchNames.WWW)]
    [TestCase("*.acme.test")]
    [Property("RFC", "8555 §8.4, §7.1.3")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "V-1")]
    public async Task Lego_Gets_A_Certificate_By_dns01(String Name)
    {

        await StartAsync(DNS: true);

        var lego   = NewLego();
        var result = lego.Run($"run {Common()} {Domains(Name)} --key-type EC256 {DNSOptions}", RFC2136);

        AssertIssued(lego.Certificate(Name), [ Name ], "EC", 256, $"{result}\n{DNS!.Log}");

    }

    #endregion

}
