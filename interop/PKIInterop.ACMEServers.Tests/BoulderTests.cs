using System.Security.Cryptography;
using System.Text.Json.Nodes;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.RawACME;

namespace PKIInterop.ACMEServers.Tests;

/// <summary>
/// Hermod's ACME client and certificate manager against Boulder - Let's
/// Encrypt's own server, its whole stack in Docker at the pinned tag: the
/// strongest evidence of what Let's Encrypt makes of Hermod.
/// </summary>
/// <remarks>
/// <para>
/// One Boulder for the fixture - it takes minutes to start - and an account
/// and random names below "le.wtf" for every test, which Boulder's test
/// configuration exempts from its limits. http-01 reaches Hermod's responder
/// through the forwarder of port 80 on Boulder's "public" network
/// (<see cref="Boulder"/>); dns-01 goes into the challtestsrv of the stack.
/// </para>
/// <para>
/// What this Boulder lacks has no test (principle 7): external account
/// binding (Let's Encrypt has none) and alternate chains of Pebble's kind.
/// Addresses it validates only in its "shortlived" profile, and public ones.
/// </para>
/// </remarks>
[Category(TestCategories.Docker)]
[Property("RFC", "8555 §7, §8; 8738; 9773")]
public sealed class BoulderTests : ServerFixture
{

    #region Bench

    private Boulder? boulder;

    /// <inheritdoc/>
    protected override String[] Tools
        => [ "docker", "dig", "openssl", "curl" ];

    /// <inheritdoc/>
    protected override String   PeerName
        => Boulder.Name;

    /// <summary>Boulder reaches the responder from its network: every address of the host.</summary>
    protected override IPv4Address ResponderAddress
        => IPv4Address.Any;

    /// <summary>A contact of a public suffix: Boulder refuses one of ".test".</summary>
    protected override String[] Contacts
        => [ "admin@le.wtf" ];

    [OneTimeSetUp]
    public void StartBoulder()
    {

        TestEnvironment.RequireDocker();

        if (!Boulder.IsInstalled)
            Assert.Ignore($"{Boulder.Name} is not installed: wsl -u root sh build/peers/setup-wsl.sh --with-boulder");

        boulder = Boulder.Start();

    }

    [OneTimeTearDown]
    public void StopBoulder()
        => boulder?.Dispose();

    [SetUp]
    public void UseBoulder()
        => Use(boulder!.ForTest(HTTP01Port));

    /// <summary>A name of its own for a test: Boulder counts certificates by name.</summary>
    private static String RandomName()
        => $"rand{Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6))}.le.wtf";

    #endregion


    #region Accounts (RFC 8555, section 7.3)

    [Test, Property("RFC", "8555 §7.3"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodAccount)]
    public async Task An_Account_Is_Opened_With_A_Contact_And_The_Terms()
    {

        var client    = NewClient();
        var directory = await client.GetDirectoryAsync();
        var account   = await client.CreateAccountAsync(Contacts, TermsOfServiceAgreed: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(directory.TermsOfService, Is.Not.Null,        $"Boulder has terms: {Evidence}");
            Assert.That(account.Created,          Is.True,            Evidence);
            Assert.That(account.Status,           Is.EqualTo("valid"), Evidence);
        }

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.3.1"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodAccountFound)]
    public async Task The_Same_Key_Finds_The_Same_Account()
    {

        using var key    = ACMEAccountKey.Generate();
        var       opened = await NewClient(key).CreateAccountAsync(Contacts, TermsOfServiceAgreed: true);
        var       found  = await NewClient(key).FindAccountAsync();

        Assert.That(found?.URL, Is.EqualTo(opened.URL), $"onlyReturnExisting finds it: {Evidence}");

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.3.1"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodAccountNone)]
    public async Task A_Key_Without_An_Account_Finds_None()

        => Assert.That(await NewClient().FindAccountAsync(), Is.Null, Evidence);

    #endregion


    #region http-01 and dns-01 (RFC 8555, sections 8.3 and 8.4; RFC 8738)

    [Test, Property("RFC", "8555 §8.3"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodHttp01)]
    public async Task A_Name_By_http01()
    {

        var name        = RandomName();
        var certificate = await (await ClientWithAccountAsync()).ObtainCertificateAsync([ name ], [ HTTP01 ]);

        await AssertIssuedAsync(certificate, [ name ]);

        Assert.That(HTTP01.Open, Is.Zero, "the answers taken away again");

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.4"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodHttp01Sixteen)]
    public async Task Sixteen_Names_By_http01()
    {

        var names       = Enumerable.Range(0, 16).Select(_ => RandomName()).ToArray();
        var certificate = await (await ClientWithAccountAsync()).ObtainCertificateAsync(names, [ HTTP01 ]);

        await AssertIssuedAsync(certificate, names);

    }

    [Test, Property("RFC", "8555 §8.4"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodDns01)]
    public async Task A_Name_By_dns01()
    {

        var name        = RandomName();
        var certificate = await (await ClientWithAccountAsync()).ObtainCertificateAsync([ name ], [ DNS01 ]);

        await AssertIssuedAsync(certificate, [ name ]);

        Assert.That(Server.DNS.Query($"_acme-challenge.{name}", "TXT"), Is.Empty, "the record taken away again");

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.1.3"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodWildcard)]
    public async Task A_Wildcard_By_dns01_And_Its_Base_By_http01()
    {

        var name        = RandomName();
        var certificate = await ObtainAsync(await ClientWithAccountAsync(), $"*.{name}", name);

        await AssertIssuedAsync(certificate, [ $"*.{name}", name ]);

    }

    [Test, Property("RFC", "8738 §3"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodIPv4)]
    public async Task An_IPv4_Address_By_http01_In_The_Shortlived_Profile()
    {

        var certificate = await (await ClientWithAccountAsync()).ObtainCertificateAsync([ boulder!.ForwarderIP ], [ HTTP01 ], Profile: "shortlived");

        await AssertIssuedAsync(certificate, [ boulder!.ForwarderIP ]);

    }

    [TestCase(ACMEKeyType.ECDSA_P256, "EC",  256)]
    [TestCase(ACMEKeyType.ECDSA_P384, "EC",  384)]
    [TestCase(ACMEKeyType.RSA_2048,   "RSA", 2048)]
    [TestCase(ACMEKeyType.RSA_4096,   "RSA", 4096)]
    [Property("RFC", "8555 §7.4"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodCertificateKeys)]
    public async Task Every_Kind_Of_Certificate_Key(ACMEKeyType KeyType, String Algorithm, Int32 Size)
    {

        var name        = RandomName();
        var certificate = await (await ClientWithAccountAsync()).ObtainCertificateAsync([ name ], Responders, KeyType);

        await AssertIssuedAsync(certificate, [ name ], Algorithm, Size);

    }

    #endregion


    #region Profiles (draft-ietf-acme-profiles)

    [Test, Property("RFC", "draft-ietf-acme-profiles §4"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodProfileIssued)]
    public async Task A_Profile_Is_Asked_For_And_Issued()
    {

        var name        = RandomName();
        var client      = await ClientWithAccountAsync();
        var directory   = await client.GetDirectoryAsync();
        var legacy      = await client.ObtainCertificateAsync([ name ], Responders);
        var shortlived  = await client.ObtainCertificateAsync([ name ], Responders, Profile: "shortlived");

        await AssertIssuedAsync(shortlived, [ name ]);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(directory.Profiles.Keys,                     Does.Contain("shortlived"),                 "Boulder advertises it");
            Assert.That(shortlived.NotAfter - shortlived.NotBefore,  Is.LessThan(legacy.NotAfter - legacy.NotBefore), "shorter than the default profile's");
        }

        AssertWire();

    }

    [Test, Property("RFC", "draft-ietf-acme-profiles §4"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodProfileUnknown)]
    public async Task An_Unknown_Profile_Is_Refused_In_Boulders_Words()
    {

        var client  = await ClientWithAccountAsync();
        var refused = await Assert.ThrowsAsync<ACMEException>(() => client.ObtainCertificateAsync([ RandomName() ], Responders, Profile: "no-such-profile"));

        Assert.That(refused?.Problem?.ShortType, Is.AnyOf("invalidProfile", "malformed"), $"{refused?.Problem}: {Evidence}");

    }

    /// <summary>
    /// <i>"Clients SHOULD NOT request a profile that the server does not
    /// advertise"</i> - C-7, seen against Boulder.
    /// </summary>
    [Test, Property("RFC", "draft-ietf-acme-profiles §4"), Property("Level", "SHOULD NOT")]
    [Category(TestCategories.KnownIssue), Property("Finding", "C-7")]
    [Cell(InteropCells.HermodProfileUnadvertised)]
    public async Task No_Profile_Boulder_Does_Not_Advertise_Is_Asked_For()
    {

        var client = await ClientWithAccountAsync();

        try
        {
            await client.ObtainCertificateAsync([ RandomName() ], Responders, Profile: "no-such-profile");
        }
        catch (Exception e) when (e is ACMEException or ArgumentException) { }

        var asked = Wire.Exchanges.Where(exchange => exchange.Method == "POST" &&
                                                     exchange.RequestBody.Length > 0 &&
                                                     RawJWS.ParseFlattened(exchange.RequestBody).PayloadJSON is { Length: > 0 } payload &&
                                                     JsonNode.Parse(payload)?["profile"] is not null).ToArray();

        Assert.That(asked, Is.Empty, $"Boulder advertises legacy, modern and shortlived only: {Evidence}");

    }

    #endregion


    #region Revocation (RFC 8555, section 7.6)

    [Test, Property("RFC", "8555 §7.6"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodAlreadyRevoked)]
    public async Task A_Revoked_Certificate_Revoked_Again_Is_alreadyRevoked()
    {

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client, RandomName());

        await client.RevokeCertificateAsync(certificate.Certificate, Reason: 4);

        var refused     = await Assert.ThrowsAsync<ACMEException>(() => client.RevokeCertificateAsync(certificate.Certificate, Reason: 4));

        Assert.That(refused?.Problem?.ShortType, Is.EqualTo("alreadyRevoked"), $"Boulder holds it revoked: {refused?.Problem}\n{Evidence}");

        AssertWire();

    }

    #endregion


    #region ARI (RFC 9773)

    [Test, Property("RFC", "9773 §4.2"), Property("Level", "MUST")]
    [Cell(InteropCells.HermodARIWindow)]
    public async Task The_Renewal_Window_Lies_In_The_Certificates_Lifetime()
    {

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client, RandomName());
        var window      = await client.GetRenewalInfoAsync(certificate.Certificate);

        Assert.That(window, Is.Not.Null, $"Boulder's directory has renewalInfo: {Evidence}");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(window!.Start, Is.LessThan(window.End),                         $"{window}");
            Assert.That(window.Start,  Is.GreaterThanOrEqualTo(certificate.NotBefore), $"{window}");
            Assert.That(window.End,    Is.LessThanOrEqualTo(certificate.NotAfter),     $"{window}");
        }

        AssertWire();

    }

    [Test, Property("RFC", "9773 §5"), Property("Level", "SHOULD")]
    [Cell(InteropCells.HermodARIReplaces)]
    public async Task A_Renewal_Says_What_It_Replaces()
    {

        var name    = RandomName();
        var client  = await ClientWithAccountAsync();
        var first   = await ObtainAsync(client, name);
        var renewed = await client.ObtainCertificateAsync([ name ], Responders, Replacing: first.Certificate);

        var sent    = Wire.Exchanges.Where (exchange => exchange.Method == "POST" && exchange.Status == 201 && exchange.ResponseBody.Contains("\"identifiers\"", StringComparison.Ordinal)).
                                     Select(order => JsonNode.Parse(RawJWS.ParseFlattened(order.RequestBody).PayloadJSON)?["replaces"]?.GetValue<String>()).
                                     ToArray();

        await AssertIssuedAsync(renewed, [ name ]);

        Assert.That(sent, Does.Contain(RawARI.CertificateId(first.Certificate.RawData)), $"the second order names the first certificate, and Boulder takes it: {Evidence}");

        AssertWire();

    }

    [Test, Property("RFC", "9773 §4.2"), Property("Level", "SHOULD")]
    [Cell(InteropCells.ManagerRenewsByARI)]
    public async Task The_Manager_Renews_When_Boulders_Window_Is_Due()
    {

        var client = await ClientWithAccountAsync();

        await using var manager = new ACMECertificateManager(client, [ RandomName() ], Responders);

        Assert.That(await manager.StartAsync(), Is.True, $"{manager.LastError}: {Evidence}");

        var first  = manager.Certificate!;

        // Revoked for a compromised key, a certificate is due at once: Boulder says so by its window.
        await client.RevokeCertificateAsync(first.Certificate, Reason: 1);

        var window = await client.GetRenewalInfoAsync(first.Certificate);
        var due    = await manager.WhenDueAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(window?.Start, Is.LessThanOrEqualTo(DateTimeOffset.UtcNow), $"Boulder moves the window of a revoked certificate into the past: {window}");
            Assert.That(due,           Is.LessThanOrEqualTo(DateTimeOffset.UtcNow), $"the manager takes the window: {window}");
        }

    }

    #endregion


    #region The certificate manager

    [Test, Property("Level", "—")]
    [Cell(InteropCells.ManagerFiles)]
    public async Task The_Manager_Keeps_A_Certificate_In_Files()
    {

        var name      = RandomName();
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-manager-{Guid.NewGuid():N}")).FullName;

        try
        {

            await using var manager = new ACMECertificateManager(await ClientWithAccountAsync(), [ name ], Responders, Directory: directory);

            Assert.That(await manager.StartAsync(), Is.True, $"{manager.LastError}: {Evidence}");

            var kept = ACMECertificate.FromPem(File.ReadAllText(manager.FullChainPath!), File.ReadAllText(manager.PrivateKeyPath!));

            await AssertIssuedAsync(kept, [ name ]);

        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }

    }

    #endregion

}
