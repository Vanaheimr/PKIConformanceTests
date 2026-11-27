using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.RawACME;

namespace PKIInterop.ACMEServers.Tests;

/// <summary>
/// Hermod's ACME client and certificate manager against Pebble - the gate of
/// interop B (PLAN.md, section 4.6): Pebble exists to catch what a client
/// assumes, and varies on purpose what a client must not depend on.
/// </summary>
/// <remarks>
/// <para>
/// <i>"Pebble is a small RFC 8555 ACME test server not suited for a
/// production certificate authority."</i> Every test starts one of its own,
/// with a challtestsrv of its own that answers every name with the loopback,
/// validating http-01 at the port of Hermod's responder and dns-01 by the
/// records Hermod's dns-01 responder writes. Every certificate is judged
/// against the root Pebble's management API hands out, by .NET and openssl;
/// every request by RawACME.
/// </para>
/// <para>
/// The same tests run against Debian 13's Pebble 2.6.0 and upstream's at its
/// pin; profiles only against upstream's - 2.6.0 has none (principle 7).
/// </para>
/// </remarks>
[Category(TestCategories.Wsl)]
[Property("RFC", "8555 §7, §8; 8738; 9773")]
public abstract class PebbleTests(Func<PebbleBuild> Build) : ServerFixture
{

    #region Bench

    /// <inheritdoc/>
    protected override String[] Tools
        => [ Build().Binary, Build().ChallTestSrvBinary, "openssl", "dig" ];

    /// <summary>A Pebble of the build, validating http-01 at Hermod's responder.</summary>
    protected Pebble StartPebble(PebbleOptions? Options = null)
        => Use(Pebble.Start(Build(), HTTP01Port, Options));

    #endregion


    #region Accounts (RFC 8555, section 7.3)

    [Test, Property("RFC", "8555 §7.3"), Property("Level", "MUST")]
    public async Task An_Account_Is_Opened_With_A_Contact_And_The_Terms()
    {

        StartPebble();

        var client  = NewClient();
        var account = await client.CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(account.Created,   Is.True,                                  Evidence);
            Assert.That(account.Status,    Is.EqualTo("valid"),                      Evidence);
            Assert.That(account.Contacts,  Is.EqualTo(new[] { "mailto:admin@acme.test" }), Evidence);
            Assert.That(client.AccountURL, Is.EqualTo(account.URL),                  Evidence);
        }

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.3.1"), Property("Level", "MUST")]
    public async Task The_Same_Key_Finds_The_Same_Account()
    {

        StartPebble();

        using var key    = ACMEAccountKey.Generate();
        var       opened = await NewClient(key).CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);
        var       found  = await NewClient(key).FindAccountAsync();
        var       again  = await NewClient(key).CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found?.URL,    Is.EqualTo(opened.URL), $"onlyReturnExisting finds it: {Evidence}");
            Assert.That(again.URL,     Is.EqualTo(opened.URL), $"newAccount of the same key answers with it: {Evidence}");
            Assert.That(again.Created, Is.False,               $"and says it was there: {Evidence}");
        }

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.3.1"), Property("Level", "MUST")]
    public async Task A_Key_Without_An_Account_Finds_None()
    {

        StartPebble();

        Assert.That(await NewClient().FindAccountAsync(), Is.Null, Evidence);

    }

    [Test, Property("RFC", "8555 §7.3.4"), Property("Level", "MUST")]
    public async Task An_External_Account_Is_Bound()
    {

        var mac = RawBase64Url.Encode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

        StartPebble(new PebbleOptions { EABKeys = new Dictionary<String, String> { ["kid-1"] = mac } });

        var account = await NewClient().CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true, EABKeyId: "kid-1", EABHMACKey: mac);

        Assert.That(account.Status, Is.EqualTo("valid"), Evidence);

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.3.4"), Property("Level", "MUST")]
    public async Task Without_A_Binding_Hermod_Says_So_And_Sends_Nothing()
    {

        StartPebble(new PebbleOptions { EABKeys = new Dictionary<String, String> { ["kid-1"] = RawBase64Url.Encode(new Byte[32]) } });

        var refused = await Assert.ThrowsAsync<ACMEException>(() => NewClient().CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused?.Message,                         Does.Contain("external account binding"), Evidence);
            Assert.That(Wire.Exchanges.Where(e => e.Method == "POST"), Is.Empty,                               $"no newAccount sent: {Evidence}");
        }

    }

    [Test, Property("RFC", "8555 §7.3.4"), Property("Level", "MUST")]
    public async Task A_Binding_Of_A_Wrong_MAC_Is_Refused_In_Pebbles_Words()
    {

        StartPebble(new PebbleOptions { EABKeys = new Dictionary<String, String> { ["kid-1"] = RawBase64Url.Encode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)) } });

        var refused = await Assert.ThrowsAsync<ACMEException>(() => NewClient().CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true,
                                                                                               EABKeyId: "kid-1", EABHMACKey: RawBase64Url.Encode(new Byte[32])));

        Assert.That(refused?.Problem?.ShortType, Is.AnyOf("unauthorized", "malformed"), $"{refused?.Problem}: {Evidence}");

    }

    #endregion


    #region http-01 and dns-01 (RFC 8555, sections 8.3 and 8.4; RFC 8738)

    [Test, Property("RFC", "8555 §8.3"), Property("Level", "MUST")]
    public async Task A_Name_By_http01()
    {

        StartPebble();

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), Name);

        await AssertIssuedAsync(certificate, [ Name ]);

        Assert.That(HTTP01.Open, Is.Zero, "the answers taken away again");

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.4"), Property("Level", "MUST")]
    public async Task Sixteen_Names_By_http01()
    {

        StartPebble();

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), [ .. BenchNames.Numbered ]);

        await AssertIssuedAsync(certificate, BenchNames.Numbered);

    }

    [Test, Property("RFC", "8555 §8.4"), Property("Level", "MUST")]
    public async Task A_Name_By_dns01()
    {

        StartPebble();

        var client      = await ClientWithAccountAsync();
        var certificate = await client.ObtainCertificateAsync([ Name ], [ DNS01 ]);

        await AssertIssuedAsync(certificate, [ Name ]);

        Assert.That(Server.DNS.Query($"_acme-challenge.{Name}", "TXT"), Is.Empty, $"the record taken away again: {Server.DNS.Log}");

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.1.3"), Property("Level", "MUST")]
    public async Task A_Wildcard_By_dns01_And_Its_Base_By_http01()
    {

        StartPebble();

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), "*.acme.test", "acme.test");

        await AssertIssuedAsync(certificate, [ "*.acme.test", "acme.test" ]);

        Assert.That(Server.DNS.Log, Does.Contain("_acme-challenge.acme.test."), "the wildcard proven by dns-01");

    }

    [Test, Property("RFC", "8738 §3"), Property("Level", "MUST")]
    public async Task An_IPv4_Address_By_http01()
    {

        StartPebble();

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), "127.0.0.1");

        await AssertIssuedAsync(certificate, [ "127.0.0.1" ]);

    }

    [Test, Property("RFC", "8738 §3"), Property("Level", "MUST")]
    public async Task An_IPv6_Address_By_http01()
    {

        Assume.That(Port80v6, Is.Not.Null, "no Hermod HTTP server at [::1]");

        StartPebble();

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

        StartPebble();

        var certificate = await (await ClientWithAccountAsync()).ObtainCertificateAsync([ Name ], Responders, KeyType);

        await AssertIssuedAsync(certificate, [ Name ], Algorithm, Size);

    }

    #endregion


    #region Pebble's deliberate variation

    /// <summary>
    /// <i>"On receiving such a response, a client SHOULD retry the request
    /// using the new nonce"</i> (RFC 8555, section 6.5) - and Pebble refuses
    /// half or nine in ten of all good nonces. Hermod retries three times:
    /// what is judged is that it does so with the nonce of the answer, the
    /// same request again, and never a nonce twice - and that it gives up,
    /// where it does, with the server's badNonce in hand, after the fourth.
    /// </summary>
    [TestCase(50)]
    [TestCase(90)]
    [Property("RFC", "8555 §6.5"), Property("Level", "SHOULD")]
    public async Task A_Storm_Of_badNonce(Int32 Percent)
    {

        StartPebble(new PebbleOptions { NonceReject = Percent });

        Exception? failure = null;

        try
        {
            await ObtainAsync(await ClientWithAccountAsync(), Name);
        }
        catch (ACMEException e)
        {
            failure = e;
        }

        var posts     = Wire.Exchanges.Where(exchange => exchange.Method == "POST").ToArray();
        var refusals  = posts.Count(exchange => exchange.ProblemType == "urn:ietf:params:acme:error:badNonce");

        // A run of refusals of one request: the longest one.
        var longest   = 0;
        var run       = 0;

        foreach (var exchange in posts)
        {
            run     = exchange.ProblemType == "urn:ietf:params:acme:error:badNonce" ? run + 1 : 0;
            longest = Math.Max(longest, run);
        }

        using (Assert.EnterMultipleScope())
        {

            Assert.That(refusals, Is.Positive, $"Pebble refused {Percent} % of the nonces, and none of {posts.Length}: {Evidence}");

            if (failure is null)
                Assert.That(longest, Is.LessThanOrEqualTo(3), $"issued, no run of refusals longer than the three retries: {Evidence}");
            else
            {
                Assert.That(failure is ACMEException { Problem.ShortType: "badNonce" }, Is.True, $"given up with Pebble's badNonce in hand, not another error: {failure}\n{Evidence}");
                Assert.That(longest, Is.EqualTo(4),                                       $"given up after the fourth refusal of one request: {Evidence}");
            }

        }

        AssertWire();

    }

    [TestCase(1)]
    [TestCase(2)]
    [TestCase(4)]
    [Property("RFC", "8555 §7.4.2"), Property("Level", "MUST")]
    public async Task Chains_Of_Every_Length(Int32 Intermediates)
    {

        StartPebble(new PebbleOptions { ChainLength = Intermediates });

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), Name);
        var chain       = new X509Certificate2Collection();
        chain.ImportFromPem(certificate.FullChainPem);

        await AssertIssuedAsync(certificate, [ Name ]);

        Assert.That(chain, Has.Count.EqualTo(1 + Intermediates), $"the leaf and every intermediate Pebble sent, in Hermod's fullchain: {certificate.FullChainPem}");

    }

    /// <summary>
    /// Pebble offers alternate chains to other roots in "Link" headers of
    /// "alternate" (RFC 8555, section 7.4.2). Choosing one is T-C6; what
    /// Hermod keeps is the default chain, to root 0.
    /// </summary>
    [Test, Property("RFC", "8555 §7.4.2"), Property("Level", "MAY")]
    public async Task With_Alternate_Roots_The_Default_Chain_Is_Kept()
    {

        StartPebble(new PebbleOptions { AlternateRoots = 2 });

        var certificate = await ObtainAsync(await ClientWithAccountAsync(), Name);
        var download    = Wire.Exchanges.Last(exchange => exchange.Accept?.Contains("pem-certificate-chain", StringComparison.Ordinal) == true);

        await AssertIssuedAsync(certificate, [ Name ], RootPEM: await ((Pebble) Server).RootPEMAsync(0));

        Assert.That(download.Header("Link"), Does.Contain("rel=\"alternate\""), $"Pebble offered alternates: {download}");

    }

    [Test, Property("RFC", "8555 §7.1.3"), Property("Level", "MUST")]
    public async Task A_Reused_Authorization_Is_Not_Proven_Again()
    {

        StartPebble(new PebbleOptions { AuthzReuse = 100 });

        var client = await ClientWithAccountAsync();

        await ObtainAsync(client, Name);
        var challengesBefore = Wire.Exchanges.Count(exchange => exchange.URL.AbsolutePath.Contains("/chalZ/", StringComparison.Ordinal));

        var second = await ObtainAsync(client, Name);
        var challengesAfter  = Wire.Exchanges.Count(exchange => exchange.URL.AbsolutePath.Contains("/chalZ/", StringComparison.Ordinal));

        await AssertIssuedAsync(second, [ Name ]);

        Assert.That(challengesAfter, Is.EqualTo(challengesBefore), $"no challenge answered for the valid authorization Pebble reused: {Evidence}");

        AssertWire();

    }

    #endregion


    #region Revocation (RFC 8555, section 7.6)

    [Test, Property("RFC", "8555 §7.6"), Property("Level", "MUST")]
    public async Task A_Revocation_With_A_Reason_Reaches_Pebble()
    {

        var pebble      = StartPebble();
        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client, Name);

        await client.RevokeCertificateAsync(certificate.Certificate, Reason: 4);

        var status      = await pebble.CertificateStatusAsync(certificate.Certificate);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(status?["Status"]?.GetValue<String>(), Is.EqualTo("Revoked"), $"{status}: {Evidence}");
            Assert.That(status?["Reason"]?.GetValue<Int32>(),  Is.EqualTo(4),         $"superseded: {status}");
        }

        AssertWire();

    }

    [Test, Property("RFC", "8555 §7.6"), Property("Level", "MUST")]
    public async Task A_Certificate_Revoked_Again_Is_alreadyRevoked()
    {

        StartPebble();

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client, Name);

        await client.RevokeCertificateAsync(certificate.Certificate);

        var refused     = await Assert.ThrowsAsync<ACMEException>(() => client.RevokeCertificateAsync(certificate.Certificate));

        Assert.That(refused?.Problem?.ShortType, Is.EqualTo("alreadyRevoked"), $"{refused?.Problem}: {Evidence}");

    }

    #endregion


    #region ARI (RFC 9773)

    [Test, Property("RFC", "9773 §4.2"), Property("Level", "MUST")]
    public async Task The_Renewal_Window_Lies_In_The_Certificates_Lifetime()
    {

        StartPebble();

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client, Name);
        var window      = await client.GetRenewalInfoAsync(certificate.Certificate);

        Assert.That(window, Is.Not.Null, $"Pebble's directory has renewalInfo: {Evidence}");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(window!.Start, Is.LessThan(window.End),                     $"{window}");
            Assert.That(window.Start,  Is.GreaterThanOrEqualTo(certificate.NotBefore), $"{window}");
            Assert.That(window.End,    Is.LessThanOrEqualTo(certificate.NotAfter),    $"{window}");
        }

        AssertWire();

    }

    [Test, Property("RFC", "9773 §5"), Property("Level", "SHOULD")]
    public async Task A_Renewal_Says_What_It_Replaces()
    {

        StartPebble();

        var client  = await ClientWithAccountAsync();
        var first   = await ObtainAsync(client, Name);
        var renewed = await client.ObtainCertificateAsync([ Name ], Responders, Replacing: first.Certificate);

        var orders  = Wire.Exchanges.Where(exchange => exchange.Method == "POST" && exchange.Status == 201 && exchange.ResponseBody.Contains("\"identifiers\"", StringComparison.Ordinal)).ToArray();
        var sent    = orders.Select(order => JsonNode.Parse(RawJWS.ParseFlattened(order.RequestBody).PayloadJSON)?["replaces"]?.GetValue<String>()).ToArray();

        await AssertIssuedAsync(renewed, [ Name ]);

        Assert.That(sent, Does.Contain(RawARI.CertificateId(first.Certificate.RawData)), $"the second order names the first certificate by RawACME's ARI identifier: {Evidence}");

        AssertWire();

    }

    #endregion


    #region The certificate manager

    [Test, Property("Level", "—")]
    public async Task The_Manager_Keeps_A_Certificate_In_Files()
    {

        StartPebble();

        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-manager-{Guid.NewGuid():N}")).FullName;

        try
        {

            var client  = await ClientWithAccountAsync();

            await using var manager = new ACMECertificateManager(client, [ Name ], Responders, Directory: directory);

            Assert.That(await manager.StartAsync(), Is.True, $"{manager.LastError}: {Evidence}");

            var fullChain = File.ReadAllText(manager.FullChainPath!);
            var key       = File.ReadAllText(manager.PrivateKeyPath!);
            var kept      = ACMECertificate.FromPem(fullChain, key);

            await AssertIssuedAsync(kept, [ Name ]);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(kept.Certificate.Thumbprint, Is.EqualTo(manager.Certificate!.Certificate.Thumbprint), "the files hold the certificate presented");
                if (!OperatingSystem.IsWindows())
                    Assert.That(File.GetUnixFileMode(manager.PrivateKeyPath!), Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite), "privkey.pem readable by its owner alone");
            }

        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }

    }

    [Test, Property("RFC", "9773 §4.2"), Property("Level", "SHOULD")]
    public async Task The_Manager_Renews_When_Pebbles_Window_Is_Due()
    {

        StartPebble();

        var client = await ClientWithAccountAsync();

        await using var manager = new ACMECertificateManager(client, [ Name ], Responders);

        Assert.That(await manager.StartAsync(), Is.True, $"{manager.LastError}: {Evidence}");

        var first  = manager.Certificate!;

        // Revoked, a certificate is due at once - where the server says so by its window.
        await client.RevokeCertificateAsync(first.Certificate, Reason: 1);

        var window = await client.GetRenewalInfoAsync(first.Certificate);
        var due    = await manager.WhenDueAsync();

        Assume.That(window is not null && window.Start <= DateTimeOffset.UtcNow, $"{Server.Name} moves the window of a revoked certificate into the past: {window}");

        Assert.That(due, Is.LessThanOrEqualTo(DateTimeOffset.UtcNow), $"the manager takes the window: {window}");

    }

    #endregion

}


/// <summary>
/// Hermod against Debian 13's Pebble, 2.6.0: ARI of draft 03, no profiles.
/// </summary>
public sealed class PebbleDebianTests() : PebbleTests(() => PebbleBuild.Debian);

/// <summary>
/// Hermod against upstream's Pebble at its pin: RFC 9773, profiles.
/// </summary>
public sealed class PebbleUpstreamTests() : PebbleTests(() => PebbleBuild.Upstream)
{

    #region Profiles (draft-ietf-acme-profiles)

    [Test, Property("RFC", "draft-ietf-acme-profiles §4"), Property("Level", "MUST")]
    public async Task A_Profile_Is_Asked_For_And_Issued()
    {

        StartPebble();

        var client      = await ClientWithAccountAsync();
        var directory   = await client.GetDirectoryAsync();
        var certificate = await client.ObtainCertificateAsync([ Name ], Responders, Profile: "shortlived");

        await AssertIssuedAsync(certificate, [ Name ]);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(directory.Profiles.Keys,                                     Does.Contain("shortlived"),                     "Pebble advertises it");
            Assert.That(certificate.NotAfter - certificate.NotBefore,                Is.EqualTo(TimeSpan.FromSeconds(518400)).Within(TimeSpan.FromSeconds(2)), "six days, as the profile has it");
        }

        AssertWire();

    }

    [Test, Property("RFC", "draft-ietf-acme-profiles §4"), Property("Level", "MUST")]
    public async Task An_Unknown_Profile_Is_Refused_In_Pebbles_Words()
    {

        StartPebble();

        var client  = await ClientWithAccountAsync();
        var refused = await Assert.ThrowsAsync<ACMEException>(() => client.ObtainCertificateAsync([ Name ], Responders, Profile: "no-such-profile"));

        Assert.That(refused?.Problem?.ShortType, Is.AnyOf("invalidProfile", "malformed"), $"{refused?.Problem}: {Evidence}");

    }

    /// <summary>
    /// <i>"Clients SHOULD NOT request a profile that the server does not
    /// advertise"</i> - C-7, seen against Pebble.
    /// </summary>
    [Test, Property("RFC", "draft-ietf-acme-profiles §4"), Property("Level", "SHOULD NOT")]
    [Category(TestCategories.KnownIssue), Property("Finding", "C-7")]
    public async Task No_Profile_Pebble_Does_Not_Advertise_Is_Asked_For()
    {

        StartPebble();

        var client = await ClientWithAccountAsync();

        try
        {
            await client.ObtainCertificateAsync([ Name ], Responders, Profile: "no-such-profile");
        }
        catch (Exception e) when (e is ACMEException or ArgumentException) { }

        var asked = Wire.Exchanges.Where(exchange => exchange.Method == "POST" &&
                                                     JsonNode.Parse(RawJWS.ParseFlattened(exchange.RequestBody).PayloadJSON.NullIfEmpty() ?? "{}")?["profile"] is not null).ToArray();

        Assert.That(asked, Is.Empty, $"Pebble advertises default and shortlived only: {Evidence}");

    }

    #endregion

}


internal static class StringExtensions
{
    public static String? NullIfEmpty(this String Text)
        => Text.Length == 0 ? null : Text;
}
