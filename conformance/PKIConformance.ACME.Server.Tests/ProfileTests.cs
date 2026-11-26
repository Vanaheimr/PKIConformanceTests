using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// draft-ietf-acme-profiles-03: the profiles a server issues under, named in
/// its directory and chosen by an order - <i>"If the server rejects the
/// newOrder request due to the requested profile, the server MUST respond
/// with a problem document of type "invalidProfile""</i>, <i>"If it accepts
/// the request, the server responds with an Order object including the
/// selected profile."</i>
/// </summary>
/// <remarks>
/// Let's Encrypt issues its six-day certificates under a profile, and lego
/// and certbot ask for one: a server that does not say which profile an
/// order got leaves a client not knowing what it will be issued.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "draft-ietf-acme-profiles-03")]
public class ProfileTests(String ServerName) : ACMEServerFixture(ServerName)
{

    protected override ACMEServerOptions Options(UInt16 HTTP01Port)
        => new (HTTP01Port: HTTP01Port, Profiles: new Dictionary<String, Int32> { ["shortlived"] = 7, ["classic"] = 90 });

    private Task<RawACMEResponse> OrderAsync(RawACMEAccount Account, String? Profile)

        => Client.PostAsync(Account, Client.Resource("newOrder"),
                            Profile is null
                                ? RawJson.Object(("identifiers", RawACMEClient.IdentifiersJSON([ Loopback4 ])))
                                : RawJson.Object(("identifiers", RawACMEClient.IdentifiersJSON([ Loopback4 ])), ("profile", RawJson.Quote(Profile))));


    /// <summary>
    /// Section 3: <i>"profiles (optional, object): A map of profile names to
    /// URLs."</i> - <i>"CAs MAY use data URIs [RFC2397] to provide an in-line
    /// text description"</i>. (Up to -01 of the draft the values were
    /// descriptions; -02 made them URLs.)
    /// </summary>
    [Test]
    [Property("RFC", "draft-ietf-acme-profiles-03 §3")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-12")]
    public void The_Directory_Names_Its_Profiles_With_URLs()
    {

        var profiles = Client.Directory["meta"]?["profiles"]?.AsObject();

        Assert.That(profiles, Is.Not.Null, Client.Directory.ToJsonString());

        Assert.Multiple(() => {
            Assert.That(profiles!.Select(profile => profile.Key), Is.SupersetOf(new[] { "shortlived", "classic" }));
            foreach (var (name, value) in profiles!)
                Assert.That(Uri.IsWellFormedUriString(value?.GetValue<String>(), UriKind.Absolute), Is.True, $"\"{name}\": {value?.ToJsonString()} is a URL");
        });

    }

    /// <summary>
    /// Section 4: <i>"If it accepts the request, the server responds with an
    /// Order object including the selected profile."</i> - in the answer, and
    /// whenever the order is read.
    /// </summary>
    [TestCase("shortlived")]
    [TestCase("classic")]
    [Property("RFC", "draft-ietf-acme-profiles-03 §4")]
    [Property("Level", "MUST")]
    public async Task An_Order_Of_A_Profile_Says_Its_Profile(String Profile)
    {

        var account = await NewAccountAsync();
        var answer  = await OrderAsync(account, Profile);
        var later   = answer.Location is String url ? await Client.PostAsGetAsync(account, url) : answer;

        Assert.Multiple(() => {
            AssertStatus(answer, 201);
            Assert.That(answer.StringOf("profile"), Is.EqualTo(Profile), answer.ToString());
            Assert.That(later.StringOf("profile"),  Is.EqualTo(Profile), later.ToString());
        });

    }

    /// <summary>
    /// Section 4: <i>"The server SHOULD reject all newOrder requests which
    /// specify a profile that the server is not advertising"</i> - and
    /// <i>"If the server rejects the newOrder request due to the requested
    /// profile, the server MUST respond with a problem document of type
    /// "invalidProfile""</i>.
    /// </summary>
    [TestCase("never-heard-of")]
    [TestCase("SHORTLIVED")]
    [Property("RFC", "draft-ietf-acme-profiles-03 §4")]
    [Property("Level", "MUST")]
    public async Task An_Order_Of_A_Profile_It_Does_Not_Advertise_Is_invalidProfile(String Profile)
    {

        var account = await NewAccountAsync();

        AssertProblem(await OrderAsync(account, Profile), 400, "invalidProfile");

    }

    /// <summary>
    /// Section 4: the profile <i>"will be used to affect issuance of the
    /// certificate requested by this Order"</i> - one of seven days is not
    /// one of ninety.
    /// </summary>
    [Test]
    [Property("RFC", "draft-ietf-acme-profiles-03 §4")]
    [Property("Level", "MUST")]
    public async Task The_Certificate_Is_Of_Its_Profile()
    {

        var account  = await NewAccountAsync();
        var answer   = await OrderAsync(account, "shortlived");
        var order    = new RawACMEOrder(answer.Location!, answer.Object!);

        foreach (var authorization in order.Authorizations)
            await Client.ProveHTTP01Async(account, authorization, Host);

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await Client.FinalizeAsync(account, await Client.RefreshAsync(account, order), RawCSR.CreateBase64Url(key, [ Loopback4 ]));

        var done     = await Client.PollWhileAsync(account, order.URL, "processing", "ready");
        var chain    = await Client.PostAsGetAsync(account, done.StringOf("certificate")!);
        using var leaf = X509Certificate2.CreateFromPem(chain.Text);

        Assert.That(leaf.NotAfter - leaf.NotBefore, Is.LessThanOrEqualTo(TimeSpan.FromDays(8)), $"{leaf.NotBefore:u} - {leaf.NotAfter:u}");

    }

}

/// <summary>
/// draft-ietf-acme-profiles-03, section 4: <i>"If the server is advertizing
/// profiles and receives a newOrder request which does not identify a
/// specific profile, it is RECOMMENDED that the server select a profile and
/// associate it with the new Order object."</i> - of a server that has no
/// default.
/// </summary>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "draft-ietf-acme-profiles-03 §4")]
public class ProfileWithoutDefaultTests(String ServerName) : ACMEServerFixture(ServerName)
{

    protected override ACMEServerOptions Options(UInt16 HTTP01Port)
        => new (HTTP01Port: HTTP01Port, Profiles: new Dictionary<String, Int32> { ["shortlived"] = 7 }, DefaultProfile: false);

    [Test]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-13")]
    public async Task An_Order_Without_A_Profile_Gets_One()
    {

        var account = await NewAccountAsync();
        var answer  = await Client.NewOrderAsync(account, Loopback4);

        Assert.Multiple(() => {
            AssertStatus(answer, 201);
            Assert.That(answer.StringOf("profile"), Is.EqualTo("shortlived"), answer.ToString());
        });

    }

}
