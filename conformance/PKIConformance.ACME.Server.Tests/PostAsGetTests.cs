using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 6.3: <i>"Except for the cases described in this section,
/// if the server receives a GET request, it MUST return an error with status
/// code 405 (Method Not Allowed) and type "malformed".</i> [...] <i>The server
/// MUST allow GET requests for the directory and newNonce resources (see
/// Section 7.1), in addition to POST-as-GET requests for these resources."</i>
/// </summary>
/// <remarks>
/// A GET is not authenticated: a server that answers one with an order or an
/// authorization tells it to whoever asks. And a client that bootstraps
/// with POST-as-GET throughout - as section 6.3 allows it to - is stuck at
/// the directory of a server that only takes GET there.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §6.3")]
public class PostAsGetTests(String ServerName) : ACMEServerFixture(ServerName)
{

    private RawACMEAccount  account   = null!;
    private RawACMEOrder    order     = null!;
    private RawACMEResponse authorization = null!;

    [OneTimeSetUp]
    public async Task Arrange()
    {
        account        = await NewAccountAsync();
        order          = await Client.OrderAsync(account, Loopback4);
        authorization  = await Client.PostAsGetAsync(account, order.Authorizations[0]);
    }

    /// <summary>
    /// The resources a GET is no request of: those of the directory but
    /// newNonce, and those an account was given.
    /// </summary>
    private String URLOf(String Resource)

        => Resource switch {
               "account"        => account.URL,
               "order"          => order.URL,
               "authorization"  => order.Authorizations[0],
               "challenge"      => RawACMEClient.ChallengeOf(authorization, "http-01")?.URL ?? throw new InvalidOperationException($"no http-01: {authorization}"),
               "finalize"       => order.Finalize,
               _                => Client.Resource(Resource)
           };

    /// <summary>
    /// A GET of a resource that is fetched by POST-as-GET, or of one that is
    /// only POSTed to: 405, of the type "malformed".
    /// </summary>
    [TestCase("newAccount")]
    [TestCase("newOrder")]
    [TestCase("revokeCert")]
    [TestCase("keyChange")]
    [TestCase("account")]
    [TestCase("order")]
    [TestCase("authorization")]
    [TestCase("challenge")]
    [TestCase("finalize")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-4")]
    public async Task A_GET_Is_Answered_405_malformed(String Resource)

        => AssertProblem(await Client.SendAsync(HttpMethod.Get, URLOf(Resource)), 405, "malformed");

    /// <summary>
    /// <i>"The server MUST allow GET requests for the directory and newNonce
    /// resources (see Section 7.1), in addition to POST-as-GET requests for
    /// these resources."</i> - a POST-as-GET of the directory, by an account.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-5")]
    public async Task A_POST_as_GET_Of_The_Directory_Is_Answered_With_The_Directory()
    {

        var answer = await Client.PostAsGetAsync(account, Client.DirectoryURL.ToString());

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(answer.StringOf("newNonce"), Is.EqualTo(Client.Resource("newNonce")), answer.ToString());
        });

    }

    /// <summary>
    /// <i>"The server MUST allow GET requests for the directory and newNonce
    /// resources (see Section 7.1), in addition to POST-as-GET requests for
    /// these resources."</i> - a POST-as-GET of newNonce, by an account: a nonce.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-5")]
    public async Task A_POST_as_GET_Of_newNonce_Is_Answered_With_A_Nonce()
    {

        var answer = await Client.PostAsGetAsync(account, Client.Resource("newNonce"));

        Assert.Multiple(() => {
            Assert.That(answer.Status,       Is.InRange(200, 299), answer.ToString());
            Assert.That(answer.ReplayNonce,  Is.Not.Null,          answer.ToString());
        });

    }

    /// <summary>
    /// <i>"On receiving a request with a zero-length (and thus non-JSON)
    /// payload, the server MUST authenticate the sender and verify any access
    /// control rules. Otherwise, the server MUST treat this request as having
    /// the same semantics as a GET request for the same resource."</i> - a
    /// POST-as-GET of the order answers the order, and changes nothing.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_POST_as_GET_Of_An_Order_Is_Answered_With_The_Order_Unchanged()
    {

        var first   = await Client.PostAsGetAsync(account, order.URL);
        var second  = await Client.PostAsGetAsync(account, order.URL);

        Assert.Multiple(() => {
            AssertStatus(first, 200);
            Assert.That(first.StringOf("status"),             Is.EqualTo("pending"),                 first.ToString());
            Assert.That(first.StringsOf("authorizations"),    Is.EqualTo(order.Authorizations),      first.ToString());
            Assert.That(second.Text,                          Is.EqualTo(first.Text),                "the same, asked again");
        });

    }

    /// <summary>
    /// A POST-as-GET of an authorization does not answer its challenge - an
    /// empty payload is no "{}" (section 7.5.1).
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.3, §7.5.1")]
    [Property("Level", "MUST")]
    public async Task A_POST_as_GET_Of_A_Challenge_Does_Not_Start_Its_Validation()
    {

        var (other, pending) = await PendingOrderAsync();
        var authz            = await Client.PostAsGetAsync(other, pending.Authorizations[0]);
        var challenge        = RawACMEClient.ChallengeOf(authz, "http-01")!.Value;

        var answer           = await Client.PostAsGetAsync(other, challenge.URL);
        await Task.Delay(500);
        var after            = await Client.PostAsGetAsync(other, challenge.URL);

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(after.StringOf("status"),                                                  Is.EqualTo("pending"), after.ToString());
            Assert.That(Host.RequestsOf(ScriptedChallengeHost.ChallengePath(challenge.Token)),     Is.Empty,              "the host was never asked");
        });

    }

}
