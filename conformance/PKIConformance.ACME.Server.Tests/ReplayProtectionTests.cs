using System.Text;

using NUnit.Framework;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 6.5: <i>"As part of JWS verification, the ACME server
/// MUST verify that the value of the "nonce" header is a value that the
/// server previously provided in a Replay-Nonce header field. Once a nonce
/// value has appeared in an ACME request, the server MUST consider it
/// invalid, in the same way as a value it had never issued."</i> [...]
/// <i>"When a server rejects a request because its nonce value was
/// unacceptable (or not present), it MUST provide HTTP status code 400 (Bad
/// Request), and indicate the ACME error type
/// "urn:ietf:params:acme:error:badNonce". An error response with the
/// "badNonce" error type MUST include a Replay-Nonce header field with a fresh
/// nonce that the server will accept in a retry of the original query"</i>.
/// </summary>
/// <remarks>
/// A server that takes a nonce twice takes a request twice: a revocation, a
/// key change, a deactivation that somebody saw go by.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §6.5")]
public class ReplayProtectionTests(String ServerName) : ACMEServerFixture(ServerName)
{

    private RawACMEAccount account = null!;

    [OneTimeSetUp]
    public async Task Arrange()
        => account = await NewAccountAsync();


    /// <summary>
    /// A request without "nonce": badNonce, 400, with a fresh nonce.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_Without_A_Nonce_Is_badNonce_With_A_Fresh_One()
    {

        var answer = await Client.PostAsync(account, account.URL, null, Header: header => header.Remove("nonce"));

        Assert.Multiple(() => {
            AssertProblem(answer, 400, "badNonce");
            Assert.That(answer.ReplayNonce, Is.Not.Null, answer.ToString());
        });

    }

    /// <summary>
    /// A nonce the server never gave: badNonce.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Nonce_It_Never_Gave_Is_badNonce()
    {

        var made   = RawBase64Url.Encode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(18));
        var answer = await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("nonce", made));

        AssertProblem(answer, 400, "badNonce");

    }

    /// <summary>
    /// The same request sent twice - its nonce once used: the second time it
    /// is badNonce, and nothing of it happens again.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Request_Sent_Again_Is_badNonce()
    {

        var jws     = await Client.SignAsync(account.Key, account.URL, account.URL, null);
        var body    = Encoding.UTF8.GetBytes(jws.ToFlattenedJSON());

        var first   = await Client.SendAsync(HttpMethod.Post, account.URL, body);
        var second  = await Client.SendAsync(HttpMethod.Post, account.URL, body);

        Assert.Multiple(() => {
            AssertStatus(first, 200);
            AssertProblem(second, 400, "badNonce");
        });

    }

    /// <summary>
    /// A nonce used by a request that failed for another reason is used: it
    /// <i>"has appeared in an ACME request"</i>.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Nonce_Of_A_Refused_Request_Is_Used_Up()
    {

        var nonce   = await Client.FreshNonceAsync();

        var refused = await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("nonce", nonce).SetString("url", account.URL + "/"));
        var again   = await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("nonce", nonce));

        Assert.Multiple(() => {
            AssertRefused(refused);
            AssertProblem(again, 400, "badNonce");
        });

    }

    /// <summary>
    /// Section 6.5.2: <i>"If the value of a "nonce" header parameter is not
    /// valid according to this encoding, then the verifier MUST reject the JWS
    /// as malformed."</i> - refused; as "malformed", or as "badNonce", which
    /// Boulder and Pebble answer and which is the more specific of the two
    /// (an interpretation, FINDINGS.md).
    /// </summary>
    [TestCase("not+base64url/")]
    [TestCase("padded==")]
    [TestCase("")]
    [Property("RFC", "8555 §6.5.2")]
    [Property("Level", "MUST")]
    public async Task A_Nonce_That_Is_No_base64url_Is_Refused(String Nonce)

        => AssertProblem(await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("nonce", Nonce)), 400, "malformed", "badNonce");

    /// <summary>
    /// <i>"An error response with the "badNonce" error type MUST include a
    /// Replay-Nonce header field with a fresh nonce that the server will
    /// accept in a retry of the original query"</i>.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Nonce_Of_badNonce_Is_Taken_In_The_Retry()
    {

        var refused = await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("nonce", "bm9uZQ"));
        var fresh   = refused.ReplayNonce;

        Assert.That(fresh, Is.Not.Null, refused.ToString());

        // The client pooled it as well; it is this retry's alone.
        Client.ForgetNonces();

        var retry   = await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("nonce", fresh!));

        AssertStatus(retry, 200);

    }

    /// <summary>
    /// <i>"The server MUST include a Replay-Nonce header field in every
    /// successful response to a POST request"</i> - of every resource a flow
    /// passes, each a base64url of section 6.5.1.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Every_Successful_Answer_To_A_POST_Has_A_Replay_Nonce()
    {

        var (other, created)  = await Client.NewAccountAsync();
        var order             = await Client.NewOrderAsync(other!, Loopback4);
        var orderURL          = order.Location!;
        var authz             = await Client.PostAsGetAsync(other!, order.StringsOf("authorizations")[0]);
        var challenge         = await Client.PostAsGetAsync(other!, RawACMEClient.ChallengeOf(authz, "http-01")!.Value.URL);
        var refetch           = await Client.PostAsGetAsync(other!, orderURL);
        var accountGet        = await Client.PostAsGetAsync(other!, other!.URL);

        using (Assert.EnterMultipleScope())
        {
            foreach (var answer in new[] { created, order, authz, challenge, refetch, accountGet })
            {
                Assert.That(answer.Status,       Is.InRange(200, 299),                     answer.ToString());
                Assert.That(answer.ReplayNonce,  Is.Not.Null,                              answer.ToString());
                Assert.That(answer.ReplayNonce,  Does.Match("^[A-Za-z0-9_-]+$"),           answer.ToString());
            }
        }

    }

    /// <summary>
    /// <i>"[...] and SHOULD provide it in error responses as well."</i> - of a
    /// resource that is not there, of a URL that does not match, of a
    /// request of another media type.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task Error_Answers_Have_A_Replay_Nonce_As_Well()
    {

        var notFound   = await Client.PostAsGetAsync(account, account.URL[..(account.URL.LastIndexOf("/acct/", StringComparison.Ordinal) + 1)] + "order/0000000000000000");
        var mismatch   = await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("url", account.URL + "/"));
        var mediaType  = await Client.PostAsync(account, account.URL, null, ContentType: "application/json");

        using (Assert.EnterMultipleScope())
        {
            foreach (var answer in new[] { notFound, mismatch, mediaType })
            {
                Assert.That(answer.Status,       Is.InRange(400, 499), answer.ToString());
                Assert.That(answer.ReplayNonce,  Is.Not.Null,          answer.ToString());
            }
        }

    }

    /// <summary>
    /// Section 6.5.1: <i>"The server MUST generate the values provided in
    /// Replay-Nonce header fields in such a way that they are unique to each
    /// message"</i> - and every one of them is good: 30 nonces fetched, then
    /// 30 requests with them sent at once, none refused as badNonce.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.5.1")]
    [Property("Level", "MUST")]
    public async Task Thirty_Nonces_Are_Each_Taken_At_Once()
    {

        var nonces   = new List<String>();

        for (var i = 0; i < 30; i++)
            nonces.Add(await Client.FreshNonceAsync());

        var answers  = await Task.WhenAll(nonces.Select(nonce => Client.PostAsync(account, account.URL, null, Header: header => header.SetString("nonce", nonce))));

        Assert.Multiple(() => {
            Assert.That(nonces.Distinct().Count(),                 Is.EqualTo(nonces.Count), "unique");
            Assert.That(answers.Where(answer => answer.Status != 200).Select(answer => answer.ToString()), Is.Empty);
        });

    }

}
