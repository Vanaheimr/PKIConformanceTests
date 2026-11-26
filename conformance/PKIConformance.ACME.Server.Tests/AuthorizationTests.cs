using System.Text.Json.Nodes;

using NUnit.Framework;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.5: an authorization, proven by answering one of its
/// challenges (section 7.5.1) or given up (section 7.5.2) - and the states of
/// section 7.1.6 it goes through, with its order.
/// </summary>
/// <remarks>
/// The challenges here are http-01 of 127.0.0.1 at the bench's host: right
/// where a test provisions the key authorization, wrong where it serves
/// something else.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.5")]
public class AuthorizationTests(String ServerName) : ACMEServerFixture(ServerName)
{

    #region Responding to a challenge (7.5.1)

    /// <summary>
    /// Section 7.5.1: <i>"The server provides a 200 (OK) response with the
    /// updated challenge object as its body."</i> - and section 7.1: <i>"The
    /// "up" link relation is used with challenge resources to indicate the
    /// authorization resource to which a challenge belongs."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.1, §7.1")]
    [Property("Level", "MUST")]
    public async Task A_Response_To_A_Challenge_Is_Answered_With_The_Challenge_Linked_Up()
    {

        var (account, order) = await PendingOrderAsync();
        var authz            = await Client.PostAsGetAsync(account, order.Authorizations[0]);
        var challenge        = RawACMEClient.ChallengeOf(authz, "http-01")!.Value;

        Host.Provision(challenge.Token, RawChallenge.KeyAuthorization(challenge.Token, account.Key.JWK));

        var answer           = await Client.PostAsync(account, challenge.URL, "{}");

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(answer.StringOf("type"),   Is.EqualTo("http-01"),                                answer.ToString());
            Assert.That(answer.StringOf("url"),    Is.EqualTo(challenge.URL),                            answer.ToString());
            Assert.That(answer.StringOf("status"), Is.AnyOf("pending", "processing", "valid"),          answer.ToString());
            Assert.That(answer.LinksOf("up"),      Does.Contain(order.Authorizations[0]),                $"rel=\"up\": {answer}");
        });

    }

    /// <summary>
    /// Proven: section 7.5.1, <i>"If the final state is "valid", then the
    /// server MUST include an "expires" field."</i>; section 8, <i>"validated
    /// (optional, string): [...] This field is REQUIRED if the "status" field is
    /// "valid"."</i>; section 7.1.6, the order <i>"Once all of the
    /// authorizations listed in the order object are in the "valid" state, the
    /// order transitions to the "ready" state."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.1, §8, §7.1.6")]
    [Property("Level", "MUST")]
    public async Task A_Proven_Authorization_Is_valid_With_expires_And_Its_Order_ready()
    {

        var (account, order) = await PendingOrderAsync();
        var authz            = await Client.ProveHTTP01Async(account, order.Authorizations[0], Host);
        var challenge        = (authz.Object?["challenges"] as JsonArray ?? []).OfType<JsonObject>().FirstOrDefault(one => one["status"]?.GetValue<String>() == "valid");
        var after            = await Client.PostAsGetAsync(account, order.URL);

        Assert.Multiple(() => {
            Assert.That(authz.StringOf("status"),                     Is.EqualTo("valid"),   authz.ToString());
            Assert.That(authz.StringOf("expires"),                    Is.Not.Null,           $"\"expires\": {authz}");
            Assert.That(challenge,                                    Is.Not.Null,           $"the valid challenge is among them: {authz}");
            Assert.That(challenge?["validated"]?.GetValue<String>(),  Is.Not.Null,           $"\"validated\" of a valid challenge: {authz}");
            Assert.That(after.StringOf("status"),                     Is.EqualTo("ready"),   after.ToString());
        });

    }

    /// <summary>
    /// Section 7.5.1: <i>"The server MUST ignore any fields in the response
    /// object that are not specified as response fields for this type of
    /// challenge."</i> - a response with a field of nobody's is taken as "{}".
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.1")]
    [Property("Level", "MUST")]
    public async Task Unknown_Fields_Of_A_Response_Are_Ignored()
    {

        var (account, order) = await PendingOrderAsync();
        var authz            = await Client.PostAsGetAsync(account, order.Authorizations[0]);
        var challenge        = RawACMEClient.ChallengeOf(authz, "http-01")!.Value;

        Host.Provision(challenge.Token, RawChallenge.KeyAuthorization(challenge.Token, account.Key.JWK));

        var answer           = await Client.PostAsync(account, challenge.URL, """{"keyAuthorization":"whatever","x-never-heard-of":1}""");
        var final            = await Client.PollWhileAsync(account, order.Authorizations[0], "pending");

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(final.StringOf("status"), Is.EqualTo("valid"), final.ToString());
        });

    }

    /// <summary>
    /// A wrong answer: the authorization is invalid (section 7.1.6, <i>"If the
    /// client attempts to fulfill a challenge and fails [...] the
    /// authorization transitions to the "invalid" state"</i>), the challenge
    /// says why (section 8.2, <i>"The server MUST add an entry to the "error"
    /// field in the challenge after each failed validation query."</i>), and the
    /// order is invalid (<i>"If an error occurs at any of these stages, the
    /// order moves to the "invalid" state."</i>).
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.6, §8.2")]
    [Property("Level", "MUST")]
    public async Task A_Wrong_Answer_Makes_Authorization_And_Order_invalid_And_Says_Why()
    {

        var (account, order) = await PendingOrderAsync();
        var authz            = await Client.PostAsGetAsync(account, order.Authorizations[0]);
        var challenge        = RawACMEClient.ChallengeOf(authz, "http-01")!.Value;

        Host.Provision(challenge.Token, challenge.Token + ".not-the-thumbprint");

        await Client.PostAsync(account, challenge.URL, "{}");

        var final            = await Client.PollWhileAsync(account, order.Authorizations[0], "pending");
        var failed           = (final.Object?["challenges"] as JsonArray ?? []).OfType<JsonObject>().FirstOrDefault(one => one["url"]?.GetValue<String>() == challenge.URL);
        var after            = await Client.PostAsGetAsync(account, order.URL);

        Assert.Multiple(() => {
            Assert.That(final.StringOf("status"),                                     Is.EqualTo("invalid"),                       final.ToString());
            Assert.That(failed?["status"]?.GetValue<String>(),                        Is.EqualTo("invalid"),                       final.ToString());
            Assert.That(failed?["error"]?["type"]?.GetValue<String>(),                Does.StartWith(RawACMEResponse.ErrorPrefix), $"\"error\": {final}");
            Assert.That(after.StringOf("status"),                                     Is.EqualTo("invalid"),                       after.ToString());
        });

    }

    /// <summary>
    /// Section 7.1.6: a challenge that failed stays failed - a second
    /// response to it, now with the right key authorization, does not make
    /// the authorization valid (its state machine has no way back from
    /// "invalid").
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.6")]
    [Property("Level", "MUST")]
    public async Task An_invalid_Authorization_Stays_invalid()
    {

        var (account, order) = await PendingOrderAsync();
        var authz            = await Client.PostAsGetAsync(account, order.Authorizations[0]);
        var challenge        = RawACMEClient.ChallengeOf(authz, "http-01")!.Value;

        Host.Provision(challenge.Token, "wrong");
        await Client.PostAsync(account, challenge.URL, "{}");
        await Client.PollWhileAsync(account, order.Authorizations[0], "pending");

        Host.Provision(challenge.Token, RawChallenge.KeyAuthorization(challenge.Token, account.Key.JWK));
        await Client.PostAsync(account, challenge.URL, "{}");
        await Task.Delay(1000);

        var final = await Client.PostAsGetAsync(account, order.Authorizations[0]);

        Assert.That(final.StringOf("status"), Is.EqualTo("invalid"), final.ToString());

    }

    #endregion

    #region Deactivation (7.5.2)

    /// <summary>
    /// Section 7.5.2: <i>"If the server accepts the deactivation, it should
    /// reply with a 200 (OK) status code and the updated contents of the
    /// authorization object."</i> - and <i>"The server MUST NOT treat
    /// deactivated authorization objects as sufficient for issuing
    /// certificates."</i>: the next order of the name needs a new proof.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.2")]
    [Property("Level", "MUST")]
    public async Task A_Deactivated_Authorization_Proves_Nothing_Any_More()
    {

        var account = await NewAccountAsync();
        var first   = await Client.ReadyOrderAsync(account, Host, Loopback4);
        var answer  = await Client.PostAsync(account, first.Authorizations[0], """{"status":"deactivated"}""");
        var next    = await Client.OrderAsync(account, Loopback4);
        var authz   = await Client.PostAsGetAsync(account, next.Authorizations[0]);

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(answer.StringOf("status"), Is.EqualTo("deactivated"),  answer.ToString());
            Assert.That(next.Status,                Is.EqualTo("pending"),      next.JSON.ToJsonString());
            Assert.That(authz.StringOf("status"),   Is.EqualTo("pending"),      authz.ToString());
        });

    }

    /// <summary>
    /// Section 7.5.2: <i>"The server MUST verify that the request is signed by
    /// the account key corresponding to the account that owns the
    /// authorization."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.2")]
    [Property("Level", "MUST")]
    public async Task An_Authorization_Is_Deactivated_By_Its_Own_Account_Alone()
    {

        var (account, order) = await PendingOrderAsync();
        var mallory          = await NewAccountAsync();

        var answer           = await Client.PostAsync(mallory, order.Authorizations[0], """{"status":"deactivated"}""");
        var still            = await Client.PostAsGetAsync(account, order.Authorizations[0]);

        Assert.Multiple(() => {
            AssertRefused(answer);
            Assert.That(still.StringOf("status"), Is.EqualTo("pending"), still.ToString());
        });

    }

    #endregion

    #region Links

    /// <summary>
    /// Section 7.1: <i>"The "index" link relation is present on all resources
    /// other than the directory and indicates the URL of the directory."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1")]
    [Property("Level", "MUST")]
    public async Task Every_Resource_Links_The_Directory_As_index()
    {

        var (account, order) = await PendingOrderAsync();
        var authz            = await Client.PostAsGetAsync(account, order.Authorizations[0]);
        var challenge        = await Client.PostAsGetAsync(account, RawACMEClient.ChallengeOf(authz, "http-01")!.Value.URL);
        var accountGet       = await Client.PostAsGetAsync(account, account.URL);
        var orderGet         = await Client.PostAsGetAsync(account, order.URL);
        var nonce            = await Client.SendAsync(HttpMethod.Head, Client.Resource("newNonce"), KeepNonce: false);

        using (Assert.EnterMultipleScope())
        {
            foreach (var answer in new[] { accountGet, orderGet, authz, challenge, nonce })
                Assert.That(answer.LinksOf("index"), Does.Contain(Client.DirectoryURL.ToString()), answer.ToString());
        }

    }

    #endregion

}
