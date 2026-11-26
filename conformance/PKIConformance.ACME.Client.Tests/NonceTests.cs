using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// RFC 8555, section 6.5, replay protection from the client's side: <i>"Every
/// JWS sent by an ACME client MUST include, in its protected header, the
/// "nonce" header parameter"</i> - a nonce of the server's, used once - and
/// what it does with a "badNonce": <i>"when retrying in response to a
/// "badNonce" error, the client MUST use the nonce provided in the error
/// response"</i>.
/// </summary>
/// <remarks>
/// Pebble rejects a share of all nonces on purpose, and Boulder's nonces go
/// stale across its front ends: a client that cannot cope with a badNonce
/// fails against both sooner or later.
/// </remarks>
[TestFixture]
[Property("RFC", "8555 §6.5")]
public class NonceTests : ClientFixture
{

    /// <summary>The first newOrder answered with a badNonce, once.</summary>
    private void BadNonceOnce(String Resource = "newOrder")
    {

        var done = 0;

        Server.Before = request => request.Resource == Resource && Interlocked.Exchange(ref done, 1) == 0
                                       ? ScriptedAnswer.Problem(400, "badNonce", "The scripted server takes this nonce no more.")
                                       : null;

    }


    /// <summary>
    /// Section 6.5: <i>"the server MUST verify that the value of the "nonce"
    /// header is a value that the server previously provided in a Replay-Nonce
    /// header field"</i> - so every nonce a client sends is one it was given.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Every_Nonce_Is_One_The_Server_Handed_Out()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);

        foreach (var request in Server.SignedRequests)
            Assert.That(Server.HandedOutNonces.ContainsKey(request.Nonce!), Is.True, request.ToString());

    }

    /// <summary>
    /// Section 6.5: <i>"Once a nonce value has appeared in an ACME request, the
    /// server MUST consider it invalid"</i> - a client that sends one twice is
    /// refused the second time.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task No_Nonce_Is_Sent_Twice()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);

        var nonces = Server.SignedRequests.Select(request => request.Nonce).ToArray();

        Assert.That(nonces, Is.Unique, Log);

    }

    /// <summary>
    /// One client, six orders at once - <i>"Thread-safe; one client may order
    /// several certificates at once"</i>, its documentation says: the pool of
    /// nonces hands none out twice.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task No_Nonce_Is_Sent_Twice_By_Orders_At_Once()
    {

        var client = await ClientWithAccountAsync();

        await Task.WhenAll(Enumerable.Range(1, 6).Select(n => ObtainAsync(client, $"n{n}.acme.test")));

        var nonces = Server.SignedRequests.Select(request => request.Nonce).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(nonces,                                                 Is.Unique,                         Log);
            Assert.That(Server.SignedRequests.Count(r => r.ErrorType() == "badNonce"), Is.Zero,                   Log);
            Assert.That(Server.Certificates,                                    Has.Count.EqualTo(6),              Log);
        }

    }

    /// <summary>
    /// Section 7.2: <i>"the client might sometimes need to get a new nonce,
    /// e.g., on its first request to the server ... To get a fresh nonce, the
    /// client sends a HEAD request to the newNonce resource on the server."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.2")]
    [Property("Level", "SHOULD")]
    public async Task The_First_Nonce_Comes_From_A_HEAD_Of_newNonce()
    {

        await ClientWithAccountAsync();

        var first  = Server.SignedRequests.First();
        var source = Server.Requests.FirstOrDefault(request => request.AnswerNonce == first.Nonce);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(source?.Resource, Is.EqualTo("newNonce"), Log);
            Assert.That(source?.Method,   Is.EqualTo("HEAD"),     Log);
        }

    }

    /// <summary>
    /// Section 6.5: <i>"On receiving such a response, a client SHOULD retry
    /// the request using the new nonce."</i>
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task A_Request_Answered_With_badNonce_Is_Sent_Again()
    {

        var client = await ClientWithAccountAsync();
        BadNonceOnce();

        var certificate = await ObtainAsync(client);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(certificate,                         Is.Not.Null);
            Assert.That(Server.RequestsOf("newOrder").Count, Is.EqualTo(2), Log);
        }

    }

    /// <summary>
    /// Section 6.5: <i>"However, when retrying in response to a "badNonce"
    /// error, the client MUST use the nonce provided in the error
    /// response."</i> - with more than one nonce in the client's pool, which
    /// six requests at once leave there.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-3")]
    public async Task The_Retry_After_badNonce_Carries_The_Nonce_Of_The_badNonce()
    {

        var client  = await ClientWithAccountAsync();
        var order   = await client.NewOrderAsync([ ACMEIdentifier.From(Name) ]);

        // Six looks at once: six answers, six nonces in the pool.
        await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => client.GetOrderAsync(order.URL)));

        BadNonceOnce();

        await client.NewOrderAsync([ ACMEIdentifier.From("second.acme.test") ]);

        var newOrders = Server.RequestsOf("newOrder").Skip(1).ToArray();
        var refused   = newOrders.First(request => request.Answer?.ErrorType == "badNonce");
        var retry     = newOrders.First(request => request.Number > refused.Number);

        Assert.That(retry.Nonce, Is.EqualTo(refused.AnswerNonce), $"refused: {refused} - retried: {retry}");

    }

    /// <summary>
    /// A server that refuses every nonce - a broken one - is not asked
    /// forever: the client gives up with the server's badNonce, after a few
    /// tries. (RFC 8555 sets no number; a client that retries without end
    /// hangs whoever called it.)
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task A_Server_That_Always_Says_badNonce_Is_Given_Up_On()
    {

        var client = await ClientWithAccountAsync();

        Server.Before = request => request.Resource == "newOrder"
                                       ? ScriptedAnswer.Problem(400, "badNonce", "Never.")
                                       : null;

        var refused = await Assert.ThrowsAsync<ACMEException>(() => client.NewOrderAsync([ ACMEIdentifier.From(Name) ]));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Problem?.ShortType,          Is.EqualTo("badNonce"),               refused.Message);
            Assert.That(Server.RequestsOf("newOrder").Count,  Is.InRange(2, 10),                     Log);
        }

    }

    /// <summary>
    /// Section 6.5: the server <i>"SHOULD provide it in error responses as
    /// well"</i> - and a client <i>"MAY assume that nonces have broad scope"</i>:
    /// the nonce of an error is as good as any, and asking newNonce again
    /// after one costs a round trip for nothing.
    /// </summary>
    [Test]
    [Property("Level", "MAY")]
    public async Task The_Nonce_Of_An_Error_Is_Used_For_The_Next_Request()
    {

        var client = await ClientWithAccountAsync();
        var done   = 0;

        Server.Before = request => request.Resource == "newOrder" && Interlocked.Exchange(ref done, 1) == 0
                                       ? ScriptedAnswer.Problem(400, "rejectedIdentifier", "Not this one.")
                                       : null;

        await Assert.ThrowsAsync<ACMEException>(() => client.NewOrderAsync([ ACMEIdentifier.From("refused.acme.test") ]));

        var error  = Server.RequestsOf("newOrder").Single();
        await client.NewOrderAsync([ ACMEIdentifier.From(Name) ]);
        var next   = Server.SignedRequests.First(request => request.Number > error.Number);

        Assert.That(next.Nonce, Is.EqualTo(error.AnswerNonce), Log);

    }

    /// <summary>
    /// Section 6.5.1: <i>"The value of the Replay-Nonce header field MUST be
    /// an octet string encoded according to the base64url encoding ...
    /// Clients MUST ignore invalid Replay-Nonce values."</i> - one that is not
    /// base64url, in the answer to a POST, is never sent back.
    /// </summary>
    [TestCase("not base64url!")]
    [TestCase("padded+/base64==")]
    [TestCase("a.b")]
    [Property("RFC", "8555 §6.5.1")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-4")]
    public async Task An_Invalid_Replay_Nonce_Of_A_POST_Is_Ignored(String Invalid)
    {

        var done   = 0;

        Server.After = (request, answer) => request.Resource == "newAccount" && Interlocked.Exchange(ref done, 1) == 0
                                                ? answer with { ReplayNonce = Invalid }
                                                : answer;

        var client = await ClientWithAccountAsync();

        try
        {
            await client.NewOrderAsync([ ACMEIdentifier.From(Name) ]);
        }
        catch (ACMEException)
        {
            // Whatever came of it: what counts is what was sent.
        }

        Assert.That(Server.SignedRequests.Select(request => request.Nonce), Has.None.EqualTo(Invalid), Log);

    }

    /// <summary>
    /// Section 6.5.1, the same of the answer to a HEAD of newNonce: an
    /// invalid value is no nonce to send.
    /// </summary>
    [TestCase("not base64url!")]
    [TestCase("padded+/base64==")]
    [Property("RFC", "8555 §6.5.1")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-4")]
    public async Task An_Invalid_Replay_Nonce_Of_newNonce_Is_Ignored(String Invalid)
    {

        var done   = 0;

        Server.After = (request, answer) => request.Resource == "newNonce" && Interlocked.Exchange(ref done, 1) == 0
                                                ? answer with { ReplayNonce = Invalid }
                                                : answer;

        try
        {
            await ClientWithAccountAsync();
        }
        catch (ACMEException)
        {
            // Whatever came of it: what counts is what was sent.
        }

        Assert.That(Server.SignedRequests.Select(request => request.Nonce), Has.None.EqualTo(Invalid), Log);

    }

}


internal static class ACMERequestExtensions
{

    /// <summary>The error type of the answer to the request, or null.</summary>
    public static String? ErrorType(this ACMERequest Request)
        => Request.Answer?.ErrorType;

}
