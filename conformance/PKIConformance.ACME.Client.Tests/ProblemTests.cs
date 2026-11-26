using System.Text.Json.Nodes;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// RFC 8555, section 6.7: what a client makes of a server's errors -
/// <i>"problem documents [RFC7807]"</i> of the error types of the RFC, their
/// "detail" (<i>"Clients SHOULD display the "detail" field of all
/// errors"</i>), their subproblems, and whatever else comes back where a
/// problem document should: an HTML page of a proxy, a problem without a type.
/// </summary>
[TestFixture]
[Property("RFC", "8555 §6.7")]
public class ProblemTests : ClientFixture
{

    private void NewOrderAnswered(ScriptedAnswer Answer, Int32 Times = Int32.MaxValue)
    {

        var count = 0;

        Server.Before = request => request.Resource == "newOrder" && Interlocked.Increment(ref count) <= Times
                                       ? Answer
                                       : null;

    }


    /// <summary>
    /// Section 6.7: <i>"Clients SHOULD display the "detail" field of all
    /// errors."</i> - an exception says it, with the type and the status.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task The_detail_Of_A_Problem_Is_Said()
    {

        var client = await ClientWithAccountAsync();
        NewOrderAnswered(ScriptedAnswer.Problem(400, "rejectedIdentifier", "The bench issues nothing for this name, by its policy 4.2."));

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Message,           Does.Contain("by its policy 4.2"),    refused.Message);
            Assert.That(refused.Problem?.ShortType, Is.EqualTo("rejectedIdentifier"));
            Assert.That(refused.Problem?.Status,    Is.EqualTo(400));
        }

    }

    /// <summary>
    /// Section 6.7.1: <i>"the server MAY return a problem document containing
    /// subproblems ... ACME clients may choose to use the "identifier" field
    /// of a subproblem as a hint that an operation would succeed if that
    /// identifier were omitted"</i> - which they can only where it reaches
    /// them, each with its identifier.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.7.1")]
    [Property("Level", "MAY")]
    public async Task Subproblems_Reach_The_Caller_With_Their_Identifiers()
    {

        var client = await ClientWithAccountAsync();

        NewOrderAnswered(ScriptedAnswer.Problem(400, "malformed", "Some of the identifiers were refused.",
                                                new JsonObject {
                                                    ["subproblems"] = new JsonArray(
                                                        new JsonObject { ["type"] = ScriptedAnswer.ErrorPrefix + "rejectedIdentifier", ["detail"] = "Not this one.",
                                                                         ["identifier"] = new JsonObject { ["type"] = "dns", ["value"] = "a.acme.test" } },
                                                        new JsonObject { ["type"] = ScriptedAnswer.ErrorPrefix + "caa",                ["detail"] = "CAA forbids it.",
                                                                         ["identifier"] = new JsonObject { ["type"] = "dns", ["value"] = "b.acme.test" } })
                                                }));

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client, "a.acme.test", "b.acme.test"));
        var sub     = refused!.Problem?.Subproblems ?? [];

        using (Assert.EnterMultipleScope())
        {
            Assert.That(sub.Select(problem => problem.ShortType),          Is.EqualTo(new[] { "rejectedIdentifier", "caa" }), refused.Message);
            Assert.That(sub.Select(problem => problem.Identifier?.Value),  Is.EqualTo(new[] { "a.acme.test", "b.acme.test" }), refused.Message);
            Assert.That(refused.Message,                                   Does.Contain("CAA forbids it."),                     refused.Message);
        }

    }

    /// <summary>
    /// RFC 7807, section 3.1: <i>"When this member is not present, its value
    /// is assumed to be "about:blank"."</i> - a problem without a "type" is
    /// one of "about:blank", and its detail is said all the same.
    /// </summary>
    [Test]
    [Property("RFC", "7807 §3.1")]
    [Property("Level", "MUST")]
    public async Task A_Problem_Without_A_type_Is_about_blank()
    {

        var client = await ClientWithAccountAsync();
        NewOrderAnswered(new ScriptedAnswer(403, "{\"detail\":\"No type here.\",\"status\":403}", "application/problem+json"));

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Problem?.Type, Is.EqualTo("about:blank"), refused.Message);
            Assert.That(refused.Message,        Does.Contain("No type here."));
        }

    }

    /// <summary>
    /// An error type of no RFC - section 6.7: <i>"The server MAY return errors
    /// whose "type" field is set to a URI other than those defined above"</i>
    /// - is kept as it came.
    /// </summary>
    [Test]
    [Property("Level", "MAY")]
    public async Task An_Error_Type_Of_No_RFC_Is_Kept_As_It_Came()
    {

        var client = await ClientWithAccountAsync();
        NewOrderAnswered(ScriptedAnswer.Problem(400, "https://pkiconformance.test/errors/quota", "Over the quota."));

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        Assert.That(refused!.Problem?.Type, Is.EqualTo("https://pkiconformance.test/errors/quota"), refused.Message);

    }

    /// <summary>
    /// What a proxy in front of a CA answers - 502 and an HTML page - is an
    /// ACME failure that says the status, not a JSON parser's exception.
    /// </summary>
    [TestCase(502, "text/html", "<html><body><h1>502 Bad Gateway</h1></body></html>")]
    [TestCase(503, "text/plain", "")]
    [TestCase(500, "application/json", "{ not json")]
    [Property("Level", "MUST")]
    public async Task What_Is_No_Problem_Document_Is_An_ACMEException_With_Its_Status(Int32 Status, String ContentType, String Body)
    {

        var client = await ClientWithAccountAsync();
        NewOrderAnswered(new ScriptedAnswer(Status, Body, ContentType));

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        Assert.That(refused!.Message, Does.Contain(Status.ToString()), refused.Message);

    }

    /// <summary>
    /// Section 6.6: <i>"the server MAY include a Retry-After header field
    /// indicating how long to wait"</i> with a rateLimited - which reaches the
    /// caller with the exception.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.6")]
    [Property("Level", "SHOULD")]
    public async Task The_Retry_After_Of_A_rateLimited_Reaches_The_Caller()
    {

        var client = await ClientWithAccountAsync();
        NewOrderAnswered(ScriptedAnswer.Problem(429, "rateLimited", "Too many orders.").With("Retry-After", "120"));

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Problem?.ShortType, Is.EqualTo("rateLimited"),          refused.Message);
            Assert.That(refused.RetryAfter,          Is.EqualTo(TimeSpan.FromSeconds(120)), refused.Message);
        }

    }


    #region ToDos

    /// <summary>
    /// ToDo T-C9 (PLAN.md, section 2.4): a rateLimited, or a 503, with a short
    /// Retry-After is waited out and the request sent again - section 6.6,
    /// <i>"the server MAY include a Retry-After header field indicating how
    /// long to wait"</i>, which is only of use to a client that waits.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.6")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C9")]
    public async Task A_Short_Retry_After_Of_A_503_Is_Waited_Out()
    {

        var client = await ClientWithAccountAsync();
        NewOrderAnswered(ScriptedAnswer.Problem(503, "rateLimited", "Busy; again in a second.").With("Retry-After", "1"), Times: 1);

        try
        {
            await ObtainAsync(client);
        }
        catch (ACMEException e)
        {
            Assert.Fail($"T-C9: the client does not wait out a Retry-After of one second, it fails: {e.Message}");
        }

        Assert.That(Server.Certificates, Has.Count.EqualTo(1), Log);

    }

    /// <summary>
    /// ToDo T-C7: section 6.2, <i>"If the server receives a request ... with
    /// an "alg" it does not support, it MUST respond with an error of type
    /// "badSignatureAlgorithm" ... The problem document returned with the
    /// error MUST include an "algorithms" field"</i> - which a client takes up:
    /// it signs again with one of them.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C7")]
    public async Task The_algorithms_Of_A_badSignatureAlgorithm_Are_Taken_Up()
    {

        var count = 0;

        Server.Before = request => request.Resource == "newAccount" && request.Alg == "ES256" && Interlocked.Increment(ref count) == 1
                                       ? ScriptedAnswer.Problem(400, "badSignatureAlgorithm", "ES256 is not taken here.",
                                                                new JsonObject { ["algorithms"] = new JsonArray("ES384", "RS256") })
                                       : null;

        try
        {
            await ClientWithAccountAsync();
        }
        catch (ACMEException e)
        {
            Assert.Fail($"T-C7: the client does not sign with one of the \"algorithms\" of a badSignatureAlgorithm: {e.Message}");
        }

        Assert.That(Server.RequestsOf("newAccount").Last().Alg, Is.AnyOf("ES384", "RS256"), Log);

    }

    /// <summary>
    /// ToDo T-C8: section 7.3.3, <i>"the server MUST include a Link header
    /// field with link relation "terms-of-service" and the URL for the new
    /// terms of service ... and it SHOULD include an "instance" field"</i> -
    /// and a client says both to its user, who is to agree.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.3")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C8")]
    public async Task A_userActionRequired_Says_The_New_Terms_And_Where_To_Agree()
    {

        var client = await ClientWithAccountAsync();

        NewOrderAnswered(ScriptedAnswer.Problem(403, "userActionRequired", "The terms of service have changed.",
                                                new JsonObject { ["instance"] = "https://pkiconformance.test/agree/v2" }).
                                        With("Link", "<https://pkiconformance.test/terms/v2>;rel=\"terms-of-service\""));

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        var said    = String.Join(" ", new Object?[] { refused!.Message,
                                                       Trackers.Property(typeof(ACMEProblem),   "Instance")?.GetValue(refused.Problem),
                                                       Trackers.Property(typeof(ACMEException), "TermsOfService", "Links")?.GetValue(refused) });

        using (Assert.EnterMultipleScope())
        {
            Assert.That(said, Does.Contain("https://pkiconformance.test/terms/v2"),  $"T-C8: the new terms are not said: {said}");
            Assert.That(said, Does.Contain("https://pkiconformance.test/agree/v2"), $"T-C8: where to agree is not said: {said}");
        }

    }

    #endregion

}
