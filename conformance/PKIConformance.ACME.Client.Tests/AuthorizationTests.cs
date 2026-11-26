using System.Text.Json.Nodes;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// RFC 8555, sections 7.5 and 8: winning the authorizations of an order -
/// which challenge, the answer in place (<i>"keyAuthorization = token || '.' ||
/// base64url(Thumbprint(accountKey))"</i>, section 8.1), the server told,
/// and the answer taken away again: <i>"The client SHOULD de-provision the
/// resource provisioned for this challenge once the challenge is
/// complete"</i> (sections 8.3, 8.4).
/// </summary>
/// <remarks>
/// The responders are Hermod's own: http-01 from a Hermod HTTP server, dns-01
/// into the zone of the bench. What judges them is the server, by RawACME.
/// </remarks>
[TestFixture]
[Property("RFC", "8555 §7.5, §8")]
public class AuthorizationTests : ClientFixture
{

    private async Task<HttpResponseMessage> Port80GetAsync(String Path)
    {
        using var http = new HttpClient();
        return await http.GetAsync($"http://127.0.0.1:{Port80.TCPPort.ToUInt16()}{Path}");
    }


    /// <summary>
    /// Section 8.3: <i>"The server ... verifies that the body of the response
    /// is a well-formed key authorization"</i> - the answer at the token's
    /// path is the key authorization RawACME computes of the token and the
    /// account key.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.1, §8.3")]
    [Property("Level", "MUST")]
    public async Task The_http01_Answer_Is_The_Key_Authorization()
    {

        var client = await ClientWithAccountAsync();
        await client.ObtainCertificateAsync([ Name ], [ HTTP01 ]);

        var validation = Server.Validations.Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(validation.Challenge.Type, Is.EqualTo("http-01"));
            Assert.That(validation.Valid,          Is.True, validation.Detail);
        }

    }

    /// <summary>
    /// Section 8.4: <i>"the client constructs the validation domain name by
    /// prepending the label "_acme-challenge" to the domain name being
    /// validated, then provisions a TXT record with the digest value under
    /// that name"</i> - for a wildcard the base name (section 7.1.3), the
    /// digest of RawACME.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.4, §7.1.3")]
    [Property("Level", "MUST")]
    public async Task The_dns01_Record_Is_The_Digest_At_The_Validation_Name()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client, "*.acme.test");

        var challenge = Server.Authorizations.Single().Challenges.Single(candidate => candidate.Type == "dns-01");
        var expected  = RawChallenge.DNS01Value(RawChallenge.KeyAuthorization(challenge.Token, Server.Accounts.Single().Key));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(ZoneChanges.Where(change => change.What == "publish").Select(change => (change.Name, change.Value)),
                        Is.EqualTo(new[] { ("_acme-challenge.acme.test", expected) }));
            Assert.That(Server.Validations.Single().Valid, Is.True, Server.Validations.Single().Detail);
        }

    }

    /// <summary>
    /// RFC 8738, section 7: <i>"The "dns-01" challenge MUST NOT be used to
    /// validate IP identifiers"</i> - an address is proven by http-01, and
    /// nothing is written into a zone for it.
    /// </summary>
    [Test]
    [Property("RFC", "8738 §7")]
    [Property("Level", "MUST NOT")]
    public async Task An_Address_Is_Proven_By_http01()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client, "127.0.0.1");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Server.Validations.Select(validation => validation.Challenge.Type), Is.EqualTo(new[] { "http-01" }));
            Assert.That(ZoneChanges, Is.Empty);
        }

    }

    /// <summary>
    /// Sections 8.3 and 8.4: <i>"The client SHOULD de-provision the resource
    /// provisioned for this challenge once the challenge is complete, i.e.,
    /// once the "status" field of the challenge has the value "valid" or
    /// "invalid"."</i> - after a certificate, and after a failure.
    /// </summary>
    [TestCase(true)]
    [TestCase(false)]
    [Property("RFC", "8555 §8.3, §8.4")]
    [Property("Level", "SHOULD")]
    public async Task The_Answers_Are_Taken_Away_Once_The_Challenges_Are_Done(Boolean Valid)
    {

        var client = await ClientWithAccountAsync();

        if (!Valid)
            Server.Validate = (_, _) => Task.FromResult((false, "no"));

        try
        {
            await ObtainAsync(client, "www.acme.test", "*.acme.test");
        }
        catch (ACMEException) when (!Valid) { }

        var http01  = Server.Authorizations.SelectMany(authz => authz.Challenges).Where(challenge => challenge.Type == "http-01" && challenge.RespondedAt is not null).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(HTTP01.Open,                                         Is.Zero, "http-01 answers left open");
            Assert.That(Server.Zone.Values.SelectMany(values => values.Keys), Is.Empty, "TXT records left in the zone");
            foreach (var challenge in http01)
                Assert.That((Int32) (await Port80GetAsync(RawChallenge.HTTP01Path(challenge.Token))).StatusCode, Is.EqualTo(404), $"the token {challenge.Token} is still served");
        }

    }

    /// <summary>
    /// Section 7.5.1: <i>"If the client's response is invalid for any reason
    /// or does not provide the server with appropriate information to validate
    /// the challenge, then the server MUST return an HTTP error. On receiving
    /// such an error, the client SHOULD undo any actions that have been taken
    /// to fulfill the challenge"</i>.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.1")]
    [Property("Level", "SHOULD")]
    public async Task An_Error_Answer_To_The_Challenge_Response_Undoes_The_Answer()
    {

        var client = await ClientWithAccountAsync();

        Server.Before = request => request.Resource == "challenge" && !request.PostAsGet
                                       ? ScriptedAnswer.Problem(400, "malformed", "The bench does not take this response.")
                                       : null;

        await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client, "www.acme.test", "*.acme.test"));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(HTTP01.Open,                                          Is.Zero);
            Assert.That(Server.Zone.Values.SelectMany(values => values.Keys), Is.Empty);
        }

    }

    /// <summary>
    /// An authorization of an order that is won already - <i>"valid"</i>, by
    /// an earlier order of the account - is not proven again: one name of two
    /// is.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.3, §7.5")]
    [Property("Level", "SHOULD")]
    public async Task A_Valid_Authorization_Is_Not_Proven_Again()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client, "a.acme.test");

        var before = Server.Requests.Count;
        await ObtainAsync(client, "a.acme.test", "b.acme.test");

        var responded = Server.Requests.Skip(before).Where(request => request.Resource == "challenge" && !request.PostAsGet).ToArray();

        Assert.That(responded.Select(request => Server.Authorizations.Single(authz => authz.Challenges.Any(challenge => challenge.Id == request.ResourceId)).Identifier.Value),
                    Is.EqualTo(new[] { "b.acme.test" }), Log);

    }

    /// <summary>
    /// Section 7.1.6: an authorization that is <i>"deactivated"</i>,
    /// <i>"expired"</i>, <i>"revoked"</i> or <i>"invalid"</i> cannot be won
    /// any more - a clear error that names it, and no challenge answered.
    /// </summary>
    [TestCase("deactivated")]
    [TestCase("expired")]
    [TestCase("revoked")]
    [TestCase("invalid")]
    [Property("RFC", "8555 §7.1.6")]
    [Property("Level", "MUST")]
    public async Task An_Authorization_That_Cannot_Be_Won_Is_A_Clear_Error(String Status)
    {

        var client = await ClientWithAccountAsync();

        Server.After = (request, answer) => request.Resource == "authz"
                                                ? answer.MapJSON(authz => authz["status"] = Status)
                                                : answer;

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Message,                                                       Does.Contain(Status).And.Contain(Name), refused.Message);
            Assert.That(Server.RequestsOf("challenge").Where(request => !request.PostAsGet),    Is.Empty, Log);
        }

    }

    /// <summary>
    /// Section 7.1.4: <i>"challenges (required, array of objects): For pending
    /// authorizations, the challenges that the client can fulfill in order to
    /// prove possession of the identifier"</i> - challenges of types the
    /// client does not know, with members it does not know, are passed over,
    /// and one it knows is taken.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.4, §8")]
    [Property("Level", "MUST")]
    public async Task Challenges_Of_Unknown_Types_Are_Passed_Over()
    {

        Server.ChallengeTypes = (identifier, wildcard) => [ "tls-alpn-01", "dns-account-01", "x-future-01", .. ScriptedACMEServer.DefaultChallengeTypes(identifier, wildcard) ];
        Server.After          = (request, answer) => request.Resource == "authz"
                                                         ? answer.MapJSON(authz => {
                                                               foreach (var challenge in authz["challenges"]!.AsArray().OfType<JsonObject>().Where(challenge => challenge["type"]?.GetValue<String>() == "x-future-01"))
                                                               {
                                                                   challenge["future"]   = new JsonObject { ["nested"] = new JsonArray(1, 2, 3) };
                                                                   challenge["required"] = true;
                                                               }
                                                           })
                                                         : answer;

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);

        Assert.That(Server.Validations.Select(validation => validation.Challenge.Type), Is.EqualTo(new[] { "http-01" }), Log);

    }

    /// <summary>
    /// A wildcard with only an http-01 responder: nothing here can prove it
    /// (section 7.1.3: dns-01 only), and the error says so - and what the
    /// server offered.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.3")]
    [Property("Level", "SHOULD")]
    public async Task A_Wildcard_Without_A_dns01_Responder_Is_A_Clear_Error()
    {

        var client  = await ClientWithAccountAsync();
        var refused = await Assert.ThrowsAsync<ACMEException>(() => client.ObtainCertificateAsync([ "*.acme.test" ], [ HTTP01 ]));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Message,                                                    Does.Contain("dns-01"), refused.Message);
            Assert.That(Server.RequestsOf("challenge").Where(request => !request.PostAsGet), Is.Empty, Log);
        }

    }

    /// <summary>
    /// Section 8.3: the token <i>"MUST NOT contain any characters outside the
    /// base64url alphabet"</i> - a server's mistake that a client's web
    /// server does not make worse: a token of "../" serves nothing outside
    /// /.well-known/acme-challenge/.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3")]
    [Property("Level", "SHOULD")]
    public async Task A_Token_With_Dot_Segments_Is_Served_Nowhere_Else()
    {

        Server.TokenFor  = _ => "../../outside";
        Server.Validate  = async (challenge, keyAuthorization) => {
                               foreach (var path in new[] { "/outside", "/.well-known/outside", "/.well-known/acme-challenge/outside" })
                               {
                                   var answer = await Port80GetAsync(path);
                                   if (answer.IsSuccessStatusCode && (await answer.Content.ReadAsStringAsync()).Contains(keyAuthorization))
                                       return (false, $"{path} serves the key authorization");
                               }
                               return (true, "served nowhere else");
                           };

        var client = await ClientWithAccountAsync();

        try
        {
            await client.ObtainCertificateAsync([ Name ], [ HTTP01 ]);
        }
        catch (ACMEException) { }

        Assert.That(Server.Validations.Select(validation => validation.Detail), Has.None.Contains("serves the key authorization"), Log);

    }


    #region ToDos

    /// <summary>
    /// ToDo T-C4: section 7.5.2, <i>"the client can deactivate an authorization
    /// by sending a POST request to the authorization URL ... with the "status"
    /// field set to "deactivated""</i>.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.2")]
    [Property("Level", "MAY")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C4")]
    public async Task An_Authorization_Is_Deactivated()
    {

        var client  = await ClientWithAccountAsync();
        await ObtainAsync(client);

        var deactivate = Trackers.Method(typeof(ACMEClient), "DeactivateAuthorizationAsync", "DeactivateAuthzAsync");

        if (deactivate is null)
            Assert.Fail("T-C4: the client cannot deactivate an authorization (RFC 8555, section 7.5.2) yet.");

        await Trackers.InvokeAsync(deactivate!, client, new Uri(Server.Authorizations.Single().URL));

        Assert.That(Server.Authorizations.Single().Status, Is.EqualTo("deactivated"), Log);

    }

    /// <summary>
    /// ToDo T-C10: RFC 8737, tls-alpn-01 - <i>"the client ... responds to the
    /// challenge by configuring a TLS server on port 443 ... with the
    /// "acme-tls/1" protocol"</i>.
    /// </summary>
    [Test]
    [Property("RFC", "8737 §3")]
    [Property("Level", "MAY")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C10")]
    public void There_Is_A_tls_alpn_01_Responder()
    {

        var responder = Trackers.HermodType("TLSALPN01ChallengeResponder", "TLSALPNChallengeResponder", "TlsAlpn01ChallengeResponder");

        Assert.That(responder, Is.Not.Null, "T-C10: Hermod has no tls-alpn-01 responder (RFC 8737) yet.");

    }

    #endregion

}
