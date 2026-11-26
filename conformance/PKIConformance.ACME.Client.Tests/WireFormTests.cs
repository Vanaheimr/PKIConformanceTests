using System.Text.RegularExpressions;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// RFC 8555, section 6: what every request of a client looks like on the wire
/// - <i>"a JSON Web Signature (JWS) object [RFC7515] ... using the Flattened
/// JSON Serialization"</i>, <i>"the "alg", "nonce", and "url" fields"</i> in
/// its protected header, <i>"either a "jwk" (JSON Web Key) or "kid" (Key ID)
/// field ... but not both"</i> - judged request by request by RawACME, over
/// the requests of a whole issuance.
/// </summary>
/// <remarks>
/// A client that gets one of these wrong is refused by every strict server
/// of the world; the scripted one refuses it as well, so that a test of
/// something else would fail too - these tests say why.
/// </remarks>
[TestFixture]
[Property("RFC", "8555 §6")]
public class WireFormTests : ClientFixture
{

    private async Task<IReadOnlyList<ACMERequest>> IssuanceAsync()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);

        return Server.SignedRequests;

    }


    #region Section 6.2 - the JWS

    /// <summary>
    /// Section 6.2: <i>"JWS objects sent in ACME requests MUST meet the
    /// following additional criteria: The JWS MUST be in the Flattened JSON
    /// Serialization [RFC7515]; The JWS MUST NOT have multiple signatures; The
    /// JWS Unencoded Payload Option [RFC7797] MUST NOT be used; The JWS
    /// Unprotected Header [RFC7515] MUST NOT be used"</i> - the three members
    /// of the flattened serialization, and no others.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2")]
    [Property("Level", "MUST")]
    public async Task Every_POST_Is_A_Flattened_JWS_And_Nothing_Else()
    {

        await IssuanceAsync();

        var posts = Server.Requests.Where(request => request.Method == "POST").ToArray();

        Assert.That(posts, Is.Not.Empty, Log);

        foreach (var post in posts)
            Assert.That(post.JWSMembers, Is.EquivalentTo(new[] { "protected", "payload", "signature" }), post.ToString());

    }

    /// <summary>
    /// Section 6.2: <i>"the request body MUST be ... with Content-Type
    /// "application/jose+json""</i> - the media type itself, no charset (the
    /// PKI refuses one, S-1 of phase 2 had it so).
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2")]
    [Property("Level", "MUST")]
    public async Task Every_POST_Is_application_jose_json()
    {

        await IssuanceAsync();

        foreach (var post in Server.Requests.Where(request => request.Method == "POST"))
            Assert.That(post.ContentType, Is.EqualTo("application/jose+json"), post.ToString());

    }

    /// <summary>
    /// Section 6.2: <i>"The protected header MUST include the following fields:
    /// "alg" (Algorithm) ... "nonce" (defined in Section 6.5) ... "url"
    /// (defined in Section 6.4) ... either "jwk" (JSON Web Key) or "kid" (Key
    /// ID) as specified below"</i> and <i>"The "jwk" and "kid" fields are
    /// mutually exclusive"</i>.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2")]
    [Property("Level", "MUST")]
    public async Task Every_Protected_Header_Has_alg_nonce_url_And_One_Of_jwk_And_kid()
    {

        foreach (var request in await IssuanceAsync())
        {
            using (Assert.EnterMultipleScope())
            {
                Assert.That(request.Alg,                                                          Is.Not.Null.And.Not.Empty, request.ToString());
                Assert.That(request.Nonce,                                                        Is.Not.Null.And.Not.Empty, request.ToString());
                Assert.That(request.HeaderURL,                                                    Is.Not.Null.And.Not.Empty, request.ToString());
                Assert.That(request.Protected!.ContainsKey("jwk") ^ request.Protected.ContainsKey("kid"), Is.True,           $"jwk or kid, not both: {request}");
            }
        }

    }

    /// <summary>
    /// Section 6.2: <i>"For newAccount requests, and for revokeCert requests
    /// authenticated by a certificate key, there MUST be a "jwk" field"</i>;
    /// <i>"For all other requests, the request is signed using an existing
    /// account, and there MUST be a "kid" field. This field MUST contain the
    /// account URL received by POSTing to the newAccount resource."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2")]
    [Property("Level", "MUST")]
    public async Task The_jwk_Goes_To_newAccount_And_The_Account_URL_Everywhere_Else()
    {

        var requests = await IssuanceAsync();
        var account  = Server.Accounts.Single();

        foreach (var request in requests)
        {
            if (request.Resource == "newAccount")
                Assert.That(request.JWK, Is.Not.Null, request.ToString());
            else
                Assert.That(request.Kid, Is.EqualTo(account.URL), $"the account URL as the server gave it: {request}");
        }

    }

    /// <summary>
    /// Section 6.2: <i>"This field [jwk] MUST contain the public key"</i> - and
    /// RFC 7517, section 9.2, a private key's members do not leave it: the
    /// "jwk" is no private key in disguise.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2, 7517 §9.2")]
    [Property("Level", "MUST")]
    public async Task The_jwk_Holds_The_Public_Key_And_No_Private_Member()
    {

        await IssuanceAsync();

        foreach (var request in Server.RequestsOf("newAccount"))
            Assert.That(request.JWK!.Select(member => member.Key), Is.EquivalentTo(new[] { "kty", "crv", "x", "y" }).Or.EquivalentTo(new[] { "kty", "n", "e" }), request.ToString());

    }

    /// <summary>
    /// Section 6.2: <i>"The JWS Protected Header MUST include ... "alg"
    /// ... This field MUST NOT contain "none" or a Message Authentication Code
    /// (MAC) algorithm"</i> - and the signature holds, by RawACME's own
    /// verification, with the key it names.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2")]
    [Property("Level", "MUST")]
    public async Task Every_Signature_Is_Asymmetric_And_Holds_By_RawACME()
    {

        var requests = await IssuanceAsync();
        var account  = Server.Accounts.Single();

        foreach (var request in requests)
        {

            var key = request.JWK is not null ? RawJWK.Parse(request.JWK.ToJsonString()) : account.Key;

            using (Assert.EnterMultipleScope())
            {
                Assert.That(request.Alg,                       Is.AnyOf("ES256", "ES384", "ES512", "RS256", "PS256"), request.ToString());
                Assert.That(request.JWS!.VerifiedBy(key),      Is.True,                                              $"verified by RawACME: {request}");
            }

        }

    }

    #endregion

    #region Section 6.3 - POST-as-GET

    /// <summary>
    /// Section 6.3: <i>"the client sends a POST request with a JWS body, where
    /// the payload of the JWS is a zero-length octet string"</i> - for every
    /// look at an order, an authorization, a certificate; <i>"The "payload"
    /// field of the JWS object MUST be present and set to the empty string
    /// ("")"</i>, not "{}".
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.3")]
    [Property("Level", "MUST")]
    public async Task Every_Look_Is_A_POST_as_GET_With_The_Empty_Payload()
    {

        var requests = await IssuanceAsync();
        var looks    = requests.Where(request => request.Resource is "order" or "authz" or "certificate").ToArray();

        Assert.That(looks.Select(request => request.Resource), Does.Contain("order").And.Contain("authz").And.Contain("certificate"), Log);

        foreach (var look in looks)
            Assert.That(look.JWS!.Payload, Is.Empty, look.ToString());

    }

    /// <summary>
    /// Section 7.5.1: <i>"The client indicates to the server that it is ready
    /// for the challenge validation by sending an empty JSON body ("{}")
    /// carried in a POST request to the challenge URL (not the authorization
    /// URL)."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.1")]
    [Property("Level", "MUST")]
    public async Task The_Response_To_A_Challenge_Is_The_Empty_Object()
    {

        await IssuanceAsync();

        var responses = Server.RequestsOf("challenge").Where(request => !request.PostAsGet).ToArray();

        Assert.That(responses, Is.Not.Empty, Log);

        foreach (var response in responses)
            Assert.That(response.PayloadJSON, Is.EqualTo("{}"), response.ToString());

    }

    #endregion

    #region Section 6.4 / 7.1 - URLs

    /// <summary>
    /// Section 7.1: <i>"Except for the directory resource, all ACME resources
    /// are addressed with URLs provided to the client by the server."</i> -
    /// every request goes to a URL the server handed out, none to one the
    /// client made up; the renewalInfo of RFC 9773 is the one URL a client
    /// builds, below the one handed out.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.4, §7.1")]
    [Property("Level", "MUST")]
    public async Task Every_Request_Goes_To_A_URL_The_Server_Handed_Out()
    {

        var client  = await ClientWithAccountAsync();
        var issued  = await ObtainAsync(client);
        await client.GetRenewalInfoAsync(issued.Certificate);

        var handedOut = Server.HandedOutURLs.ToHashSet();

        foreach (var request in Server.Requests)
        {
            if (request.Resource == "renewalInfo")
                Assert.That(request.URL, Does.StartWith(request.HandedOutURL + "/"), request.ToString());
            else
                Assert.That(handedOut, Does.Contain(request.URL), $"a URL handed out: {request}");
        }

    }

    /// <summary>
    /// Section 6.4.1: <i>"The value of the "url" header parameter MUST be a
    /// string representing the target URL."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.4.1")]
    [Property("Level", "MUST")]
    public async Task The_url_Of_Every_Request_Is_The_URL_It_Is_Sent_To()
    {

        foreach (var request in await IssuanceAsync())
            Assert.That(request.HeaderURL, Is.EqualTo(request.URL), request.ToString());

    }

    /// <summary>
    /// A URL of the given shape for a resource: what RFC 3986 allows, and a
    /// client that parses a URL and writes it out again may change.
    /// </summary>
    private String Shaped(String Shape, String Kind, String Id)

        => Shape switch {
               "a query"             => $"{Server.BaseURL}/acme/{Kind}?id={Id}",
               "an escaped slash"    => $"{Server.BaseURL}/acme/{Kind}/{Id}%2F0",
               "an escaped space"    => $"{Server.BaseURL}/acme/{Kind}/{Id}%200",
               "an escaped tilde"    => $"{Server.BaseURL}/acme/{Kind}/%7E{Id}",
               "a lower-case escape" => $"{Server.BaseURL}/acme/{Kind}/{Id}%3a0",
               "a dot segment"       => $"{Server.BaseURL}/acme/./{Kind}/{Id}",
               _                     => Server.DefaultURLFor(Kind, Id)
           };

    private async Task IssueAnywayAsync()
    {
        try
        {
            var client = await ClientWithAccountAsync();
            await ObtainAsync(client);
        }
        catch (Exception)
        {
            // What the client did is in the requests; the server refused it there.
        }
    }

    /// <summary>
    /// Section 6.4: <i>"In POST requests sent to these resources, the client
    /// MUST set the "url" header parameter to the exact string provided by the
    /// server (rather than performing any re-encoding on the URL)."</i> - the
    /// URLs of the order, the authorizations, the challenges, the finalization
    /// and the certificate in a shape RFC 3986 allows: a client that takes the
    /// string through a URL parser and writes it out again sends another one.
    /// </summary>
    [TestCase("plain")]
    [TestCase("a query")]
    [TestCase("an escaped slash")]
    [TestCase("an escaped space",    Category = TestCategories.KnownIssue)]
    [TestCase("an escaped tilde",    Category = TestCategories.KnownIssue)]
    [TestCase("a lower-case escape")]
    [TestCase("a dot segment",       Category = TestCategories.KnownIssue)]
    [Property("RFC", "8555 §6.4")]
    [Property("Level", "MUST")]
    [Property("Finding", "C-2")]
    public async Task The_url_Is_The_Exact_String_The_Server_Handed_Out(String Shape)
    {

        Server.URLFor = (kind, id) => kind is "order" or "authz" or "challenge" or "finalize" or "certificate"
                                          ? Shaped(Shape, kind, id)
                                          : Server.DefaultURLFor(kind, id);

        await IssueAnywayAsync();

        var shaped = Server.SignedRequests.Where(request => request.Resource is "order" or "authz" or "challenge" or "finalize" or "certificate").ToArray();

        Assert.That(shaped.Select(request => request.Resource), Does.Contain("authz"), Log);

        foreach (var request in shaped)
            Assert.That(request.HeaderURL, Is.EqualTo(request.HandedOutURL), $"the \"url\" as handed out: {request}");

    }

    /// <summary>
    /// Section 6.2: the "kid" <i>"MUST contain the account URL received by
    /// POSTing to the newAccount resource"</i> - received, as a string, and
    /// sent back as that string: of every shape RFC 3986 allows.
    /// </summary>
    [TestCase("plain")]
    [TestCase("a query")]
    [TestCase("an escaped slash")]
    [TestCase("an escaped space",    Category = TestCategories.KnownIssue)]
    [TestCase("an escaped tilde",    Category = TestCategories.KnownIssue)]
    [TestCase("a lower-case escape")]
    [TestCase("a dot segment",       Category = TestCategories.KnownIssue)]
    [Property("RFC", "8555 §6.2")]
    [Property("Level", "MUST")]
    [Property("Finding", "C-2")]
    public async Task The_kid_Is_The_Exact_Account_URL_The_Server_Handed_Out(String Shape)
    {

        Server.URLFor = (kind, id) => kind == "account"
                                          ? Shaped(Shape, kind, id)
                                          : Server.DefaultURLFor(kind, id);

        await IssueAnywayAsync();

        var signed = Server.SignedRequests.Where(request => request.Kid is not null).ToArray();

        Assert.That(signed, Is.Not.Empty, Log);

        foreach (var request in signed)
            Assert.That(request.Kid, Is.EqualTo(Server.Accounts.Single().URL), $"the \"kid\" as handed out: {request}");

    }

    #endregion

    #region Section 6.1 - HTTP

    /// <summary>
    /// Section 6.1: <i>"ACME clients MUST send a User-Agent header field, in
    /// accordance with [RFC7231]."</i> - with every request: the directory,
    /// the nonces, the POSTs, the renewal information.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.1")]
    [Property("Level", "MUST")]
    public async Task Every_Request_Has_A_User_Agent()
    {

        var client = await ClientWithAccountAsync();
        var issued = await ObtainAsync(client);
        await client.GetRenewalInfoAsync(issued.Certificate);

        foreach (var request in Server.Requests)
            Assert.That(request.Header("User-Agent"), Is.Not.Null.And.Not.Empty, request.ToString());

    }

    /// <summary>
    /// Section 6.1: <i>"This header field SHOULD include the name and version
    /// of the ACME software in addition to the name and version of the
    /// underlying HTTP client software."</i> - two products of RFC 9110,
    /// section 10.1.5, "name/version" each.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.1")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-10")]
    public async Task The_User_Agent_Names_The_ACME_Software_And_The_HTTP_Client()
    {

        var client     = await ClientWithAccountAsync();
        await ObtainAsync(client);

        var userAgent  = Server.Requests.First().Header("User-Agent") ?? "";
        var products   = Regex.Matches(userAgent, @"[!#$%&'*+\-.^_`|~0-9A-Za-z]+/[!#$%&'*+\-.^_`|~0-9A-Za-z]+").Count;

        Assert.That(products, Is.GreaterThanOrEqualTo(2), $"User-Agent: {userAgent}");

    }

    /// <summary>
    /// Section 6.1: <i>"ACME clients SHOULD send an Accept-Language header
    /// field in accordance with [RFC7231] to enable localization of error
    /// messages."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.1")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-11")]
    public async Task An_Accept_Language_Is_Sent()
    {

        await IssuanceAsync();

        foreach (var request in Server.Requests.Where(request => request.Method == "POST"))
            Assert.That(request.Header("Accept-Language"), Is.Not.Null.And.Not.Empty, request.ToString());

    }

    #endregion

}
