using System.Net;
using System.Text;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Validation.Tests;

/// <summary>
/// RFC 8555, section 8.3, http-01: <i>"Dereference the URL using an HTTP GET
/// request."</i> [...] <i>"Verify that the body of the response is a
/// well-formed key authorization. The server SHOULD ignore whitespace
/// characters at the end of the body."</i> <i>"Verify that key authorization
/// provided by the HTTP server matches the key authorization stored by the
/// server."</i> <i>"The server SHOULD follow redirects when dereferencing the
/// URL."</i> - and RFC 8738, section 5, of an address.
/// </summary>
/// <remarks>
/// <para>
/// http-01 is a CA asking a web server whether a name is somebody's: a
/// validator that takes a body that is not the key authorization, or that
/// takes one from where it was not asked, issues for a name nobody proved.
/// </para>
/// <para>
/// The names are addresses, which need no resolution (RFC 8738, section 4:
/// <i>"their initial DNS resolution step MUST be skipped"</i>); the port is
/// the host's, as the server under test was started with it - section 8.3
/// has port 80, which a bench does not hold.
/// </para>
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §8.3")]
public class HTTP01ValidationTests(String ServerName) : ValidationFixture(ServerName)
{

    private static readonly (String Type, String Value) Loopback4 = ("ip", "127.0.0.1");
    private static readonly (String Type, String Value) Loopback6 = ("ip", "::1");

    private Task<Validation> AnsweredAsync((String Type, String Value) Identifier, Func<String, String, HostAnswer> Answer)
        => ValidateAsync(Identifier, "http-01", (token, keyAuthorization) => Host.AnswerChallenge(token, _ => Answer(token, keyAuthorization)));

    /// <summary>
    /// No proof - after the host was asked: a validator that never asks
    /// refuses every answer, the wrong ones among them, and proves nothing by it.
    /// </summary>
    private void AssertNoProof(Validation Validation)
    {
        Assert.Multiple(() => {
            Assert.That(Host.RequestsOf(ScriptedChallengeHost.ChallengePath(Validation.Token)), Is.Not.Empty, $"the host was asked: {Validation}");
            Assert.That(Validation.Status, Is.EqualTo("invalid"), Validation.ToString());
        });
    }


    #region The request

    /// <summary>
    /// The key authorization as a client serves it: valid - and asked for as
    /// section 8.3 and RFC 8738, section 5, say: a GET of
    /// "/.well-known/acme-challenge/{token}", with <i>"the Host header field
    /// MUST be set to the IP address being used for validation"</i> (and the
    /// port, which RFC 9110, section 7.2, adds where it is not 80).
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, 8738 §5")]
    [Property("Level", "MUST")]
    public async Task The_Key_Authorization_Is_Asked_For_By_A_GET_Of_Its_Path_And_Taken()
    {

        var validation = await AnsweredAsync(Loopback4, (_, keyAuthorization) => HostAnswer.Text(keyAuthorization));
        var requests   = Host.RequestsOf(ScriptedChallengeHost.ChallengePath(validation.Token));

        Assert.Multiple(() => {
            Assert.That(validation.Status,                       Is.EqualTo("valid"),                                       validation.ToString());
            Assert.That(requests,                                Is.Not.Empty,                                              "the host was asked");
            Assert.That(requests.Select(request => request.Method), Has.All.EqualTo("GET"),                                 "by GET");
            Assert.That(requests.Select(request => request.Host),    Has.All.EqualTo($"127.0.0.1:{Host.Port}").Or.EqualTo("127.0.0.1"), "Host: the address");
        });

    }

    /// <summary>
    /// The same of an IPv6 address: RFC 8738, section 5, the textual form of
    /// RFC 5952 - and in a Host header, in brackets (RFC 3986, section 3.2.2).
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, 8738 §5")]
    [Property("Level", "MUST")]
    public async Task An_IPv6_Address_Is_Asked_At_The_Address()
    {

        if (!Host.IPv6)
            Assert.Ignore("::1 cannot be listened on here.");

        var validation = await AnsweredAsync(Loopback6, (_, keyAuthorization) => HostAnswer.Text(keyAuthorization));
        var requests   = Host.RequestsOf(ScriptedChallengeHost.ChallengePath(validation.Token));

        Assert.Multiple(() => {
            Assert.That(validation.Status,                              Is.EqualTo("valid"),                                     validation.ToString());
            Assert.That(requests.Select(request => request.Local.Address), Has.All.EqualTo(IPAddress.IPv6Loopback),              "asked at ::1");
            Assert.That(requests.Select(request => request.Host),        Has.All.EqualTo($"[::1]:{Host.Port}").Or.EqualTo("[::1]"), "Host: the address in brackets");
        });

    }

    #endregion

    #region The answer

    /// <summary>
    /// Step 4: <i>"The server SHOULD ignore whitespace characters at the end of
    /// the body."</i> - a newline, CRLF, spaces and a tab.
    /// </summary>
    [TestCase("\n")]
    [TestCase("\r\n")]
    [TestCase("  \t\n")]
    [Property("Level", "SHOULD")]
    public async Task Whitespace_At_The_End_Is_Ignored(String Whitespace)
    {

        var validation = await AnsweredAsync(Loopback4, (_, keyAuthorization) => HostAnswer.Text(keyAuthorization + Whitespace));

        Assert.That(validation.Status, Is.EqualTo("valid"), validation.ToString());

    }

    /// <summary>
    /// Steps 4 and 5: what is not the key authorization - with whitespace in
    /// front, a character more, the token alone, another account's
    /// thumbprint, the key authorization twice - is no proof: the
    /// authorization is invalid, and its challenge says why (section 8.2:
    /// <i>"The server MUST add an entry to the "error" field in the challenge
    /// after each failed validation query."</i>).
    /// </summary>
    [TestCase("leading whitespace")]
    [TestCase("one character more")]
    [TestCase("the token alone")]
    [TestCase("another thumbprint")]
    [TestCase("twice")]
    [TestCase("empty")]
    [Property("RFC", "8555 §8.3, §8.2")]
    [Property("Level", "MUST")]
    public async Task What_Is_Not_The_Key_Authorization_Is_No_Proof(String What)
    {

        var validation = await AnsweredAsync(Loopback4, (token, keyAuthorization) => HostAnswer.Text(What switch {
                                                 "leading whitespace"  => " " + keyAuthorization,
                                                 "one character more"  => keyAuthorization + "x",
                                                 "the token alone"     => token,
                                                 "another thumbprint"  => token + ".NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
                                                 "twice"               => keyAuthorization + keyAuthorization,
                                                 _                     => ""
                                             }));

        Assert.Multiple(() => {
            AssertNoProof(validation);
            Assert.That(validation.ErrorType,  Is.Not.Null,            $"the challenge's \"error\": {validation}");
        });

    }

    /// <summary>
    /// <i>"If the request fails, or the body does not pass these checks, then
    /// it has failed."</i> - a status other than success, with the key
    /// authorization as its body even.
    /// </summary>
    [TestCase(404)]
    [TestCase(500)]
    [TestCase(403)]
    [Property("Level", "MUST")]
    public async Task An_Error_Status_Is_No_Proof_Whatever_The_Body(Int32 Status)
    {

        var validation = await AnsweredAsync(Loopback4, (_, keyAuthorization) => HostAnswer.Text(keyAuthorization, Status));

        AssertNoProof(validation);

    }

    /// <summary>
    /// A body far longer than any key authorization, which begins with it:
    /// not the key authorization.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Body_That_Only_Begins_With_The_Key_Authorization_Is_No_Proof()
    {

        var validation = await AnsweredAsync(Loopback4, (_, keyAuthorization) => HostAnswer.Text(keyAuthorization + new String('x', 20000)));

        AssertNoProof(validation);

    }

    /// <summary>
    /// An answer that is no HTTP: the request failed.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Answer_That_Is_No_HTTP_Is_No_Proof()
    {

        var validation = await AnsweredAsync(Loopback4, (_, keyAuthorization) => new HostAnswer(Raw: Encoding.ASCII.GetBytes(keyAuthorization + "\r\n")));

        AssertNoProof(validation);

    }

    /// <summary>
    /// A host that never answers: the validation fails, in its time - it does
    /// not stay "processing" for ever.
    /// </summary>
    [Test]
    [Category(TestCategories.Slow)]
    [Property("Level", "MUST")]
    public async Task A_Host_That_Never_Answers_Is_No_Proof()
    {

        var validation = await AnsweredAsync(Loopback4, (_, _) => new HostAnswer(Hang: true));

        AssertNoProof(validation);

    }

    #endregion

    #region Redirects

    /// <summary>
    /// <i>"The server SHOULD follow redirects when dereferencing the URL.
    /// Clients might use redirects, for example, so that the response can be
    /// provided by a centralized certificate management server."</i>
    /// </summary>
    [TestCase(301)]
    [TestCase(302)]
    [TestCase(307)]
    [TestCase(308)]
    [Property("Level", "SHOULD")]
    public async Task A_Redirect_Is_Followed(Int32 Status)
    {

        var validation = await ValidateAsync(Loopback4, "http-01", (token, keyAuthorization) => {
                             Host.AnswerChallenge(token, _ => HostAnswer.Redirect($"http://127.0.0.1:{Host.Port}/central/{token}", Status));
                             Host.Answer($"/central/{token}", _ => HostAnswer.Text(keyAuthorization));
                         });

        Assert.That(validation.Status, Is.EqualTo("valid"), validation.ToString());

    }

    /// <summary>
    /// Redirects in a loop: the validation fails, and the validator stops
    /// following them (section 10.2, <i>"limit the number of redirects"</i>).
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, §10.2")]
    [Property("Level", "MUST")]
    public async Task Redirects_In_A_Loop_Are_No_Proof()
    {

        var validation = await ValidateAsync(Loopback4, "http-01", (token, _) => {
                             Host.AnswerChallenge(token, _ => HostAnswer.Redirect($"http://127.0.0.1:{Host.Port}/loop/{token}"));
                             Host.Answer($"/loop/{token}", _ => HostAnswer.Redirect($"http://127.0.0.1:{Host.Port}{ScriptedChallengeHost.ChallengePath(token)}"));
                         });

        var asked = Host.Requests.Count(request => request.Path.EndsWith(validation.Token, StringComparison.Ordinal));

        Assert.Multiple(() => {
            AssertNoProof(validation);
            Assert.That(asked,             Is.LessThanOrEqualTo(50),         "the redirects were given up on");
        });

    }

    #endregion

    #region Names (ToDo T-S5)

    /// <summary>
    /// PLAN.md, section 0.3: a name of http-01 is resolved through the
    /// server's own DNSClient - here pointed at the bench's name server, which
    /// alone knows "www.acme.test". A tracker of T-S5 until the validator
    /// resolves that way.
    /// </summary>
    [Test]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-S5")]
    [Property("Level", "MUST")]
    public async Task A_Name_Is_Resolved_Through_The_Server_s_DNSClient()
    {

        DNS.AddAddress("www.acme.test", IPAddress.Loopback);

        var validation = await AnsweredAsync(("dns", "www.acme.test"), (_, keyAuthorization) => HostAnswer.Text(keyAuthorization));

        Assert.Multiple(() => {
            Assert.That(DNS.QuestionsFor("www.acme.test"), Is.Not.Empty,        "the bench's name server was asked");
            Assert.That(validation.Status,                 Is.EqualTo("valid"), validation.ToString());
        });

    }

    #endregion

}
