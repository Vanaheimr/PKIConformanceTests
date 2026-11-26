using NUnit.Framework;

using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 6.4: <i>"On receiving such an object in an HTTP request,
/// the server MUST compare the "url" header parameter to the request URL. If
/// the two do not match, then the server MUST reject the request as
/// unauthorized."</i> [...] <i>"The server MUST reject the request as
/// unauthorized if the string equality check fails."</i>
/// </summary>
/// <remarks>
/// The "url" is what binds a signature to the resource it was meant for:
/// without it, a request a proxy or anybody on the way sees can be sent
/// again to another resource. Each test sends a request of an account to its
/// account URL with a "url" that differs in one place.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §6.4")]
public class RequestURLTests(String ServerName) : ACMEServerFixture(ServerName)
{

    private RawACMEAccount account = null!;

    [OneTimeSetUp]
    public async Task Arrange()
        => account = await NewAccountAsync();

    /// <summary>
    /// The account URL, changed as the case says.
    /// </summary>
    private String Changed(String How)
    {

        var url = new Uri(account.URL);

        return How switch {
                   "scheme"          => "http" + account.URL["https".Length..],
                   "host"            => account.URL.Replace(url.Host, "localhost"),
                   "port"            => account.URL.Replace($":{url.Port}", $":{url.Port + 1}"),
                   "path case"       => account.URL.Replace("/acct/", "/ACCT/"),
                   "trailing slash"  => account.URL + "/",
                   "query"           => account.URL + "?x=1",
                   "fragment"        => account.URL + "#x",
                   "another account" => account.URL[..(account.URL.LastIndexOf('/') + 1)] + "0000000000000000",
                   "newOrder"        => Client.Resource("newOrder"),
                   _                 => throw new ArgumentException(How)
               };

    }

    /// <summary>
    /// A "url" that is not the request URL, by one difference: unauthorized.
    /// </summary>
    [TestCase("scheme")]
    [TestCase("host")]
    [TestCase("port")]
    [TestCase("path case")]
    [TestCase("trailing slash")]
    [TestCase("query")]
    [TestCase("fragment")]
    [TestCase("another account")]
    [TestCase("newOrder")]
    [Property("Level", "MUST")]
    public async Task A_url_Other_Than_The_Request_URL_Is_unauthorized(String How)
    {

        var other  = Changed(How);
        var answer = await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("url", other));

        AssertProblem(answer, 401, "unauthorized");

    }

    /// <summary>
    /// <i>"The "url" header parameter MUST be carried in the protected header of
    /// the JWS."</i> - a request without one is refused.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.4.1")]
    [Property("Level", "MUST")]
    public async Task A_Request_Without_url_Is_Refused()

        => AssertProblem(await Client.PostAsync(account, account.URL, null, Header: header => header.Remove("url")), null);

    /// <summary>
    /// The control: the account URL exactly as the server gave it.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_url_The_Server_Gave_Is_Taken()

        => AssertStatus(await Client.PostAsGetAsync(account, account.URL), 200);

}
