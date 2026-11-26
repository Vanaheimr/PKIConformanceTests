using System.Net;
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.2: a fresh nonce for the next request - and section
/// 6.5.1: what a nonce looks like.
/// </summary>
/// <remarks>
/// <para>
/// <i>"To get a fresh nonce, the client sends a HEAD request to the newNonce
/// resource on the server. The server's response MUST include a Replay-Nonce
/// header field containing a fresh nonce and SHOULD have status code 200 (OK).
/// The server MUST also respond to GET requests for this resource, returning
/// an empty body (while still providing a Replay-Nonce header) with a status
/// code of 204 (No Content). The server MUST include a Cache-Control header
/// field with the "no-store" directive in responses for the newNonce resource,
/// in order to prevent caching of this resource."</i>
/// </para>
/// <para>
/// A nonce served from a cache is a nonce somebody used before: every request
/// signed with it is refused as a replay, and a client that does not get past
/// badNonce gets nowhere at all.
/// </para>
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.2")]
public partial class NewNonceTests(String ServerName)
{

    private IACMEServerUnderTest?  server;
    private Uri?                   newNonce;
    private HttpClient             http = null!;

    /// <summary>
    /// <i>"Replay-Nonce = 1*base64url"</i>, with <i>"base64url = ALPHA / DIGIT /
    /// "-" / "_""</i> - section 6.5.1.
    /// </summary>
    [GeneratedRegex("^[A-Za-z0-9_-]+$")]
    private static partial Regex Base64Url();

    [OneTimeSetUp]
    public async Task StartServer()
    {

        server = await ServersUnderTest.StartAsync(ServerName);
        http   = server.TLS.NewHttpClient();

        var directory = JObject.Parse(await http.GetStringAsync(server.DirectoryURL));
        newNonce      = new Uri(directory.Value<String>("newNonce") ?? throw new InvalidOperationException($"{server.Name}: the directory has no newNonce"));

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        http?.Dispose();
        if (server is not null)
            await server.DisposeAsync();
    }

    private async Task<HttpResponseMessage> Send(HttpMethod Method)
        => await http.SendAsync(new HttpRequestMessage(Method, newNonce));

    private static String? NonceOf(HttpResponseMessage Response)
        => Response.Headers.TryGetValues("Replay-Nonce", out var values) ? String.Join(",", values) : null;


    [Test]
    [Property("Level", "MUST")]
    public async Task HEAD_Is_Answered_With_A_Nonce()
    {
        using var response = await Send(HttpMethod.Head);
        Assert.That(NonceOf(response), Is.Not.Null.And.Not.Empty, $"{server!.Name}: HEAD {newNonce} answered without a Replay-Nonce");
    }

    [Test]
    [Property("Level", "SHOULD")]
    public async Task HEAD_Is_Answered_With_200()
    {
        using var response = await Send(HttpMethod.Head);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), $"{server!.Name}: HEAD {newNonce}");
    }

    [Test]
    [Property("Level", "MUST")]
    public async Task GET_Is_Answered_With_204_A_Nonce_And_No_Body()
    {

        using var response = await Send(HttpMethod.Get);
        var       body     = await response.Content.ReadAsByteArrayAsync();

        Assert.Multiple(() => {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.NoContent), $"{server!.Name}: GET {newNonce}");
            Assert.That(NonceOf(response),   Is.Not.Null.And.Not.Empty,            $"{server!.Name}: GET {newNonce} answered without a Replay-Nonce");
            Assert.That(body,                Is.Empty,                             $"{server!.Name}: GET {newNonce} answered with a body");
        });

    }

    [TestCase("HEAD")]
    [TestCase("GET")]
    [Property("Level", "MUST")]
    public async Task Neither_Answer_May_Be_Cached(String Method)
    {

        using var response = await Send(new HttpMethod(Method));

        Assert.That(response.Headers.CacheControl?.NoStore, Is.True,
                    $"{server!.Name}: {Method} {newNonce} answered with Cache-Control: {response.Headers.CacheControl?.ToString() ?? "(none)"}");

    }

    /// <summary>
    /// Section 6.5.1: <i>"The value of the Replay-Nonce header field MUST be an
    /// octet string encoded according to the base64url encoding"</i> - one
    /// value, without padding.
    /// </summary>
    [Test]
    [Property("RFC",   "8555 §6.5.1")]
    [Property("Level", "MUST")]
    public async Task A_Nonce_Is_Base64Url()
    {

        using var response = await Send(HttpMethod.Head);
        var       nonce    = NonceOf(response) ?? "";

        Assert.That(Base64Url().IsMatch(nonce), Is.True, $"{server!.Name}: Replay-Nonce \"{nonce}\"");

    }

    /// <summary>
    /// Section 6.5.1: <i>"The server MUST generate the values provided in
    /// Replay-Nonce header fields in such a way that they are unique to each
    /// message, with high probability, and unpredictable to anyone besides the
    /// server."</i> Uniqueness is what a test can see.
    /// </summary>
    [Test]
    [Property("RFC",   "8555 §6.5.1")]
    [Property("Level", "MUST")]
    public async Task Every_Answer_Has_A_Nonce_Of_Its_Own()
    {

        var nonces = new List<String>();

        for (var i = 0; i < 50; i++)
        {
            using var response = await Send(i % 2 == 0 ? HttpMethod.Head : HttpMethod.Get);
            nonces.Add(NonceOf(response) ?? "");
        }

        Assert.That(nonces, Is.Unique, $"{server!.Name} handed out a nonce twice");

    }

}
