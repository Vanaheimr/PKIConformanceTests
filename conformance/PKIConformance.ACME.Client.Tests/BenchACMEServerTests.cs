using NUnit.Framework;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// The bench itself: <see cref="ScriptedACMEServer"/> driven by RawACME's
/// client - so that a test of Hermod that is green is green because Hermod
/// did it right, not because the server took anything. It refuses what RFC
/// 8555, section 6 refuses, validates http-01 as section 8.3 asks, and
/// refuses a CSR of other names.
/// </summary>
[TestFixture]
[Property("RFC", "8555 §6, §8.3")]
public class BenchACMEServerTests
{

    private ScriptedACMEServer     server = null!;
    private ScriptedChallengeHost  host   = null!;
    private RawACMEClient          raw    = null!;

    [SetUp]
    public async Task Start()
    {
        server            = ScriptedACMEServer.Start();
        host              = ScriptedChallengeHost.Start();
        server.HTTP01Port = host.Port;
        raw               = await RawACMEClient.ConnectAsync(new HttpClient(), new Uri(server.DirectoryURL));
    }

    [TearDown]
    public async Task Stop()
    {
        await host.DisposeAsync();
        await server.DisposeAsync();
    }


    /// <summary>
    /// Section 6.5: a nonce used once is refused the second time, badNonce.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Bench_Refuses_A_Nonce_Sent_Twice()
    {

        var nonce  = await raw.FreshNonceAsync();
        var first  = await raw.PostAsync(RawKey.Generate("ES256"), null, raw.Resource("newAccount"), """{"termsOfServiceAgreed":true}""", header => header.SetString("nonce", nonce));
        var second = await raw.PostAsync(RawKey.Generate("ES256"), null, raw.Resource("newAccount"), """{"termsOfServiceAgreed":true}""", header => header.SetString("nonce", nonce));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(first.Status,     Is.EqualTo(201),        first.ToString());
            Assert.That(second.ErrorType, Is.EqualTo("badNonce"), second.ToString());
        }

    }

    /// <summary>
    /// Section 6.4: a "url" other than the string handed out is unauthorized.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Bench_Refuses_A_url_Other_Than_Handed_Out()
    {

        var answer = await raw.PostAsync(RawKey.Generate("ES256"), null, raw.Resource("newAccount"), """{"termsOfServiceAgreed":true}""",
                                         header => header.SetString("url", raw.Resource("newAccount") + "/"));

        Assert.That(answer.ErrorType, Is.EqualTo("unauthorized"), answer.ToString());

    }

    /// <summary>
    /// Section 6.2: a Content-Type other than "application/jose+json" is
    /// refused.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Bench_Refuses_A_Content_Type_With_A_charset()
    {

        var answer = await raw.PostAsync(RawKey.Generate("ES256"), null, raw.Resource("newAccount"), """{"termsOfServiceAgreed":true}""",
                                         ContentType: "application/jose+json; charset=utf-8");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(answer.Status,    Is.EqualTo(415),        answer.ToString());
            Assert.That(answer.ErrorType, Is.EqualTo("malformed"), answer.ToString());
        }

    }

    /// <summary>
    /// Section 8.3: the bench asks the client's port 80 for the token, with
    /// the name as the Host, and takes the key authorization RawACME makes -
    /// the order is ready then.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3")]
    [Property("Level", "MUST")]
    public async Task The_Bench_Validates_http01_At_The_Name()
    {

        var account = await raw.AccountAsync();
        var order   = await raw.ReadyOrderAsync(account, host, ("dns", "www.acme.test"));
        var asked   = host.Requests.Single(request => request.Path.StartsWith("/.well-known/acme-challenge/", StringComparison.Ordinal));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(order.Status, Is.EqualTo("ready"));
            Assert.That(asked.Host,   Is.EqualTo("www.acme.test"));
            Assert.That(asked.Method, Is.EqualTo("GET"));
        }

    }

    /// <summary>
    /// Section 7.4: <i>"The CSR MUST indicate the exact same set of requested
    /// identifiers as the initial newOrder request."</i> - a CSR of another
    /// name is badCSR at the bench.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task The_Bench_Refuses_A_CSR_Of_Other_Names()
    {

        var account = await raw.AccountAsync();
        var order   = await raw.ReadyOrderAsync(account, host, ("dns", "www.acme.test"));

        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var answer    = await raw.FinalizeAsync(account, order, RawCSR.CreateBase64Url(key, [ ("dns", "other.acme.test") ]));

        Assert.That(answer.ErrorType, Is.EqualTo("badCSR"), answer.ToString());

    }

}
