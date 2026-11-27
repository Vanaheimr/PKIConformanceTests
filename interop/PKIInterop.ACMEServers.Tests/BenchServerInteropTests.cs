using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;

namespace PKIInterop.ACMEServers.Tests;

/// <summary>
/// The bench of interop B, tested before it judges anything (PLAN.md,
/// "Learned in phase 3" and "in phase 4"): the name servers answer what the
/// servers ask, the servers start and hand out what they issue by, and the
/// judge of the wire finds nothing in a client of the suite's own - and
/// what is wrong where it is.
/// </summary>
/// <remarks>
/// Nothing here is Hermod's: the client is RawACMEClient, every check .NET,
/// dig and openssl.
/// </remarks>
[Category(TestCategories.Wsl)]
public sealed class BenchServerInteropTests
{

    /// <summary>RFC 8555, section 6.1: "Clients MUST send a User-Agent header field" - and Pebble 2.10.3 refuses a request without one.</summary>
    private const String UserAgent = "PKIConformance-Bench/1.0";

    private static PebbleBuild Build(String Name)
        => Name == "Debian" ? PebbleBuild.Debian : PebbleBuild.Upstream;

    [OneTimeSetUp]
    public void RequirePeers()
    {

        if (Wsl.UsesWslBridge)
            Assert.Ignore("The bench of interop B runs natively in Linux: wsl sh build/test-in-wsl.sh --filter \"TestCategory=WSL\"");

        TestEnvironment.RequireWsl(PebbleBuild.Debian.Binary, PebbleBuild.Upstream.Binary, PebbleBuild.Upstream.ChallTestSrvBinary, "step-ca", "dig", "openssl");

    }


    #region challtestsrv

    [TestCase("Debian")]
    [TestCase("Upstream")]
    public async Task ChallTestSrv_Answers_Every_Name_With_The_Loopback_And_Takes_TXT_Records(String Of)
    {

        using var dns = ChallTestSrv.Start(Build(Of).ChallTestSrvBinary);

        var name      = $"n{Guid.NewGuid():N}"[..12] + ".acme.test";

        await dns.SetTXTAsync($"_acme-challenge.{name}", "first");
        await dns.SetTXTAsync($"_acme-challenge.{name}", "second");

        var both      = dns.Query($"_acme-challenge.{name}", "TXT");

        await dns.ClearTXTAsync($"_acme-challenge.{name}");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(dns.Query(name, "A"),                          Is.EqualTo(new[] { "127.0.0.1" }),           dns.Log);
            Assert.That(dns.Query(name, "AAAA"),                       Is.Empty,                                    "no ::1: the servers ask 127.0.0.1");
            Assert.That(both,                                          Is.EquivalentTo(new[] { "\"first\"", "\"second\"" }), dns.Log);
            Assert.That(dns.Query($"_acme-challenge.{name}", "TXT"),   Is.Empty,                                    dns.Log);
        }

    }

    #endregion


    #region The servers

    [TestCase("Debian")]
    [TestCase("Upstream")]
    public async Task Pebble_Starts_And_Hands_Out_The_Root_It_Issues_By(String Of)
    {

        using var pebble    = Pebble.Start(Build(Of), ChallTestSrv.FreeTcpPort());
        using var http      = new HttpClient(RecordingHandler.TrustingHandler(pebble.TrustedRootFile));
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);

        var directory       = JsonNode.Parse(await http.GetStringAsync(pebble.DirectoryURL));
        using var root      = X509Certificate2.CreateFromPem(await pebble.RootPEMAsync());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(directory?["newAccount"]?.GetValue<String>(), Does.StartWith($"https://127.0.0.1:{pebble.Port}/"), pebble.Log);
            Assert.That(root.Subject,                                  Is.EqualTo(root.Issuer),                           "a root");
            Assert.That(root.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority, Is.True);
        }

    }

    [Test]
    public async Task StepCA_Starts_And_Its_CRL_Is_Signed_By_Its_Intermediate()
    {

        using var stepCA    = StepCA.Start(ChallTestSrv.FreeTcpPort());
        using var http      = new HttpClient(RecordingHandler.TrustingHandler(stepCA.TrustedRootFile));
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);

        var directory       = JsonNode.Parse(await http.GetStringAsync(stepCA.DirectoryURL));
        var signed          = OpenSSL.VerifyCRL(await stepCA.CRLAsync(), stepCA.IntermediatePEM);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(directory?["newOrder"]?.GetValue<String>(), Does.StartWith($"https://127.0.0.1:{stepCA.Port}/acme/acme/"), stepCA.Log);
            Assert.That(signed.StdOut,                               Does.Contain("verify OK"),                                       $"{signed}");
        }

    }

    #endregion


    #region The judge of the wire

    /// <summary>
    /// What RawACMEClient sends Pebble - an account, an order, a look at it -
    /// recorded and judged: nothing wrong.
    /// </summary>
    private static async Task<(RecordingHandler Wire, IReadOnlyList<String> Wrong)> RecordAsync()
    {

        using var pebble  = Pebble.Start(PebbleBuild.Upstream, ChallTestSrv.FreeTcpPort());
        var wire          = new RecordingHandler(pebble.TrustedRootFile);
        using var http    = new HttpClient(wire, disposeHandler: false);
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);

        var client        = await RawACMEClient.ConnectAsync(http, pebble.DirectoryURL);
        var account       = await client.AccountAsync();
        var order         = await client.OrderAsync(account, ("dns", "www.acme.test"));

        await client.RefreshAsync(account, order);

        return (wire, WireForm.Judge(wire.Exchanges));

    }

    [Test]
    public async Task The_Judge_Finds_Nothing_Wrong_With_A_Client_Of_The_Suites_Own()
    {

        var (wire, wrong) = await RecordAsync();

        using (wire)
        {
            Assert.That(wire.Exchanges.Count(exchange => exchange.Method == "POST"), Is.GreaterThanOrEqualTo(3), wire.Log);
            Assert.That(wrong,                                                       Is.Empty,                   $"{String.Join("\n", wrong)}\n{wire.Log}");
        }

    }

    [Test]
    public async Task The_Judge_Finds_A_Nonce_Used_Twice_And_A_GET_Of_An_Order()
    {

        var (wire, _)  = await RecordAsync();

        using (wire)
        {

            var exchanges  = wire.Exchanges;
            var last       = exchanges[^1];
            var order      = exchanges.First(exchange => exchange.Status == 201 && exchange.ResponseBody.Contains("\"identifiers\"", StringComparison.Ordinal));

            var replayed   = last  with { Number = last.Number + 1 };
            var fetched    = order with { Number = last.Number + 2, Method = "GET", URL = new Uri(order.Location!), RequestBody = "", ContentType = null };

            var wrong      = WireForm.Judge([ .. exchanges, replayed, fetched ]);

            using (Assert.EnterMultipleScope())
            {
                Assert.That(wrong.Any(line => line.StartsWith($"#{replayed.Number} ", StringComparison.Ordinal) && line.Contains("used again",  StringComparison.Ordinal)), Is.True, String.Join("\n", wrong));
                Assert.That(wrong.Any(line => line.StartsWith($"#{fetched.Number} ",  StringComparison.Ordinal) && line.Contains("POST-as-GET", StringComparison.Ordinal)), Is.True, String.Join("\n", wrong));
                Assert.That(wrong, Has.Count.EqualTo(2),                                                         String.Join("\n", wrong));
            }

        }

    }

    #endregion

}
