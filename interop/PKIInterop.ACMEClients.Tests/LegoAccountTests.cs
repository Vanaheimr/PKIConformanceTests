using Newtonsoft.Json.Linq;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// lego opens accounts at the ACME server under test (RFC 8555, section
/// 7.3) - with every kind of account key it has, and so with every signature
/// algorithm a server has to check.
/// </summary>
/// <remarks>
/// <para>
/// Hermod's client signs with ECDSA only, so against Hermod alone the RSA
/// paths of the server (RS256) are never walked. lego walks them, and with
/// its own JWS code, its own JSON and its own HTTP stack.
/// </para>
/// <para>
/// lego also has account keys of ML-DSA (FIPS 204), which no ACME server of
/// RFC 8555 knows. The server has to refuse them, and to say why in a way a
/// client understands: <i>"If the server receives a request signed with an
/// algorithm it does not support, it MUST return an error with status code
/// 400 (Bad Request) and type badSignatureAlgorithm"</i> (section 6.2).
/// </para>
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Category(TestCategories.Wsl)]
[Property("RFC", "8555 §7.3")]
public class LegoAccountTests(String ServerName)
{

    private IACMEServerUnderTest? server;

    [OneTimeSetUp]
    public async Task StartServer()
    {

        TestEnvironment.RequireWsl("lego");

        server = await ServersUnderTest.StartAsync(ServerName, new ACMEServerOptions(ReachableFromWsl: true));

        TestEnvironment.RequireReachableFromWsl(server.DirectoryURLFromWsl ?? throw new InvalidOperationException($"{server.Name} is not reachable from WSL."),
                                                server.TLS.RootFile);

        TestContext.Progress.WriteLine($"{Lego.Version} against {server.Name} at {server.DirectoryURLFromWsl}");

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        if (server is not null)
            await server.DisposeAsync();
    }

    /// <summary>The test's cell of the interop matrix, into its output (InteropCells).</summary>
    [SetUp]
    public void DeclareCell()
        => InteropMatrix.Declare(InteropCells.Clients, Lego.Name, ServerName == ServersUnderTest.PKI ? Revisions.PKI : ServerName);


    /// <summary>
    /// A new account, for a key of the given type: lego says so, and what it
    /// keeps of the server's answer is a valid account at a URL of the server,
    /// with the contact it asked for.
    /// </summary>
    [TestCase("EC256",   "ES256")]
    [TestCase("EC384",   "ES384")]
    [TestCase("RSA2048", "RS256")]
    [TestCase("RSA3072", "RS256")]
    [TestCase("RSA4096", "RS256")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.Account)]
    public void Lego_Registers_An_Account(String KeyType, String Algorithm)
    {

        using var lego    = new Lego(server!.TLS.RootFile);
        var       email   = $"lego-{KeyType.ToLowerInvariant()}@acme.test";

        var       result  = lego.Run($"accounts register --server '{server!.DirectoryURLFromWsl}' --accept-tos --email '{email}' --key-type {KeyType}");

        Assert.That(result.Success, Is.True, $"{Lego.Version} could not register an {KeyType} account ({Algorithm}) at {server.Name}:\n{result}");

        var accounts = lego.Files("account.json");

        Assert.That(accounts, Has.Count.EqualTo(1), $"{Lego.Version} kept no account, or several:\n{String.Join("\n", accounts.Select(account => account.Path))}");

        // lego 5 keeps the account object of the server's answer as
        // "registration", with the Location it came with as "accountURL".
        var stored        = JObject.Parse(accounts[0].Content);
        var registration  = stored["registration"] as JObject;

        Assert.Multiple(() => {

            Assert.That(registration?.Value<String>("accountURL"),  Does.StartWith($"{server.DirectoryURLFromWsl!.GetLeftPart(UriPartial.Authority)}/"),
                                                                    $"the account is not at a URL of the server - the Location of section 7.3: {stored}");

            Assert.That(registration?.Value<String>("status"),      Is.EqualTo("valid"),
                                                                    $"a new account is valid (section 7.1.2): {stored}");

            Assert.That(registration?["contact"]?.Values<String>(), Is.EqualTo(new[] { $"mailto:{email}" }),
                                                                    $"the server answers with the contact asked for: {stored}");

            Assert.That(registration?.Value<String>("orders"),      Does.StartWith($"{server.DirectoryURLFromWsl!.GetLeftPart(UriPartial.Authority)}/"),
                                                                    $"an account object has \"orders\" (section 7.1.2: \"orders (required, string)\"): {stored}");

        });

    }

    /// <summary>
    /// An account key of ML-DSA - which RFC 8555 does not know - refused as
    /// section 6.2 has it: badSignatureAlgorithm, which lego shows.
    /// </summary>
    [Test]
    [Property("RFC",   "8555 §6.2")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountKeys)]
    public void An_MLDSA_Account_Key_Is_Refused_As_badSignatureAlgorithm()
    {

        using var lego   = new Lego(server!.TLS.RootFile);
        var       result = lego.Run($"accounts register --server '{server!.DirectoryURLFromWsl}' --accept-tos --email mldsa@acme.test --key-type MLDSA44");

        Assert.Multiple(() => {
            Assert.That(result.Success, Is.False,                                  $"{server.Name} opened an account for an ML-DSA key:\n{result}");
            Assert.That(result.StdOut,  Does.Contain("badSignatureAlgorithm"),     $"{server.Name} refused the ML-DSA key, but not as badSignatureAlgorithm:\n{result}");
        });

    }

}
