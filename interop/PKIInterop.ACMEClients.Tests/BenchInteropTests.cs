using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.Scripted;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// The interop bench itself - so that a red interop test is red at the server
/// or at the peer, never at the bench: the names of the bench resolve, BIND
/// takes an update signed by its TSIG key and answers it, the system's CA
/// bundle laid over trusts the bench's root, and openssl tells a chain to
/// its root from one that is not.
/// </summary>
[TestFixture]
[Category(TestCategories.Wsl)]
public class BenchInteropTests
{

    /// <summary>The test's line of the interop matrix, into its output: the bench, counted apart.</summary>
    [SetUp]
    public void DeclareCell()
        => InteropMatrix.Declare(InteropCells.Bench, "bench of interop A", Revisions.PKI);

    /// <summary>
    /// Every name of the bench resolves to the loopback, by the system - as
    /// the PKI resolves http-01.
    /// </summary>
    [Test]
    public void The_Names_Of_The_Bench_Resolve_To_The_Loopback()
    {

        TestEnvironment.RequireWsl();
        TestEnvironment.RequireBenchNames();

        foreach (var name in BenchNames.All)
            Assert.That(System.Net.Dns.GetHostAddresses(name), Has.Some.Matches<IPAddress>(IPAddress.IsLoopback), name);

    }

    /// <summary>
    /// BIND takes an RFC 2136 update signed by the TSIG key - nsupdate's -
    /// writes it into its log, and answers the record through Hermod's
    /// DNSClient, as the PKI reads dns-01.
    /// </summary>
    [Test]
    public async Task BIND_Takes_A_Signed_Update_And_Answers_It()
    {

        TestEnvironment.RequireWsl("named", "nsupdate", "dig");

        using var bind = Bind.Start();

        var update = Wsl.Run($"printf 'server 127.0.0.1 {bind.Port}\\nzone {Bind.Zone}\\nupdate add _acme-challenge.{BenchNames.WWW}. 60 TXT \"bench\"\\nsend\\n' | " +
                             $"nsupdate -k '{bind.KeyFile}' 2>&1", TimeSpan.FromSeconds(30));

        var dig    = Wsl.Run($"dig +short -p {bind.Port} @127.0.0.1 _acme-challenge.{BenchNames.WWW} TXT", TimeSpan.FromSeconds(15));
        var info   = await bind.NewDNSClient().Query(org.GraphDefined.Vanaheimr.Hermod.DNS.DNSServiceName.Parse($"_acme-challenge.{BenchNames.WWW}"),
                                                     [ org.GraphDefined.Vanaheimr.Hermod.DNS.DNSResourceRecordTypes.TXT ], ForceUpdate: true);
        var hermod = info.Answers.OfType<org.GraphDefined.Vanaheimr.Hermod.DNS.TXT>().Select(txt => String.Concat(txt.Strings)).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(update.Success,  Is.True,                                                 update.ToString());
            Assert.That(bind.AddedTXT,   Has.Some.Contains($"_acme-challenge.{BenchNames.WWW}"),   bind.Log);
            Assert.That(dig.StdOut,      Does.Contain("\"bench\""),                               dig.ToString());
            Assert.That(hermod,          Has.Some.Contains("bench"),                              "Hermod's DNSClient reads it");
        }

    }

    /// <summary>
    /// An update signed by another key is refused: BIND is no zone anybody
    /// writes into.
    /// </summary>
    [Test]
    public void BIND_Refuses_An_Update_Of_Another_Key()
    {

        TestEnvironment.RequireWsl("named", "nsupdate");

        using var bind = Bind.Start();

        var other  = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var update = Wsl.Run($"printf 'server 127.0.0.1 {bind.Port}\\nzone {Bind.Zone}\\nupdate add x.{Bind.Zone}. 60 TXT \"no\"\\nsend\\n' | " +
                             $"nsupdate -y 'hmac-sha256:{Bind.KeyName}:{other}' 2>&1", TimeSpan.FromSeconds(30));

        Assert.That(bind.AddedTXT, Is.Empty, $"{update}\n{bind.Log}");

    }

    /// <summary>
    /// openssl tells a chain to the root from one to another root - so that
    /// "leaf.pem: OK" of a peer's certificate means something.
    /// </summary>
    [Test]
    public void OpenSSL_Tells_A_Chain_To_The_Root_From_Another()
    {

        TestEnvironment.RequireWsl("openssl");

        using var ca    = BenchCA.Create(Intermediates: 1);
        using var other = BenchCA.Create(Intermediates: 1, Name: "Another CA");
        using var key   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf  = ca.Issue(new CertificateRequest("CN=x", key, HashAlgorithmName.SHA256).PublicKey, [ ("dns", BenchNames.WWW) ],
                                   DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));

        var good  = OpenSSL.Verify(ca.Root.ExportCertificatePem(),    ca.ChainPem(leaf));
        var wrong = OpenSSL.Verify(other.Root.ExportCertificatePem(), ca.ChainPem(leaf));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(good.StdOut,  Does.Contain("leaf.pem: OK"),     good.ToString());
            Assert.That(wrong.StdOut, Does.Not.Contain("leaf.pem: OK"), wrong.ToString());
        }

    }

    /// <summary>
    /// The system's CA bundle laid over in the namespace of the run trusts the
    /// bench's root - what uacme needs - and curl, which reads the system's
    /// bundle, takes a server of it.
    /// </summary>
    [Test]
    public async Task The_System_s_Bundle_Laid_Over_Trusts_The_Bench_s_Root()
    {

        TestEnvironment.RequireWsl("curl");

        await using var server = await PKIConformance.Core.Servers.ServersUnderTest.StartAsync(PKIConformance.Core.Servers.ServersUnderTest.PKI,
                                                                                                new PKIConformance.Core.Servers.ACMEServerOptions(ReachableFromWsl: true));

        TestEnvironment.TrustSystemWide(server.TLS.RootFile);

        var curl = Wsl.Run($"curl -s -o /dev/null -w '%{{http_code}}' '{server.DirectoryURLFromWsl}'", TimeSpan.FromSeconds(30));

        Assert.That(curl.StdOut.Trim(), Is.EqualTo("200"), curl.ToString());

    }

}
