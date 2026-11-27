using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.ACME;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using PKIConformance.Core;
using PKIConformance.Core.Peers;

namespace PKIInterop.ACMEServers.Tests;

/// <summary>
/// The bench of a test of Hermod's client against an ACME server of the
/// world: the client's "port 80" - Hermod HTTP servers on 127.0.0.1 and ::1
/// at one port, with Hermod's http-01 responder - Hermod's dns-01 responder,
/// writing into the server's challtestsrv, the server, started by the test
/// with the options it needs, and the recording of every exchange.
/// </summary>
/// <remarks>
/// <para>
/// Everything that judges is not Hermod's: the server is somebody else's,
/// the recording is judged by RawACME (<see cref="WireForm"/>), a
/// certificate by .NET and openssl, against the root the server says it
/// issues by.
/// </para>
/// <para>
/// The servers run natively in Linux, and so must the test: under WSL's NAT
/// a server inside WSL does not reach the responders of a Windows process
/// through the Windows firewall (PLAN.md, "Learned in phase 0").
/// </para>
/// </remarks>
public abstract class ServerFixture
{

    #region Data

    /// <summary>A name of the bench: the server's challtestsrv answers it with the loopback.</summary>
    protected const String Name = "www.acme.test";

    private readonly List<IDisposable> clients = [];

    #endregion

    #region Properties

    /// <summary>The tools of WSL the fixture needs.</summary>
    protected abstract String[]           Tools       { get; }

    /// <summary>Where Hermod's responders listen: the loopback, where the server is on the host.</summary>
    protected virtual IPv4Address         ResponderAddress
        => IPv4Address.Localhost;

    /// <summary>The contacts of an account the bench opens.</summary>
    protected virtual String[]            Contacts
        => [ "admin@acme.test" ];

    /// <summary>The server of the test, once started.</summary>
    protected IACMEServerPeer             Server      { get; private set; } = null!;

    /// <summary>The client's web server on "port 80", at 127.0.0.1.</summary>
    protected HTTPServer                  Port80      { get; private set; } = null!;

    /// <summary>The same at ::1, where IPv6 is there.</summary>
    protected HTTPServer?                 Port80v6    { get; private set; }

    /// <summary>The port both listen at - the server's http-01 port.</summary>
    protected UInt16                      HTTP01Port  { get; private set; }

    /// <summary>Hermod's http-01 responder, at <see cref="Port80"/>.</summary>
    protected HTTP01ChallengeResponder    HTTP01      { get; private set; } = null!;

    /// <summary>Hermod's dns-01 responder, writing into the server's challtestsrv.</summary>
    protected DNS01ChallengeResponder     DNS01       { get; private set; } = null!;

    /// <summary>Both responders, http-01 first.</summary>
    protected IACMEChallengeResponder[]   Responders
        => [ HTTP01, DNS01 ];

    /// <summary>Every exchange of the test's clients with the server.</summary>
    protected RecordingHandler            Wire        { get; private set; } = null!;

    /// <summary>What a red test shows: the server, every exchange, the end of the server's log.</summary>
    protected String                      Evidence
        => $"{Server?.Name}\n{Wire?.Log}\n--- {Server?.Name} ---\n{Tail(Server?.Log ?? "", 40)}";

    #endregion


    #region Setup / Teardown

    [OneTimeSetUp]
    public void RequirePeers()
    {

        if (Wsl.UsesWslBridge)
            Assert.Ignore("The server runs inside WSL, Hermod's responders in this Windows process, and WSL does not reach them through the Windows firewall - " +
                          "run inside WSL: wsl sh build/test-in-wsl.sh --filter \"TestCategory=WSL\"");

        TestEnvironment.RequireWsl(Tools);

    }

    [SetUp]
    public void StartResponders()
    {

        Port80      = new HTTPServer(IPAddress: ResponderAddress,
                                     TCPPort:   IPPort.Zero,
                                     AutoStart: true);

        HTTP01Port  = Port80.TCPPort.ToUInt16();

        try
        {
            Port80v6 = !ResponderAddress.Equals(IPv4Address.Localhost) ? null : new HTTPServer(IPAddress: IPv6Address.Localhost,
                                      TCPPort:   IPPort.Parse(HTTP01Port),
                                      AutoStart: true);
        }
        catch (Exception)
        {
            // No ::1 here, or the port taken at it: the tests of IPv6 then say so.
            Port80v6 = null;
        }

        HTTP01      = new HTTP01ChallengeResponder();
        HTTP01.RegisterAt(Port80);

        if (Port80v6 is not null)
            HTTP01.RegisterAt(Port80v6);

        DNS01       = new DNS01ChallengeResponder(
                          Publish:   (name, value, ct) => Server.DNS.SetTXTAsync(name, value, ct),
                          Withdraw:  (name, value, ct) => Server.DNS.ClearTXTAsync(name, ct)
                      );

    }

    [TearDown]
    public async Task StopBench()
    {

        if (TestContext.CurrentContext.Result.Outcome.Status != NUnit.Framework.Interfaces.TestStatus.Passed && Server is not null)
            TestContext.Out.WriteLine(Evidence);

        foreach (var client in clients)
            client.Dispose();

        clients.Clear();

        Server?.Dispose();
        Wire?.Dispose();

        await Port80.DisposeAsync();

        if (Port80v6 is not null)
            await Port80v6.DisposeAsync();

        // NUnit keeps the fixture for the next test: nothing of this one there.
        Server   = null!;
        Wire     = null!;
        Port80v6 = null;

    }

    /// <summary>
    /// The server of the test - started by the test, validating http-01 at
    /// <see cref="HTTP01Port"/>; stopped after it.
    /// </summary>
    protected T Use<T>(T Server) where T : IACMEServerPeer
    {
        this.Server = Server;
        this.Wire   = new RecordingHandler(Server.TrustedRootFile);
        return Server;
    }

    #endregion


    #region Clients

    /// <summary>
    /// A client of the server, with a new account key unless one is given,
    /// every exchange recorded.
    /// </summary>
    protected ACMEClient NewClient(ACMEAccountKey? Key = null)
    {

        var client = new ACMEClient(Server.DirectoryURL,
                                    Key ?? ACMEAccountKey.Generate(),
                                    HTTPHandler:   Wire,
                                    PollInterval:  TimeSpan.FromMilliseconds(250),
                                    PollTimeout:   TimeSpan.FromSeconds(60));

        clients.Add(client);

        return client;

    }

    /// <summary>
    /// A client with an account: opened with a contact, the terms agreed.
    /// </summary>
    protected async Task<ACMEClient> ClientWithAccountAsync(ACMEAccountKey? Key = null)
    {
        var client = NewClient(Key);
        await client.CreateAccountAsync(Contacts, TermsOfServiceAgreed: true);
        return client;
    }

    /// <summary>
    /// A certificate for the names - <see cref="Name"/> by default - by both
    /// responders.
    /// </summary>
    protected Task<ACMECertificate> ObtainAsync(ACMEClient       Client,
                                                params String[]  Names)

        => Client.ObtainCertificateAsync(Names.Length > 0 ? Names : [ Name ], Responders);

    #endregion


    #region AssertIssuedAsync(...)

    /// <summary>
    /// What Hermod was issued, judged: the leaf is for exactly the names, of
    /// the key asked for, for serverAuth, with the key identifier of its
    /// issuer; openssl verifies the chain as Hermod keeps it - its fullchain -
    /// to the root the server issues by, or the one given.
    /// </summary>
    protected async Task<X509Certificate2> AssertIssuedAsync(ACMECertificate      Certificate,
                                                             IEnumerable<String>  Names,
                                                             String               KeyAlgorithm  = "EC",
                                                             Int32                KeySize       = 256,
                                                             String?              RootPEM       = null)
    {

        var chain = new X509Certificate2Collection();
        chain.ImportFromPem(Certificate.FullChainPem);

        Assert.That(chain, Is.Not.Empty, $"no certificate in Hermod's fullchain: {Evidence}");

        var leaf      = chain[0];
        var expected  = Names.Select(Normalized).ToHashSet();
        var san       = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        var names     = (san?.EnumerateDnsNames().Select(name => name.ToLowerInvariant()) ?? []).
                            Concat(san?.EnumerateIPAddresses().Select(address => address.ToString()) ?? []).
                            ToHashSet();

        using var ec  = leaf.GetECDsaPublicKey();
        using var rsa = ec is null ? leaf.GetRSAPublicKey() : null;

        var root      = RootPEM ?? await Server.IssuingRootPEMAsync();
        var verified  = OpenSSL.Verify(root, Certificate.FullChainPem);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(names,                                                          Is.EquivalentTo(expected),           $"the names of the certificate: {Evidence}");
            Assert.That(ec is not null ? "EC" : rsa is not null ? "RSA" : "?",           Is.EqualTo(KeyAlgorithm),             "the kind of key");
            Assert.That(ec?.KeySize ?? rsa?.KeySize,                                    Is.EqualTo(KeySize),                  "the size of the key");
            Assert.That(leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().SelectMany(eku => eku.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>()).Select(oid => oid.Value),
                                                                                        Does.Contain("1.3.6.1.5.5.7.3.1"),    "serverAuth");
            Assert.That(leaf.Extensions.OfType<X509AuthorityKeyIdentifierExtension>(),  Is.Not.Empty,                         "the key identifier of the issuer");
            Assert.That(Certificate.Certificate.RawData,                                Is.EqualTo(leaf.RawData),             "Hermod's certificate is the leaf of its fullchain");
            Assert.That(verified.StdOut,                                                Does.Contain("leaf.pem: OK"),         $"{OpenSSL.Version} verifies Hermod's fullchain to {Server.Name}'s root: {verified}");
        }

        return leaf;

    }

    /// <summary>
    /// Every exchange of the test as RFC 8555 has it, by RawACME.
    /// </summary>
    protected void AssertWire()
    {
        var wrong = WireForm.Judge(Wire.Exchanges);
        Assert.That(wrong, Is.Empty, $"what Hermod sent {Server.Name}:\n{String.Join("\n", wrong)}\n{Evidence}");
    }

    /// <summary>A name in lower case, an address in its form of RFC 5952.</summary>
    protected static String Normalized(String Name)
        => IPAddress.TryParse(Name, out var address) ? address.ToString() : Name.ToLowerInvariant();

    /// <summary>The last lines of a text.</summary>
    protected static String Tail(String Text, Int32 Lines)
        => String.Join("\n", Text.Split('\n').TakeLast(Lines));

    #endregion

}
