using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// The bench of an interop test: the ACME server under test, started for each
/// test with the options it needs, reachable from the peers; the port its
/// http-01 asks at - a peer's own web server's, or the bench's web server of
/// a webroot; a BIND of the zone acme.test for dns-01; and the judge of what
/// a peer was issued.
/// </summary>
/// <remarks>
/// <para>
/// What a peer was issued is judged independently of the server's own view
/// (PLAN.md, section 4.5): its names by .NET, its chain by openssl to the
/// server's root, its key, serverAuth and the issuer's key identifier - and
/// then whether the server keeps it as issued to the account.
/// </para>
/// <para>
/// Two legs: the peers of Linux (<see cref="InteropFixture"/>), natively in
/// WSL by build/test-in-wsl.sh or on Debian in the nightly - a Windows test
/// process skips them, as WSL cannot reach it through the Windows firewall
/// (PLAN.md, "Learned in phase 0"); and the peers of Windows
/// (<see cref="WindowsInteropFixture"/>), natively on Windows, against the
/// server on the loopback, judged by the host's own openssl.
/// </para>
/// </remarks>
public abstract class PeerFixture(String ServerName)
{

    #region Properties

    /// <summary>Whether the peers are of WSL (or of Linux), rather than of Windows.</summary>
    protected abstract Boolean           InWsl        { get; }

    /// <summary>The tools of WSL the fixture needs - or, on the Windows leg, the files of its peers.</summary>
    protected abstract String[]          Tools        { get; }

    /// <summary>The client of the fixture and its version - its column of the interop matrix.</summary>
    protected abstract String            PeerName     { get; }

    /// <summary>The server under test of the test.</summary>
    protected IACMEServerUnderTest       Server       { get; private set; } = null!;

    /// <summary>The directory as the peers reach it.</summary>
    protected String                     DirectoryURL => InWsl ? Server.DirectoryURLFromWsl!.ToString() : Server.DirectoryURL.ToString();

    /// <summary>The port http-01 asks at.</summary>
    protected UInt16                     HTTP01Port   { get; private set; }

    /// <summary>The bench's web server of a webroot, where the test has one.</summary>
    protected ScriptedChallengeHost?     Webroot      { get; private set; }

    /// <summary>The webroot, as the peers see it: their answers go into its .well-known/acme-challenge/.</summary>
    protected String                     WebrootPath  { get; private set; } = "";

    /// <summary>Where the answers of http-01 go as files, as the peers see it - the WELLKNOWN of dehydrated, the CHALLENGE_PATH of uacme.</summary>
    protected String                     WellKnownPath => $"{WebrootPath}/.well-known/acme-challenge";

    /// <summary>The BIND of acme.test, where the test has one.</summary>
    protected Bind?                      DNS          { get; private set; }

    /// <summary>Things to throw away after the test.</summary>
    protected List<IDisposable>          Disposables  { get; } = [];

    #endregion


    #region Setup / Teardown

    [OneTimeSetUp]
    public void RequirePeers()
    {
        if (InWsl)
            TestEnvironment.RequireWsl(Tools);
        else
            TestEnvironment.RequireWindows(Tools);
    }

    /// <summary>The test's cell of the interop matrix, into its output (InteropCells).</summary>
    [SetUp]
    public void DeclareCell()
        => InteropMatrix.Declare(InteropCells.Clients, PeerName, ServerName == ServersUnderTest.PKI ? Revisions.PKI : ServerName);

    [TearDown]
    public async Task StopBench()
    {

        foreach (var disposable in Disposables)
            disposable.Dispose();

        Disposables.Clear();

        if (Server is not null)
            await Server.DisposeAsync();

        if (Webroot is not null)
            await Webroot.DisposeAsync();

        DNS?.Dispose();

        Server  = null!;
        Webroot = null;
        DNS     = null;

    }

    /// <summary>
    /// Start the server under test for the test: reachable from the peers,
    /// http-01 asking at a free port - of the bench's web server of a
    /// webroot, where one is asked for - and resolving through a BIND of
    /// its own, where asked for.
    /// </summary>
    protected async Task StartAsync(ACMEServerOptions?  Options  = null,
                                    Boolean             Webroot  = false,
                                    Boolean             DNS      = false)
    {

        if (Webroot)
        {
            var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-webroot-{Guid.NewGuid():N}"[..40])).FullName;
            var answers   = Directory.CreateDirectory(Path.Combine(directory, ".well-known", "acme-challenge")).FullName;
            this.Webroot  = ScriptedChallengeHost.Start();
            this.Webroot.ServeDirectory(answers);
            WebrootPath   = InWsl ? Wsl.ToWslPath(directory) : directory;
            HTTP01Port    = this.Webroot.Port;
        }
        else
            HTTP01Port    = FreeTcpPort();

        if (DNS)
            this.DNS = Bind.Start();

        Server = await ServersUnderTest.StartAsync(ServerName,
                                                   (Options ?? new ACMEServerOptions()) with {
                                                       ReachableFromWsl  = InWsl,
                                                       HTTP01Port        = HTTP01Port,
                                                       DNSClient         = this.DNS?.NewDNSClient() ?? Options?.DNSClient
                                                   });

        if (InWsl)
            TestEnvironment.RequireReachableFromWsl(Server.DirectoryURLFromWsl ?? throw new InvalidOperationException($"{Server.Name} is not reachable from WSL."),
                                                    Server.TLS.RootFile);

    }

    /// <summary>A peer of the test, thrown away after it.</summary>
    protected T Keep<T>(T Peer) where T : IDisposable
    {
        Disposables.Add(Peer);
        return Peer;
    }

    /// <summary>A TCP port free on every address, for a peer's own web server.</summary>
    protected static UInt16 FreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        var port = (UInt16) ((IPEndPoint) listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    #endregion


    #region AssertIssued(...)

    /// <summary>
    /// What a peer was issued, judged: the leaf of the chain is for exactly
    /// the names, of the key asked for, for serverAuth, with the key
    /// identifier of its issuer; openssl verifies the chain to the server's
    /// root; the server keeps it as issued to an account.
    /// </summary>
    /// <param name="ChainPEM">The leaf and its issuers as the peer keeps them (its fullchain).</param>
    /// <param name="Names">The DNS names and addresses it was asked for.</param>
    /// <param name="KeyAlgorithm">"EC" or "RSA".</param>
    /// <param name="KeySize">The size of the key in bits.</param>
    /// <param name="Evidence">What the peer said.</param>
    /// <returns>The leaf.</returns>
    protected X509Certificate2 AssertIssued(String?               ChainPEM,
                                            IEnumerable<String>   Names,
                                            String                KeyAlgorithm,
                                            Int32                 KeySize,
                                            Object                Evidence)
    {

        Assert.That(ChainPEM, Is.Not.Null.And.Not.Empty, $"no certificate was kept: {Evidence}");

        var chain = new X509Certificate2Collection();
        chain.ImportFromPem(ChainPEM!);

        Assert.That(chain, Is.Not.Empty, $"no certificate in what was kept: {Evidence}");

        var leaf     = chain[0];
        var expected = Names.Select(Normalized).ToHashSet();
        var san      = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        var names    = (san?.EnumerateDnsNames().Select(name => name.ToLowerInvariant()) ?? []).
                           Concat(san?.EnumerateIPAddresses().Select(address => address.ToString()) ?? []).
                           ToHashSet();

        using var ec   = leaf.GetECDsaPublicKey();
        using var rsa  = ec is null ? leaf.GetRSAPublicKey() : null;

        var verified   = InWsl ? OpenSSL.Verify(Server.IssuingRootPEM, ChainPEM!) : OpenSSL.VerifyNative(Server.IssuingRootPEM, ChainPEM!);
        var openssl    = InWsl ? OpenSSL.Version : OpenSSL.NativeVersion;

        using (Assert.EnterMultipleScope())
        {

            Assert.That(names,                                                         Is.EquivalentTo(expected),                       $"the names of the certificate: {Evidence}");
            Assert.That(ec is not null ? "EC" : rsa is not null ? "RSA" : "?",          Is.EqualTo(KeyAlgorithm),                         "the kind of key");
            Assert.That(ec?.KeySize ?? rsa?.KeySize,                                   Is.EqualTo(KeySize),                              "the size of the key");
            Assert.That(leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().SelectMany(eku => eku.EnhancedKeyUsages.Cast<Oid>()).Select(oid => oid.Value),
                                                                                       Does.Contain("1.3.6.1.5.5.7.3.1"),                "serverAuth");
            Assert.That(leaf.Extensions.OfType<X509AuthorityKeyIdentifierExtension>(), Is.Not.Empty,                                     "the key identifier of the issuer");
            Assert.That(verified.StdOut,                                               Does.Contain("leaf.pem: OK"),                     $"{openssl} verifies the chain to {Server.Name}'s root: {verified}");
            Assert.That(Server.Issued().Select(issued => Convert.ToHexString(issued.DER)), Does.Contain(Convert.ToHexString(leaf.RawData)), $"{Server.Name} keeps it as issued");

        }

        return leaf;

    }

    /// <summary>A name in lower case, an address in its form of RFC 5952.</summary>
    protected static String Normalized(String Name)
        => IPAddress.TryParse(Name, out var address) ? address.ToString() : Name.ToLowerInvariant();

    #endregion

    #region AssertRevoked(Leaf, Reason, Evidence)

    /// <summary>
    /// A certificate a peer revoked: the server holds it revoked, for the
    /// reason given, and its CRL - judged by openssl - lists it.
    /// </summary>
    protected void AssertRevoked(X509Certificate2  Leaf,
                                 String            ChainPEM,
                                 Int32?            Reason,
                                 Object            Evidence)
    {

        var issued  = Server.Issued().FirstOrDefault(candidate => candidate.DER.AsSpan().SequenceEqual(Leaf.RawData));
        var crl     = Server.CRL();
        var checked_ = crl is null ? null
                     : InWsl       ? OpenSSL.Verify      (Server.IssuingRootPEM, ChainPEM, crl)
                     :               OpenSSL.VerifyNative(Server.IssuingRootPEM, ChainPEM, crl);
        var openssl  = InWsl ? OpenSSL.Version : OpenSSL.NativeVersion;

        using (Assert.EnterMultipleScope())
        {
            Assert.That(issued?.Revoked,  Is.True,                                         $"{Server.Name} holds it revoked: {Evidence}");
            if (Reason is not null)
                Assert.That(issued?.Reason, Is.EqualTo(Reason),                            $"the reason: {Evidence}");
            Assert.That(crl,              Is.Not.Null,                                     $"{Server.Name} has a CRL");
            Assert.That(checked_?.StdOut, Does.Contain("certificate revoked"),            $"{openssl} finds it in the CRL: {checked_}");
        }

    }

    #endregion

    #region CSR(Peer, Names, KeyType)

    /// <summary>
    /// A key and a CSR for the names, made by openssl - a CSR of the client's
    /// own, as section 7.4 lets it bring one: its paths as the peer sees them.
    /// </summary>
    /// <param name="Peer">The peer whose directory they go into.</param>
    /// <param name="Names">DNS names and addresses, as subject alternative names; the first one as the common name too.</param>
    protected static (String CSR, String Key, String DER) CSR(Peer             Peer,
                                                              params String[]  Names)
    {

        var san    = String.Join(",", Names.Select(name => IPAddress.TryParse(name, out _) ? $"IP:{name}" : $"DNS:{name}"));
        var csr    = Peer.WslPathOf("own.csr");
        var key    = Peer.WslPathOf("own.key");
        var der    = Peer.WslPathOf("own.csr.der");

        var result = Wsl.Run($"openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout {PKIConformance.Core.Peers.Peer.Quote(key)} " +
                             $"-out {PKIConformance.Core.Peers.Peer.Quote(csr)} -subj '/CN={Names[0]}' -addext 'subjectAltName={san}' 2>&1 && " +
                             $"openssl req -in {PKIConformance.Core.Peers.Peer.Quote(csr)} -outform DER -out {PKIConformance.Core.Peers.Peer.Quote(der)} 2>&1",
                             TimeSpan.FromSeconds(30));

        Assert.That(result.Success, Is.True, $"openssl made no CSR: {result}");

        return (csr, key, der);

    }

    #endregion

    #region ExternalAccountAsync()

    /// <summary>
    /// A key of an external account binding, made as the server's operator
    /// makes one: its key identifier, and its MAC key in base64url.
    /// </summary>
    protected async Task<(String KeyId, String MAC)> ExternalAccountAsync()
    {
        var (keyId, mac) = await Server.NewExternalAccountKeyAsync();
        return (keyId, PKIConformance.Core.RawACME.RawBase64Url.Encode(mac));
    }

    #endregion

    #region Account(Contact)

    /// <summary>The account of the server with the contact, or null.</summary>
    protected ServerAccount? AccountOf(String Contact)
        => Server.Accounts().FirstOrDefault(account => account.Contacts.Contains($"mailto:{Contact}"));

    #endregion

    #region Refused(Result, Types)

    /// <summary>
    /// A peer that did not get what it asked for, and says why in the words
    /// of the server - one of the error types of RFC 8555, section 6.7.
    /// </summary>
    protected static void AssertRefused(Wsl.Result  Result,
                                        String      Log,
                                        params String[] Types)
    {
        var said = Result.StdOut + "\n" + Log;
        using (Assert.EnterMultipleScope())
        {
            Assert.That(Result.Success, Is.False, $"it was not refused: {Result}");
            Assert.That(Types.Any(type => said.Contains(type, StringComparison.OrdinalIgnoreCase)), Is.True,
                        $"it does not say {String.Join(" or ", Types)}: {said[..Math.Min(said.Length, 4000)]}");
        }
    }

    #endregion

}


/// <summary>
/// The bench of the peers of Linux - certbot, lego, acme.sh, dehydrated,
/// uacme, Python's acme - natively in WSL or on Debian.
/// </summary>
[Category(TestCategories.Wsl)]
public abstract class InteropFixture(String ServerName) : PeerFixture(ServerName)
{
    protected sealed override Boolean InWsl => true;
}


/// <summary>
/// The bench of the peers of Windows - Posh-ACME, win-acme - natively on
/// Windows, no WSL: the server on the loopback, its http-01 asking the
/// bench's web server of a webroot, what they were issued judged by the
/// host's own openssl. The names of the bench resolve on no Windows that
/// was left as it was, so its certificates are of addresses (RFC 8738).
/// </summary>
[Category(TestCategories.Windows)]
public abstract class WindowsInteropFixture(String ServerName) : PeerFixture(ServerName)
{
    protected sealed override Boolean InWsl => false;
}
