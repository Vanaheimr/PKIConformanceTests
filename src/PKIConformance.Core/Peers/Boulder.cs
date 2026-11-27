using System.Net.Http.Json;

namespace PKIConformance.Core.Peers;

/// <summary>
/// Boulder - Let's Encrypt's own ACME server - as its Docker compose stack at
/// the pinned tag (build/peers/setup-wsl.sh --with-boulder), started once for
/// a fixture: the strongest evidence of what Let's Encrypt makes of Hermod.
/// </summary>
/// <remarks>
/// <para>
/// Boulder validates http-01 at port 80 of what a name resolves to, and that
/// cannot be moved (va.newDefaultPortConfig). The names resolve through the
/// challtestsrv inside its stack, every one of them, by its default, to the
/// address of a forwarder on its "public" network - a container of Boulder's
/// own tools image on port 80 - that hands every connection on to Hermod's
/// responder on the host, at the port of the test (<see cref="ForTest"/>).
/// dns-01 goes into the same challtestsrv, through its management API.
/// </para>
/// <para>
/// Its policy wants names of public suffixes and limits certificates by
/// registered domain: the names of a test are random ones below "le.wtf",
/// which its test configuration exempts. An address it validates only in the
/// "shortlived" profile, and only a public one: the forwarder's.
/// </para>
/// </remarks>
public sealed class Boulder : IDisposable
{

    #region Data

    /// <summary>The compose project of the suite's Boulder.</summary>
    public const String  Project      = "pkiconformance-boulder";

    /// <summary>The network of the forwarder: Boulder's "public" one, 64.112.117.0/25.</summary>
    public const String  PublicNet    = "64.112.117";

    /// <summary>The host's address on that network - where Hermod's responder is reached.</summary>
    public const String  HostIP       = "64.112.117.1";

    /// <summary>The forwarder: port 80 to a host and port, connection by connection, both ways.</summary>
    private const String ForwarderCode = """
                                         import socket, sys, threading
                                         target = (sys.argv[1], int(sys.argv[2]))
                                         server = socket.socket()
                                         server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                         server.bind(("0.0.0.0", 80))
                                         server.listen(64)
                                         def pipe(source, sink):
                                             try:
                                                 while True:
                                                     data = source.recv(65536)
                                                     if not data:
                                                         break
                                                     sink.sendall(data)
                                             except OSError:
                                                 pass
                                             finally:
                                                 try:
                                                     sink.shutdown(socket.SHUT_WR)
                                                 except OSError:
                                                     pass
                                         print("forwarding port 80 to %s:%d" % target, flush=True)
                                         while True:
                                             client, _ = server.accept()
                                             try:
                                                 upstream = socket.create_connection(target, timeout=10)
                                                 upstream.settimeout(None)
                                             except OSError as e:
                                                 print("no connection to the target: %s" % e, flush=True)
                                                 client.close()
                                                 continue
                                             threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
                                             threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()
                                         """;

    /// <summary>Where Boulder's challtestsrv is, on its internal network.</summary>
    public const String  ChallSrvIP   = "10.77.77.77";

    #endregion

    #region Properties

    /// <summary>The checkout of Boulder at its pin.</summary>
    public static String  Checkout
        => $"{Pins.Lib}/boulder-{Pins.Get("BOULDER_VERSION")}";

    /// <summary>"Boulder v0.20261117.0".</summary>
    public static String  Name
        => $"Boulder {Pins.Get("BOULDER_VERSION")}";

    /// <summary>Whether its checkout is there.</summary>
    public static Boolean IsInstalled
        => Wsl.Run($"test -f {Peer.Quote($"{Checkout}/docker-compose.yml")}", TimeSpan.FromSeconds(15)).Success;

    /// <summary>
    /// The forwarder's address on Boulder's "public" network: what every name
    /// resolves to, and the address a test of an IP identifier asks for - one
    /// of its own for every start, as Boulder allows two certificates of the
    /// same identifiers in three hours.
    /// </summary>
    public String         ForwarderIP  { get; } = $"{PublicNet}.{System.Security.Cryptography.RandomNumberGenerator.GetInt32(10, 121)}";

    /// <summary>The URL of its directory: its WFE, published on the host.</summary>
    public Uri            DirectoryURL
        => new ("http://localhost:4001/directory");

    /// <summary>Its challtestsrv.</summary>
    public IChallengeDNS  DNS          { get; } = new BoulderDNS();

    /// <summary>The PEM file of its roots of the internal PKI: what the client trusts, where TLS is spoken at all.</summary>
    public String         TrustedRootFile
        => $"{Checkout}/test/certs/ipki/minica.pem";

    /// <summary>The last of what Boulder logged.</summary>
    public String         Log
        => Compose("logs --no-color --tail 60 boulder", TimeSpan.FromSeconds(30)).StdOut;

    #endregion

    #region Constructor(s)

    private Boulder() { }

    /// <summary>
    /// Boulder started - its certificates made first, where they are not -
    /// and answering at its directory; Boulder's challtestsrv resolving every
    /// name to the forwarder. A stack kept running (PKICONFORMANCE_KEEP_BOULDER)
    /// is taken as it is; anything else left of a run before - containers,
    /// and the volumes its MTC log refuses to start on ("tile exists") - is
    /// taken away first, and so is what a failed start leaves.
    /// </summary>
    public static Boulder Start(TimeSpan? Timeout = null)
    {

        var deadline = DateTime.UtcNow + (Timeout ?? TimeSpan.FromMinutes(20));
        var boulder  = new Boulder();

        if (!boulder.Answers)
        {

            Compose("down -v --timeout 20", TimeSpan.FromMinutes(5));

            try
            {

                if (!Wsl.Run($"test -d {Peer.Quote($"{Checkout}/test/certs/webpki")}", TimeSpan.FromSeconds(15)).Success)
                {
                    var setup = Compose("run --rm bsetup", TimeSpan.FromMinutes(15));
                    if (!setup.Success)
                        throw new InvalidOperationException($"Boulder's certificates were not made: {setup}");
                }

                // Vitess takes longer to become healthy the first time than compose waits
                // for it; the second "up" finds it so.
                var up = Compose("up -d boulder", TimeSpan.FromMinutes(10));

                for (var attempt = 0; !up.Success && attempt < 3 && DateTime.UtcNow < deadline; attempt++)
                {
                    Thread.Sleep(TimeSpan.FromSeconds(10));
                    up = Compose("up -d boulder", TimeSpan.FromMinutes(10));
                }

                if (!up.Success)
                    throw new InvalidOperationException($"Boulder's stack did not start: {up}");

                while (!boulder.Answers)
                {

                    if (DateTime.UtcNow > deadline || IsExited)
                        throw new InvalidOperationException($"Boulder did not answer at {boulder.DirectoryURL}: {boulder.Log}");

                    Thread.Sleep(TimeSpan.FromSeconds(3));

                }

            }
            catch
            {
                Compose("down -v --timeout 20", TimeSpan.FromMinutes(5));
                throw;
            }

        }

        var dns = Wsl.Run($"curl -fs -d '{{\"ip\":\"{boulder.ForwarderIP}\"}}' http://{ChallSrvIP}:8055/set-default-ipv4", TimeSpan.FromSeconds(15));

        if (!dns.Success)
            throw new InvalidOperationException($"Boulder's challtestsrv did not take the forwarder as its default: {dns}");

        return boulder;

    }

    /// <summary>Whether its WFE answers at the directory.</summary>
    private Boolean Answers
        => Wsl.Run($"curl -fs -o /dev/null {DirectoryURL}", TimeSpan.FromSeconds(15)).Success;

    /// <summary>Whether its main container has given up already - its start.py exits when a service of it does not come up.</summary>
    private static Boolean IsExited
        => Wsl.Run($"docker inspect -f '{{{{.State.Status}}}}' {Project}-boulder-1", TimeSpan.FromSeconds(15)).StdOut.Trim() == "exited";

    #endregion


    #region ForTest(HTTP01Port)

    /// <summary>
    /// Boulder as the server of one test: the forwarder of port 80 pointed at
    /// Hermod's responder on the host, at the given port - and taken away
    /// again with the test.
    /// </summary>
    public IACMEServerPeer ForTest(UInt16 HTTP01Port)
        => new Session(this, HTTP01Port);

    private sealed class Session : IACMEServerPeer
    {

        private readonly Boulder boulder;

        public Session(Boulder Boulder, UInt16 HTTP01Port)
        {

            boulder = Boulder;

            Docker($"rm -f {Project}-forwarder");

            // Boulder's tools have python3, and no socat.
            var script  = Path.Combine(Path.GetTempPath(), $"pkiconformance-forward-{Guid.NewGuid():N}.py");
            File.WriteAllText(script, ForwarderCode);

            var network = $"{Project}_publicnet";
            var image   = $"letsencrypt/boulder-tools:{Pins.Get("BOULDER_TOOLS_TAG")}";
            var started = Docker($"run -d --name {Project}-forwarder --network {network} --ip {boulder.ForwarderIP} " +
                                 $"-v {Peer.Quote(Wsl.ToWslPath(script))}:/forward.py:ro {image} python3 -u /forward.py {HostIP} {HTTP01Port}");

            if (!started.Success)
                throw new InvalidOperationException($"The forwarder of port 80 did not start: {started}");

        }

        public String        Name             => Boulder.Name;
        public Uri           DirectoryURL     => boulder.DirectoryURL;
        public String        TrustedRootFile  => boulder.TrustedRootFile;
        public IChallengeDNS DNS              => boulder.DNS;
        public String        Log              => boulder.Log;

        public Task<String> IssuingRootPEMAsync(CancellationToken CancellationToken = default)

            => Task.FromResult(Wsl.Run($"cat {Peer.Quote(Checkout)}/test/certs/webpki/root-*.cert.pem", TimeSpan.FromSeconds(15)).StdOut);

        public void Dispose()
            => Docker($"rm -f {Project}-forwarder");

    }

    #endregion


    #region Compose / Docker

    /// <summary>docker compose of the suite's project, with the tags of the pins.</summary>
    public static Wsl.Result Compose(String Arguments, TimeSpan Timeout)

        => Wsl.Run($"cd {Peer.Quote(Checkout)} && " +
                   $"BOULDER_TOOLS_TAG={Pins.Get("BOULDER_TOOLS_TAG")} " +
                   $"BOULDER_VTCOMBOSERVER_TAG={Pins.Get("BOULDER_VTCOMBOSERVER_TAG")} " +
                   $"BOULDER_SUNLIGHT_TAG={Pins.Get("BOULDER_SUNLIGHT_TAG")} " +
                   $"docker compose -p {Project} {Arguments} 2>&1",
                   Timeout);

    private static Wsl.Result Docker(String Arguments)
        => Wsl.Run($"docker {Arguments} 2>&1", TimeSpan.FromMinutes(2));

    #endregion


    #region Dispose()

    /// <summary>
    /// Stop the stack - unless PKICONFORMANCE_KEEP_BOULDER says to keep it
    /// running for the next run.
    /// </summary>
    public void Dispose()
    {

        Docker($"rm -f {Project}-forwarder");

        if (Environment.GetEnvironmentVariable("PKICONFORMANCE_KEEP_BOULDER") is not "1")
            Compose("down -v --timeout 20", TimeSpan.FromMinutes(5));

    }

    #endregion


    #region (class) BoulderDNS

    /// <summary>
    /// The challtestsrv inside Boulder's stack, by its management API on
    /// Boulder's internal network.
    /// </summary>
    private sealed class BoulderDNS : IChallengeDNS
    {

        private readonly HttpClient management = new () { BaseAddress = new Uri($"http://{ChallSrvIP}:8055/"), Timeout = TimeSpan.FromSeconds(10) };

        public async Task SetTXTAsync(String Name, String Value, CancellationToken CancellationToken = default)
            => (await management.PostAsJsonAsync("set-txt", new { host = FQDN(Name), value = Value }, CancellationToken)).EnsureSuccessStatusCode();

        public async Task ClearTXTAsync(String Name, CancellationToken CancellationToken = default)
            => (await management.PostAsJsonAsync("clear-txt", new { host = FQDN(Name) }, CancellationToken)).EnsureSuccessStatusCode();

        public String[] Query(String Name, String Type)

            => Wsl.Run($"dig +short +time=1 +tries=1 -p 8053 @{ChallSrvIP} {Peer.Quote(Name)} {Type}", TimeSpan.FromSeconds(10)).
                   StdOut.
                   Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        public String Log
            => "";

        private static String FQDN(String Name)
            => Name.EndsWith('.') ? Name : $"{Name}.";

    }

    #endregion

}
