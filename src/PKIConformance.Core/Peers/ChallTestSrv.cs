using System.Diagnostics;
using System.Net.Http.Json;
using System.Net.Sockets;

namespace PKIConformance.Core.Peers;

/// <summary>
/// pebble-challtestsrv as the name server of an ACME server of the world -
/// Pebble's, step-ca's - on ports of its own of 127.0.0.1: every A query
/// answered with the loopback, no AAAA, and the TXT records of dns-01 set
/// and cleared through its management API, by the delegates of Hermod's
/// DNS01ChallengeResponder.
/// </summary>
/// <remarks>
/// Its other servers - http-01, https-01, tls-alpn-01, DoH - are switched
/// off: the answers of http-01 are Hermod's responder's to give.
/// </remarks>
public sealed class ChallTestSrv : Peer, IChallengeDNS
{

    #region Data

    private readonly Process     process;
    private readonly HttpClient  management = new () { Timeout = TimeSpan.FromSeconds(10) };

    #endregion

    #region Properties

    /// <summary>The binary.</summary>
    public String   Binary          { get; }

    /// <summary>The port of its name server, UDP and TCP, at 127.0.0.1.</summary>
    public UInt16   DNSPort         { get; }

    /// <summary>The port of its management API, at 127.0.0.1.</summary>
    public UInt16   ManagementPort  { get; }

    /// <summary>Its name server, as a server under test is pointed at it: "127.0.0.1:port".</summary>
    public String   DNSAddress
        => $"127.0.0.1:{DNSPort}";

    /// <summary>What it wrote: every record it added and removed.</summary>
    public String   Log
        => Read("challtestsrv.log") ?? "";

    #endregion

    #region Constructor(s)

    private ChallTestSrv(String  Binary,
                         UInt16  DNSPort,
                         UInt16  ManagementPort,
                         String  DefaultIPv4)

        : base("challtestsrv", Path.GetTempFileName())

    {

        this.Binary          = Binary;
        this.DNSPort         = DNSPort;
        this.ManagementPort  = ManagementPort;

        management.BaseAddress = new Uri($"http://127.0.0.1:{ManagementPort}/");

        process = Wsl.StartDetached($"exec {Quote(Binary)} {DNSFlag(Binary)} 127.0.0.1:{DNSPort} -management 127.0.0.1:{ManagementPort} " +
                                    $"-defaultIPv4 {DefaultIPv4} -defaultIPv6 '' -http01 '' -https01 '' -tlsalpn01 '' -doh '' " +
                                    $"> {Quote(WslPathOf("challtestsrv.log"))} 2>&1",
                                    asRoot: false);

    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<String, String> dnsFlags = new ();

    /// <summary>
    /// The flag of its name server: "-dns01" up to Pebble 2.6, "-dnsserver"
    /// since.
    /// </summary>
    private static String DNSFlag(String Binary)

        => dnsFlags.GetOrAdd(Binary, binary => Wsl.Run($"{Quote(binary)} -h 2>&1", TimeSpan.FromSeconds(15)).StdOut.Contains("-dnsserver", StringComparison.Ordinal)
                                                   ? "-dnsserver"
                                                   : "-dns01");

    /// <summary>
    /// A challtestsrv on free ports, answering every A query with the given
    /// address - the loopback by default.
    /// </summary>
    public static ChallTestSrv Start(String  Binary       = "pebble-challtestsrv",
                                     String  DefaultIPv4  = "127.0.0.1")
    {

        for (var attempt = 0; attempt < 5; attempt++)
        {

            var server   = new ChallTestSrv(Binary, FreeUdpAndTcpPort(), FreeTcpPort(), DefaultIPv4);
            var deadline = DateTime.UtcNow.AddSeconds(15);

            while (DateTime.UtcNow < deadline && !server.process.HasExited)
            {

                if (server.Log.Contains("Starting management server", StringComparison.Ordinal) && Answers(server.ManagementPort))
                    return server;

                Thread.Sleep(50);

            }

            var log = server.Log;
            server.Dispose();

            if (attempt == 4)
                throw new InvalidOperationException($"pebble-challtestsrv did not come up: {log}");

        }

        throw new InvalidOperationException("pebble-challtestsrv did not come up.");

    }

    #endregion


    #region Records

    /// <summary>
    /// Add a TXT record - a value beside the ones the name has already.
    /// </summary>
    public async Task SetTXTAsync(String             Name,
                                  String             Value,
                                  CancellationToken  CancellationToken = default)

        => (await management.PostAsJsonAsync("set-txt", new { host = FQDN(Name), value = Value }, CancellationToken)).EnsureSuccessStatusCode();

    /// <summary>
    /// Take every TXT record of the name away.
    /// </summary>
    public async Task ClearTXTAsync(String             Name,
                                    CancellationToken  CancellationToken = default)

        => (await management.PostAsJsonAsync("clear-txt", new { host = FQDN(Name) }, CancellationToken)).EnsureSuccessStatusCode();

    /// <summary>
    /// What its name server answers for a name and type now, as dig sees it.
    /// </summary>
    public String[] Query(String Name, String Type)

        => Wsl.Run($"dig +short +time=1 +tries=1 -p {DNSPort} @127.0.0.1 {Quote(Name)} {Type}", TimeSpan.FromSeconds(10)).
               StdOut.
               Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static String FQDN(String Name)
        => Name.EndsWith('.') ? Name : $"{Name}.";

    #endregion


    #region Ports

    /// <summary>A port free for UDP and for TCP at once, at 127.0.0.1.</summary>
    public static UInt16 FreeUdpAndTcpPort()
    {

        for (var attempt = 0; ; attempt++)
        {

            using var udp  = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var       port = ((IPEndPoint) udp.Client.LocalEndPoint!).Port;

            try
            {
                var tcp = new TcpListener(IPAddress.Loopback, port);
                tcp.Start();
                tcp.Stop();
                return (UInt16) port;
            }
            catch (SocketException) when (attempt < 20)
            {
                // Taken for TCP: another one.
            }

        }

    }

    /// <summary>A TCP port free at every address.</summary>
    public static UInt16 FreeTcpPort()
    {
        var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        var port = (UInt16) ((IPEndPoint) listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    /// <summary>Whether something accepts a TCP connection at the port of 127.0.0.1.</summary>
    public static Boolean Answers(UInt16 Port)
    {
        try
        {
            using var client = new TcpClient();
            return client.ConnectAsync(IPAddress.Loopback, Port).Wait(TimeSpan.FromSeconds(1)) && client.Connected;
        }
        catch (Exception e) when (e is SocketException or AggregateException)
        {
            return false;
        }
    }

    #endregion


    #region Dispose()

    /// <inheritdoc/>
    public override void Dispose()
    {

        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
            process.WaitForExit(5000);
        }
        catch (InvalidOperationException) { }

        process.Dispose();
        management.Dispose();

        base.Dispose();

    }

    #endregion

}
