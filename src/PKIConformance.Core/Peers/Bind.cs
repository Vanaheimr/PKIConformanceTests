using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace PKIConformance.Core.Peers;

/// <summary>
/// BIND 9 as the authoritative name server of the zone "acme.test": a named
/// of its own per use, on a port of its own of 127.0.0.1, that takes dynamic
/// updates (RFC 2136) signed with a TSIG key (RFC 8945) - so that each ACME
/// client's own DNS plugin writes its dns-01 records (certbot-dns-rfc2136,
/// lego's rfc2136 provider, acme.sh's dns_nsupdate), and the server under
/// test reads them through its DNSClient pointed here.
/// </summary>
/// <remarks>
/// Every update named takes is written into its log - the evidence of what a
/// client wrote, whatever the server under test then made of it.
/// </remarks>
public sealed class Bind : Peer
{

    #region Data

    /// <summary>The zone.</summary>
    public const String Zone     = "acme.test";

    /// <summary>The name of the TSIG key.</summary>
    public const String KeyName  = "pkiconformance";

    private readonly Process named;

    #endregion

    #region Properties

    /// <summary>What <c>named -v</c> says.</summary>
    public static String Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => Wsl.Run("named -v", TimeSpan.FromSeconds(15)).StdOut.Trim());

    /// <summary>The port named listens on, at 127.0.0.1.</summary>
    public UInt16  Port          { get; }

    /// <summary>The secret of the TSIG key, base64, HMAC-SHA256.</summary>
    public String  KeySecret     { get; }

    /// <summary>The TSIG key as nsupdate and acme.sh read it from a file, as the peer sees it.</summary>
    public String  KeyFile       { get; }

    #endregion

    #region Constructor(s)

    private Bind(UInt16 Port)
        : base("bind", Path.GetTempFileName())
    {

        this.Port      = Port;
        this.KeySecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        var key        = $"key \"{KeyName}\" {{ algorithm hmac-sha256; secret \"{KeySecret}\"; }};\n";
        this.KeyFile   = Write("tsig.key", key);

        Write($"{Zone}.zone", $"""
                               $TTL 60
                               @   IN SOA ns.{Zone}. hostmaster.{Zone}. 1 60 60 3600 60
                               @   IN NS  ns.{Zone}.
                               ns  IN A   127.0.0.1
                               """ + "\n");

        Write("named.conf", $$"""
                              options {
                                  directory "{{WslDirectory}}";
                                  pid-file "{{WslPathOf("named.pid")}}";
                                  listen-on port {{Port}} { 127.0.0.1; };
                                  listen-on-v6 { none; };
                                  recursion no;
                                  dnssec-validation no;
                                  allow-transfer { none; };
                                  notify no;
                              };
                              {{key}}
                              zone "{{Zone}}" {
                                  type primary;
                                  file "{{WslPathOf($"{Zone}.zone")}}";
                                  journal "{{WslPathOf($"{Zone}.jnl")}}";
                                  allow-update { key "{{KeyName}}"; };
                              };
                              logging {
                                  channel log { file "{{WslPathOf("named.log")}}"; print-time yes; severity info; };
                                  category default { log; };
                                  category update  { log; };
                              };
                              """);

        // -f, not -g: -g sends every log to stderr and ignores the logging of the configuration.
        named = Wsl.StartDetached($"exec named -f -c {Quote(WslPathOf("named.conf"))} 2>&1", asRoot: false);

    }

    /// <summary>
    /// A named on a free port, answering - or null, with why not.
    /// </summary>
    public static Bind Start()
    {

        for (var attempt = 0; attempt < 5; attempt++)
        {

            var bind     = new Bind(FreeUdpPort());
            var deadline = DateTime.UtcNow.AddSeconds(20);

            while (DateTime.UtcNow < deadline)
            {

                if (bind.named.HasExited)
                    break;

                if (Wsl.Run($"dig +short +time=1 +tries=1 -p {bind.Port} @127.0.0.1 {Zone} SOA", TimeSpan.FromSeconds(5)).StdOut.Contains("hostmaster", StringComparison.Ordinal))
                    return bind;

                Thread.Sleep(100);

            }

            var log = bind.Log;
            bind.Dispose();

            if (attempt == 4)
                throw new InvalidOperationException($"named did not come up: {log}");

        }

        throw new InvalidOperationException("named did not come up.");

    }

    private static UInt16 FreeUdpPort()
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return (UInt16) ((IPEndPoint) socket.Client.LocalEndPoint!).Port;
    }

    #endregion


    #region Log / Updates

    /// <summary>What named wrote into its log.</summary>
    public String Log
        => Read("named.log") ?? "";

    /// <summary>
    /// The lines of the log of updates that added a TXT record - "adding an RR
    /// at '_acme-challenge.www.acme.test' TXT ...".
    /// </summary>
    public IReadOnlyList<String> AddedTXT
        => [ .. Log.Split('\n').Where(line => line.Contains("adding an RR at", StringComparison.Ordinal) && line.Contains(" TXT", StringComparison.Ordinal)) ];

    #endregion

    #region NewDNSClient()

    /// <summary>
    /// A DNSClient of Hermod that asks this named - for the server under test.
    /// </summary>
    public DNSClient NewDNSClient()

        => new (IPv4Address.Localhost,
                IPPort.Parse(Port),
                QueryTimeout:   TimeSpan.FromSeconds(3),
                UseQueryCache:  false);

    #endregion

    #region Dispose()

    /// <inheritdoc/>
    public override void Dispose()
    {

        try
        {
            if (!named.HasExited)
                named.Kill(entireProcessTree: true);
            named.WaitForExit(5000);
        }
        catch (InvalidOperationException) { }

        named.Dispose();

        base.Dispose();

    }

    #endregion

}
