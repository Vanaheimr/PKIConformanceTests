using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Security.Cryptography.X509Certificates;

using PKIConformance.Core.Servers;

namespace PKIConformance.Core.Peers;

/// <summary>
/// A build of Pebble: Debian's, or upstream's at its pin, beside it.
/// </summary>
/// <param name="Name">"Pebble 2.6.0+ds1-1+b7 (Debian)", "Pebble 2.10.3".</param>
/// <param name="Version">Its version.</param>
/// <param name="Binary">pebble.</param>
/// <param name="ChallTestSrvBinary">Its pebble-challtestsrv.</param>
/// <param name="HasProfiles">Whether it knows certificate profiles (draft-ietf-acme-profiles): 2.7.0 and later.</param>
public sealed record PebbleBuild(String   Name,
                                 String   Version,
                                 String   Binary,
                                 String   ChallTestSrvBinary,
                                 Boolean  HasProfiles)
{

    /// <summary>Debian 13's Pebble, 2.6.0: ARI of draft 03, no profiles.</summary>
    public static PebbleBuild Debian
        => debian.Value;

    private static readonly Lazy<PebbleBuild> debian = new (() => {
        var version = Wsl.Run("dpkg-query -W -f='${Version}' pebble", TimeSpan.FromSeconds(15)).StdOut.Trim();
        return new PebbleBuild($"Pebble {version} (Debian)", version, "/usr/bin/pebble", "/usr/bin/pebble-challtestsrv", HasProfiles: false);
    });

    /// <summary>Upstream's Pebble at its pin (build/peers/pins.env).</summary>
    public static PebbleBuild Upstream
    {
        get
        {
            var version = Pins.Get("PEBBLE_VERSION");
            return new PebbleBuild($"Pebble {version}", version, $"{Pins.Lib}/pebble-{version}/pebble", $"{Pins.Lib}/pebble-{version}/pebble-challtestsrv", HasProfiles: true);
        }
    }

    /// <inheritdoc/>
    public override String ToString()
        => Name;

}


/// <summary>
/// How a Pebble is started: its knobs of deliberate variation, the
/// environment variables of its README, and its configuration.
/// </summary>
public sealed record PebbleOptions
{

    /// <summary>The share of good nonces refused as badNonce, in percent (PEBBLE_WFE_NONCEREJECT) - none by default here, 5 by Pebble's.</summary>
    public Int32                                 NonceReject     { get; init; }

    /// <summary>The intermediates between leaf and root (PEBBLE_CHAIN_LENGTH): 1 and more.</summary>
    public Int32                                 ChainLength     { get; init; } = 1;

    /// <summary>The roots beside the default one, each with a chain of its own (PEBBLE_ALTERNATE_ROOTS).</summary>
    public Int32                                 AlternateRoots  { get; init; }

    /// <summary>The share of valid authorizations reused, in percent (PEBBLE_AUTHZREUSE) - Pebble's own by default.</summary>
    public Int32?                                AuthzReuse      { get; init; }

    /// <summary>The MAC keys of external accounts, base64url, by key identifier; where given, an account needs one.</summary>
    public IReadOnlyDictionary<String, String>?  EABKeys         { get; init; }

    /// <summary>The Retry-After of an authorization not done yet, in seconds.</summary>
    public Int32                                 RetryAfterAuthz { get; init; } = 1;

    /// <summary>The Retry-After of an order not done yet, in seconds.</summary>
    public Int32                                 RetryAfterOrder { get; init; } = 1;

    /// <summary>Pebble's -strict: the changes "known to break client compatibility" on.</summary>
    public Boolean                               Strict          { get; init; } = true;

}


/// <summary>
/// Pebble - Let's Encrypt's ACME server for testing clients - started for a
/// test of Hermod's client: on ports of its own of 127.0.0.1, its TLS by a
/// certificate of the bench, resolving and reading dns-01 through a
/// challtestsrv of its own, and validating http-01 at the port of Hermod's
/// responder.
/// </summary>
/// <remarks>
/// <i>"Pebble is a small RFC 8555 ACME test server not suited for a
/// production certificate authority"</i> - it exists to catch what clients
/// assume, and varies on purpose what a client must not depend on: nonces
/// refused, chains of other lengths, alternate roots, authorizations reused.
/// Its roots are made anew at every start; its management API hands them out.
/// </remarks>
public sealed class Pebble : Peer, IACMEServerPeer
{

    #region Data

    private readonly Process     process;
    private readonly HttpClient  management;

    #endregion

    #region Properties

    /// <summary>The build.</summary>
    public PebbleBuild    Build            { get; }

    /// <summary>How it was started.</summary>
    public PebbleOptions  Options          { get; }

    /// <summary>The port it validates http-01 at.</summary>
    public UInt16         HTTP01Port       { get; }

    /// <summary>The port of its ACME API, at 127.0.0.1.</summary>
    public UInt16         Port             { get; }

    /// <summary>The port of its management API, at 127.0.0.1.</summary>
    public UInt16         ManagementPort   { get; }

    /// <summary>Its TLS, made by the bench.</summary>
    public BenchTLS       TLS              { get; }

    /// <summary>Its challtestsrv.</summary>
    public ChallTestSrv   DNS              { get; }

    IChallengeDNS IACMEServerPeer.DNS
        => DNS;

    /// <inheritdoc/>
    public String         Name
        => Build.Name;

    /// <inheritdoc/>
    public Uri            DirectoryURL
        => new ($"https://127.0.0.1:{Port}/dir");

    /// <inheritdoc/>
    public String         TrustedRootFile
        => TLS.RootFile;

    /// <inheritdoc/>
    public String         Log
        => Read("pebble.log") ?? "";

    #endregion

    #region Constructor(s)

    private Pebble(PebbleBuild    Build,
                   PebbleOptions  Options,
                   UInt16         HTTP01Port,
                   UInt16         Port,
                   UInt16         ManagementPort,
                   ChallTestSrv   DNS)

        : base("pebble", Path.GetTempFileName())

    {

        this.Build           = Build;
        this.Options         = Options;
        this.HTTP01Port      = HTTP01Port;
        this.Port            = Port;
        this.ManagementPort  = ManagementPort;
        this.DNS             = DNS;
        this.TLS             = BenchTLS.Create(Directory, [ "127.0.0.1", "::1", "localhost" ]);

        management           = new HttpClient(RecordingHandler.TrustingHandler(TLS.RootFile)) {
                                   BaseAddress = new Uri($"https://127.0.0.1:{ManagementPort}/"),
                                   Timeout     = TimeSpan.FromSeconds(10)
                               };

        var pebble           = new JsonObject {
                                   ["listenAddress"]                   = $"127.0.0.1:{Port}",
                                   ["managementListenAddress"]         = $"127.0.0.1:{ManagementPort}",
                                   ["certificate"]                     = Wsl.ToWslPath(TLS.FullChainFile),
                                   ["privateKey"]                      = Wsl.ToWslPath(TLS.PrivateKeyFile),
                                   ["httpPort"]                        = HTTP01Port,
                                   ["tlsPort"]                         = ChallTestSrv.FreeTcpPort(),
                                   ["ocspResponderURL"]                = "",
                                   ["externalAccountBindingRequired"]  = Options.EABKeys is not null,
                                   ["domainBlocklist"]                 = new JsonArray("blocked-domain.example"),
                                   ["retryAfter"]                      = new JsonObject {
                                                                             ["authz"] = Options.RetryAfterAuthz,
                                                                             ["order"] = Options.RetryAfterOrder
                                                                         }
                               };

        if (Options.EABKeys is not null)
            pebble["externalAccountMACKeys"] = new JsonObject(Options.EABKeys.Select(key => KeyValuePair.Create(key.Key, (JsonNode?) JsonValue.Create(key.Value))));

        // Profiles came with 2.7.0 and replaced the one validity period of the configuration.
        if (Build.HasProfiles)
            pebble["profiles"] = new JsonObject {
                                     ["default"]     = new JsonObject { ["description"] = "The profile you know and love",                           ["validityPeriod"] = 7776000 },
                                     ["shortlived"]  = new JsonObject { ["description"] = "A short-lived cert profile, without actual enforcement",  ["validityPeriod"] = 518400 }
                                 };
        else
            pebble["certificateValidityPeriod"] = 7776000;

        Write("pebble-config.json", new JsonObject { ["pebble"] = pebble }.ToJsonString(new () { WriteIndented = true }));

        var environment = new List<String> {
                              "PEBBLE_VA_NOSLEEP=1",
                              $"PEBBLE_WFE_NONCEREJECT={Options.NonceReject}",
                              $"PEBBLE_CHAIN_LENGTH={Options.ChainLength}",
                              $"PEBBLE_ALTERNATE_ROOTS={Options.AlternateRoots}"
                          };

        if (Options.AuthzReuse is Int32 reuse)
            environment.Add($"PEBBLE_AUTHZREUSE={reuse}");

        process = Wsl.StartDetached($"cd {Quote(WslDirectory)} && exec env {String.Join(' ', environment)} {Quote(Build.Binary)} " +
                                    $"-config {Quote(WslPathOf("pebble-config.json"))} -dnsserver {DNS.DNSAddress} -strict={(Options.Strict ? "true" : "false")} " +
                                    $"> {Quote(WslPathOf("pebble.log"))} 2>&1",
                                    asRoot: false);

    }

    /// <summary>
    /// A Pebble of the build, started with the options, validating http-01
    /// at the given port - with a challtestsrv of its own.
    /// </summary>
    public static Pebble Start(PebbleBuild     Build,
                               UInt16          HTTP01Port,
                               PebbleOptions?  Options = null)
    {

        for (var attempt = 0; attempt < 5; attempt++)
        {

            var dns      = ChallTestSrv.Start(Build.ChallTestSrvBinary);
            var pebble   = new Pebble(Build, Options ?? new PebbleOptions(), HTTP01Port, ChallTestSrv.FreeTcpPort(), ChallTestSrv.FreeTcpPort(), dns);
            var deadline = DateTime.UtcNow.AddSeconds(20);

            while (DateTime.UtcNow < deadline && !pebble.process.HasExited)
            {

                if (pebble.Log.Contains("Listening on", StringComparison.Ordinal) &&
                    ChallTestSrv.Answers(pebble.Port) &&
                    ChallTestSrv.Answers(pebble.ManagementPort))
                    return pebble;

                Thread.Sleep(50);

            }

            var log = pebble.Log;
            pebble.Dispose();

            if (attempt == 4)
                throw new InvalidOperationException($"{Build} did not come up: {log}");

        }

        throw new InvalidOperationException($"{Build} did not come up.");

    }

    #endregion


    #region Management API

    /// <summary>A root of what it issues, in PEM: 0 is the one of the default chain.</summary>
    public Task<String> RootPEMAsync(Int32 Index = 0, CancellationToken CancellationToken = default)
        => management.GetStringAsync($"roots/{Index}", CancellationToken);

    /// <inheritdoc/>
    public Task<String> IssuingRootPEMAsync(CancellationToken CancellationToken = default)
        => RootPEMAsync(0, CancellationToken);

    /// <summary>An intermediate of a root, in PEM: the one below root 0 by default.</summary>
    public Task<String> IntermediatePEMAsync(Int32 Index = 0, CancellationToken CancellationToken = default)
        => management.GetStringAsync($"intermediates/{Index}", CancellationToken);

    /// <summary>
    /// What Pebble keeps of an issued certificate: "Status" ("Valid",
    /// "Revoked"), "Reason", "RevokedAt" - or null, where it knows none of
    /// that serial number.
    /// </summary>
    public async Task<JsonObject?> CertificateStatusAsync(X509Certificate2   Certificate,
                                                          CancellationToken  CancellationToken = default)
    {

        // Pebble's "%x" of the serial: lower case, no leading zeros.
        var serial   = Certificate.SerialNumber.TrimStart('0').ToLowerInvariant();
        var response = await management.GetAsync($"cert-status-by-serial/{serial}", CancellationToken);

        return response.IsSuccessStatusCode
                   ? JsonNode.Parse(await response.Content.ReadAsStringAsync(CancellationToken)) as JsonObject
                   : null;

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
        DNS.Dispose();

        base.Dispose();

    }

    #endregion

}
