using System.Diagnostics;
using System.Text.Json.Nodes;

using PKIConformance.Core.Scripted;

namespace PKIConformance.Core.Peers;

/// <summary>
/// How a step-ca is started.
/// </summary>
public sealed record StepCAOptions
{

    /// <summary>The challenges its ACME provisioner offers.</summary>
    public IReadOnlyList<String>  Challenges   { get; init; } = [ "http-01", "dns-01" ];

    /// <summary>The lifetime of what it issues.</summary>
    public TimeSpan               Validity     { get; init; } = TimeSpan.FromHours(24);

}


/// <summary>
/// step-ca - Smallstep's certificate authority, an ACME server of a stack of
/// its own - started for a test of Hermod's client: on a port of its own of
/// 127.0.0.1, issuing by a root and an intermediate of the bench (made by
/// .NET alone), resolving and reading dns-01 through a challtestsrv of its
/// own, validating http-01 at the port of Hermod's responder.
/// </summary>
/// <remarks>
/// Its TLS is its own, issued by the bench's intermediate for 127.0.0.1:
/// the bench's root is trusted for both. <c>--insecure --acme-http-port</c>
/// moves http-01 off port 80, <c>--resolver</c> points it at challtestsrv;
/// its CRL is on, and made anew on every revocation.
/// </remarks>
public sealed class StepCA : Peer, IACMEServerPeer
{

    #region Data

    private readonly Process  process;
    private readonly BenchCA  ca;

    #endregion

    #region Properties

    /// <summary>What <c>step-ca version</c> says.</summary>
    public static String  Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => Wsl.Run("step-ca version", TimeSpan.FromSeconds(15)).StdOut.Split('\n')[0].Trim());

    /// <summary>How it was started.</summary>
    public StepCAOptions  Options          { get; }

    /// <summary>The port of its API, at 127.0.0.1.</summary>
    public UInt16         Port             { get; }

    /// <summary>The port it validates http-01 at.</summary>
    public UInt16         HTTP01Port       { get; }

    /// <summary>Its challtestsrv.</summary>
    public ChallTestSrv   DNS              { get; }

    IChallengeDNS IACMEServerPeer.DNS
        => DNS;

    /// <summary>The root of the bench it issues below, in PEM.</summary>
    public String         RootPEM          { get; }

    /// <summary>The intermediate of the bench it issues by, in PEM.</summary>
    public String         IntermediatePEM
        => ca.Issuing.ExportCertificatePem() + "\n";

    /// <inheritdoc/>
    public String         Name
        => Version.Replace("Smallstep CA/", "step-ca ").Split(' ', 3) is [ var name, var number, .. ] ? $"{name} {number}" : Version;

    /// <inheritdoc/>
    public Uri            DirectoryURL
        => new ($"https://127.0.0.1:{Port}/acme/acme/directory");

    /// <summary>Where its certificate revocation list is, DER.</summary>
    public Uri            CRLURL
        => new ($"https://127.0.0.1:{Port}/crl");

    /// <inheritdoc/>
    public String         TrustedRootFile  { get; }

    /// <inheritdoc/>
    public String         Log
        => Read("step-ca.log") ?? "";

    #endregion

    #region Constructor(s)

    private StepCA(StepCAOptions  Options,
                   UInt16         HTTP01Port,
                   UInt16         Port,
                   ChallTestSrv   DNS)

        : base("step-ca", Path.GetTempFileName())

    {

        this.Options     = Options;
        this.HTTP01Port  = HTTP01Port;
        this.Port        = Port;
        this.DNS         = DNS;

        ca               = BenchCA.Create(Intermediates: 1, Name: "PKIConformance step-ca Bench");
        RootPEM          = ca.Root.ExportCertificatePem() + "\n";

        Write("root.crt",          RootPEM);
        Write("intermediate.crt",  ca.Issuing.ExportCertificatePem() + "\n");
        Write("intermediate.key",  ca.IssuingKeyPem + "\n");

        TrustedRootFile  = PathOf("root.crt");

        var validity     = $"{(Int32) Options.Validity.TotalMinutes}m";

        var config       = new JsonObject {
                               ["root"]      = WslPathOf("root.crt"),
                               ["crt"]       = WslPathOf("intermediate.crt"),
                               ["key"]       = WslPathOf("intermediate.key"),
                               ["address"]   = $"127.0.0.1:{Port}",
                               ["dnsNames"]  = new JsonArray("127.0.0.1", "localhost"),
                               ["logger"]    = new JsonObject { ["format"] = "text" },
                               ["db"]        = new JsonObject { ["type"] = "bbolt", ["dataSource"] = WslPathOf("db.bolt") },
                               ["crl"]       = new JsonObject { ["enabled"] = true, ["generateOnRevoke"] = true, ["cacheDuration"] = "24h" },
                               ["authority"] = new JsonObject {
                                                   ["provisioners"] = new JsonArray(
                                                       new JsonObject {
                                                           ["type"]        = "ACME",
                                                           ["name"]        = "acme",
                                                           ["challenges"]  = new JsonArray([ .. Options.Challenges.Select(challenge => JsonValue.Create(challenge)) ]),
                                                           ["claims"]      = new JsonObject {
                                                                                 ["minTLSCertDuration"]      = "5m",
                                                                                 ["maxTLSCertDuration"]      = validity,
                                                                                 ["defaultTLSCertDuration"]  = validity
                                                                             }
                                                       })
                                               },
                               ["tls"]       = new JsonObject { ["minVersion"] = 1.2, ["maxVersion"] = 1.3 }
                           };

        Write("ca.json", config.ToJsonString(new () { WriteIndented = true }));

        process = Wsl.StartDetached($"cd {Quote(WslDirectory)} && exec env STEPPATH={Quote(WslDirectory)} step-ca --insecure --acme-http-port {HTTP01Port} " +
                                    $"--resolver {DNS.DNSAddress} {Quote(WslPathOf("ca.json"))} < /dev/null > {Quote(WslPathOf("step-ca.log"))} 2>&1",
                                    asRoot: false);

    }

    /// <summary>
    /// A step-ca started with the options, validating http-01 at the given
    /// port - with a challtestsrv of its own.
    /// </summary>
    public static StepCA Start(UInt16          HTTP01Port,
                               StepCAOptions?  Options = null)
    {

        for (var attempt = 0; attempt < 5; attempt++)
        {

            var dns      = ChallTestSrv.Start();
            var stepCA   = new StepCA(Options ?? new StepCAOptions(), HTTP01Port, ChallTestSrv.FreeTcpPort(), dns);
            var deadline = DateTime.UtcNow.AddSeconds(30);

            while (DateTime.UtcNow < deadline && !stepCA.process.HasExited)
            {

                if (stepCA.Log.Contains("Serving HTTPS on", StringComparison.Ordinal) && ChallTestSrv.Answers(stepCA.Port))
                    return stepCA;

                Thread.Sleep(50);

            }

            var log = stepCA.Log;
            stepCA.Dispose();

            if (attempt == 4)
                throw new InvalidOperationException($"step-ca did not come up: {log}");

        }

        throw new InvalidOperationException("step-ca did not come up.");

    }

    #endregion


    #region IssuingRootPEMAsync / CRLAsync

    /// <inheritdoc/>
    public Task<String> IssuingRootPEMAsync(CancellationToken CancellationToken = default)
        => Task.FromResult(RootPEM);

    /// <summary>Its certificate revocation list, DER.</summary>
    public async Task<Byte[]> CRLAsync(CancellationToken CancellationToken = default)
    {
        using var client = new HttpClient(RecordingHandler.TrustingHandler(TrustedRootFile)) { Timeout = TimeSpan.FromSeconds(10) };
        return await client.GetByteArrayAsync(CRLURL, CancellationToken);
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
        ca.Dispose();
        DNS.Dispose();

        base.Dispose();

    }

    #endregion

}
