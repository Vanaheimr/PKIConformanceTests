using System.Reflection;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;

using cloud.charging.open.PKI.Issuance;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using PKINode      = cloud.charging.open.PKI.PKI;
using ACMESettings = cloud.charging.open.PKI.Enrollment.ACMESettings;

namespace PKIConformance.Core.Servers;

/// <summary>
/// The PKI's ACME server: a PKI started in this process, as PKITests starts
/// one - a root, a sub-CA below it that ACME signs with, and the ACME
/// settings of the test - over HTTPS with a certificate of the bench.
/// </summary>
/// <remarks>
/// The PKI is started with nothing of its own on disk but in a directory of
/// its own below the temporary directory, and with the time servers of a node
/// switched off: a test is not to wait for the network.
/// </remarks>
public sealed class PKIACMEServer : IACMEServerUnderTest
{

    #region Data

    /// <summary>
    /// No time servers: a node asks the legal ones by default.
    /// </summary>
    private const String NoTimeServers = """{ "nts": { "groups": { "legal": { "enabled": false } } } }""";

    private readonly String    directory;
    private readonly PKINode   pki;

    #endregion

    #region Properties

    /// <inheritdoc/>
    public String  Name                 { get; }

    /// <inheritdoc/>
    public Uri     DirectoryURL         { get; }

    /// <inheritdoc/>
    public Uri?    DirectoryURLFromWsl  { get; }

    /// <inheritdoc/>
    public BenchTLS TLS                 { get; }

    /// <inheritdoc/>
    public String  IssuingRootPEM       { get; }

    /// <summary>
    /// The PKI itself, for what a test arranges beyond ACME - never for what
    /// it judges.
    /// </summary>
    public PKINode PKI
        => pki;

    #endregion

    #region Constructor(s)

    private PKIACMEServer(String    Directory,
                          PKINode   PKI,
                          BenchTLS  TLS,
                          String    IssuingRootPEM,
                          String?   WslHost)
    {

        this.directory       = Directory;
        this.pki             = PKI;
        this.TLS             = TLS;
        this.IssuingRootPEM  = IssuingRootPEM;

        var port             = PKI.HTTPPort.ToUInt16();

        this.DirectoryURL    = new Uri($"https://127.0.0.1:{port}/acme/directory");
        this.Name            = $"PKI {CommitOf(typeof(PKINode).Assembly)}";

        if (WslHost is not null)
            this.DirectoryURLFromWsl = new Uri($"https://{WslHost}:{port}/acme/directory");

    }

    #endregion


    #region StartAsync(Options = null)

    /// <summary>
    /// Start a PKI whose ACME server signs as the options say.
    /// </summary>
    public static async Task<PKIACMEServer> StartAsync(ACMEServerOptions? Options = null)
    {

        Options ??= new ACMEServerOptions();

        var directory = Path.Combine(Path.GetTempPath(), "pkiconformance-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(directory);

        var configFile = Path.Combine(directory, WWCPConfigFile.DefaultFileName);
        File.WriteAllText(configFile, NoTimeServers);

        // Where a peer inside WSL reaches this process: the Windows host behind
        // WSL's NAT, or the one loopback natively. Named in the TLS certificate.
        var wslHost    = Options.ReachableFromWsl ? Wsl.WindowsHostAddress : null;
        var tls        = BenchTLS.Create(directory, [ "127.0.0.1", "::1", "localhost", .. wslHost is null ? Array.Empty<String>() : [ wslHost ] ]);

        var pki = await TestPorts.StartedOnFreshPorts(() => new PKINode(HTTPHostname:    Options.ReachableFromWsl ? IPv4Address.Any : IPv4Address.Localhost,
                                                                        HTTPPort:        TestPorts.Free(),
                                                                        AccountsPath:    Path.Combine(directory, "accounts"),
                                                                        ConfigFile:      new WWCPConfigFile(configFile),
                                                                        DNSClient:       Options.DNSClient,
                                                                        LogToConsole:    false,
                                                                        BridgeDebugLog:  false,
                                                                        Web:             new WebConfiguration(TLS: new WebTLSConfiguration(new WebCertificateSource(tls.FullChainFile, tls.PrivateKeyFile)))));

        try
        {

            if (!pki.Store.TryCreateRootCA(new SubjectName("PKIConformance ACME Root"), KeyAlgorithm.ECC_P256, 365, null, null, null, out var root, out var error, out _))
                throw new InvalidOperationException($"The root CA of the test could not be made: {error}");

            if (!pki.Store.TryIssue(root!.Id, null, CertificateProfile.SubCA, new SubjectName("PKIConformance ACME Sub"), KeyAlgorithm.ECC_P256, 300, [], null, null, null,
                                    out var sub, out error, out _))
                throw new InvalidOperationException($"The sub-CA of the test could not be made: {error}");

            if (!ACMESettings.TryParse(SettingsOf(Options, sub!.Id), out var acme, out error))
                throw new InvalidOperationException($"The ACME settings of the test are not the PKI's: {error}");

            if (!pki.TrySetACME(acme!, out error))
                throw new InvalidOperationException($"The PKI took no ACME settings: {error}");

            return new PKIACMEServer(directory,
                                     pki,
                                     tls,
                                     pki.Store.CertificatePEM(root.Id) ?? throw new InvalidOperationException("The root CA of the test has no PEM."),
                                     wslHost);

        }
        catch
        {
            await pki.DisposeAsync();
            throw;
        }

    }

    #endregion

    #region (private static) SettingsOf(Options, IssuerId)

    /// <summary>
    /// The options in the words of the "acme" section of the PKI.
    /// </summary>
    private static JObject SettingsOf(ACMEServerOptions  Options,
                                      String             IssuerId)
    {

        var json = new JObject(new JProperty("issuer", IssuerId));

        if (Options.ExternalAccountRequired)
            json["externalAccountRequired"] = true;

        if (Options.AllowedNames is not null)
            json["allowedNames"]   = new JArray(Options.AllowedNames);

        if (Options.Challenges is not null)
            json["challenges"]     = new JArray(Options.Challenges);

        if (Options.HTTP01Port is UInt16 port)
            json["http01Port"]     = port;

        if (Options.TermsOfService is not null)
            json["termsOfService"] = Options.TermsOfService;

        return json;

    }

    #endregion

    #region (private static) CommitOf(Assembly)

    /// <summary>
    /// The commit the assembly was built from, as its Directory.Build.props
    /// stamped it - shortened as git shortens it.
    /// </summary>
    private static String CommitOf(Assembly Assembly)
    {

        var commit = Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().
                              FirstOrDefault(metadata => metadata.Key == "GitCommit")?.Value ?? "unknown";

        return commit.Length > 8 && !commit.StartsWith("unknown")
                   ? commit[..8] + (commit.EndsWith("-dirty") ? "-dirty" : "")
                   : commit;

    }

    #endregion

    #region DisposeAsync()

    /// <summary>
    /// Stop the PKI and take its directory away.
    /// </summary>
    public async ValueTask DisposeAsync()
    {

        await pki.DisposeAsync();

        try
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
        catch (Exception e)
        {
            // A temporary directory that outlives one run is not worth failing it over.
            TestContext.Progress.WriteLine($"{directory} was left behind: {e.Message}");
        }

    }

    #endregion

}
