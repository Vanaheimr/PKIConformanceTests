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
    private readonly String    issuerId;

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
                          String    IssuerId,
                          String?   WslHost)
    {

        this.directory       = Directory;
        this.pki             = PKI;
        this.TLS             = TLS;
        this.IssuingRootPEM  = IssuingRootPEM;
        this.issuerId        = IssuerId;

        var port             = PKI.HTTPPort.ToUInt16();

        this.DirectoryURL    = new Uri($"https://127.0.0.1:{port}/acme/directory");
        this.Name            = Revisions.PKI;

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
                                     sub.Id,
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

        var json = Options.DefaultProfile
                       ? new JObject(new JProperty("issuer", IssuerId))
                       : [];

        if (Options.Profiles is not null)
            json["profiles"] = new JObject(Options.Profiles.Select(profile => new JProperty(profile.Key, new JObject(
                                                                                    new JProperty("issuer",       IssuerId),
                                                                                    new JProperty("validDays",    profile.Value),
                                                                                    new JProperty("description",  $"{profile.Value} days.")))));

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

    #region NewExternalAccountKeyAsync()

    /// <inheritdoc/>
    public Task<(String KeyId, Byte[] MACKey)> NewExternalAccountKeyAsync()

        => pki.ACMEState.TryNewExternalAccountKey("PKIConformance", "pkiconformance", out var key, out var error)
               ? Task.FromResult((key.KeyId, key.MACKey))
               : throw new InvalidOperationException($"The PKI made no key of an external account binding: {error}");

    #endregion

    #region Accounts() / Issued() / CRL()

    /// <inheritdoc/>
    public IReadOnlyList<ServerAccount> Accounts()

        => [ .. pki.ACMEState.Accounts().Select(account => new ServerAccount(
                                                               account.Id,
                                                               account.Status,
                                                               [ .. account.Contacts ],
                                                               account.JWK.Value<String>("kty") ?? "?",
                                                               account.JWK.Value<String>("kty") == "RSA"
                                                                   ? (Base64UrlLength(account.JWK.Value<String>("n")) * 8).ToString()
                                                                   : account.JWK.Value<String>("crv"),
                                                               account.ExternalAccount,
                                                               RawACME.RawJWK.Parse(account.JWK.ToString()).Thumbprint)) ];

    /// <inheritdoc/>
    public IReadOnlyList<ServerIssued> Issued()

        => [ .. pki.ACMEState.Accounts().
                              SelectMany(account => pki.ACMEState.IssuedFor(account.Id)).
                              Select(issued => {
                                  using var certificate = pki.Store.Load(issued.CertificateId);
                                  var revocation        = pki.Store.RevocationOf(issued.CertificateId);
                                  // The PKI keeps what an order replaces by its own identifier of
                                  // the certificate; the interface speaks RFC 9773's.
                                  using var replaced    = issued.Replaces is not null ? pki.Store.Load(issued.Replaces) : null;
                                  return new ServerIssued(certificate?.RawData ?? [],
                                                          issued.AccountId,
                                                          replaced is not null ? RawACME.RawARI.CertificateId(replaced.RawData) : issued.Replaces,
                                                          revocation is not null,
                                                          revocation is not null ? (Int32) revocation.Reason : null);
                              }) ];

    /// <inheritdoc/>
    public Byte[]? CRL()
        => pki.Store.CRL(issuerId);

    private static Int32 Base64UrlLength(String? Text)
    {
        if (Text is null)
            return 0;
        var octets = Text.Length * 3 / 4;
        // An RSA modulus is sent without leading zero octets (RFC 7518, section 6.3.1.1).
        return octets;
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
