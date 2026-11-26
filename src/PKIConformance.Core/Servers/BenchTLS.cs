using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PKIConformance.Core.Servers;

/// <summary>
/// The TLS of a server under test: a root of the bench and a server
/// certificate below it for the addresses the server is reached at, written
/// as the PEM files a server reads and a peer trusts.
/// </summary>
/// <remarks>
/// <para>
/// <i>"Each ACME function is accomplished by the client sending a sequence of
/// HTTPS requests to the server"</i> (RFC 8555, section 6.1) - and lego, for
/// one, refuses anything else. The certificate is made here, with nothing but
/// .NET, and not by the PKI under test: what the clients connect through is
/// not to depend on what is being tested.
/// </para>
/// </remarks>
public sealed class BenchTLS
{

    #region Properties

    /// <summary>
    /// The PEM file with the server certificate - what a server shows.
    /// </summary>
    public String  FullChainFile   { get; }

    /// <summary>
    /// The PEM file with its private key.
    /// </summary>
    public String  PrivateKeyFile  { get; }

    /// <summary>
    /// The PEM file with the root of the bench - what a peer trusts.
    /// </summary>
    public String  RootFile        { get; }

    /// <summary>
    /// The root of the bench, in PEM.
    /// </summary>
    public String  RootPEM         { get; }

    #endregion

    #region Constructor(s)

    private BenchTLS(String  FullChainFile,
                     String  PrivateKeyFile,
                     String  RootFile,
                     String  RootPEM)
    {
        this.FullChainFile   = FullChainFile;
        this.PrivateKeyFile  = PrivateKeyFile;
        this.RootFile        = RootFile;
        this.RootPEM         = RootPEM;
    }

    #endregion


    #region Create(Directory, Hosts)

    /// <summary>
    /// A root and a server certificate for the given names and addresses,
    /// written into the given directory. Valid from five minutes ago for a
    /// day: long enough for a run, short enough to be of no use after it.
    /// </summary>
    public static BenchTLS Create(String               Directory,
                                  IEnumerable<String>  Hosts)
    {

        var now = DateTimeOffset.UtcNow;

        using var rootKey      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       rootRequest  = new CertificateRequest("CN=PKIConformance TLS Bench Root", rootKey, HashAlgorithmName.SHA256);

        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));

        using var root         = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(1).AddMinutes(5));

        using var key          = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var       request      = new CertificateRequest("CN=PKIConformance ACME server", key, HashAlgorithmName.SHA256);
        var       names        = new SubjectAlternativeNameBuilder();

        foreach (var host in Hosts.Distinct())
        {
            if (System.Net.IPAddress.TryParse(host, out var address))
                names.AddIpAddress(address);
            else
                names.AddDnsName(host);
        }

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, includeKeyIdentifier: true, includeIssuerAndSerial: false));
        request.CertificateExtensions.Add(names.Build());

        // A positive serial number of 127 bits (RFC 5280, section 4.1.2.2).
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0]  = (Byte) ((serial[0] & 0x7F) | 0x01);

        using var leaf         = request.Create(root, now.AddMinutes(-5), now.AddDays(1), serial);

        var fullChainFile      = Path.Combine(Directory, "tls-fullchain.pem");
        var privateKeyFile     = Path.Combine(Directory, "tls-privkey.pem");
        var rootFile           = Path.Combine(Directory, "tls-root.pem");
        var rootPEM            = root.ExportCertificatePem();

        File.WriteAllText(fullChainFile,   leaf.ExportCertificatePem() + "\n");
        File.WriteAllText(privateKeyFile,  key.ExportPkcs8PrivateKeyPem() + "\n");
        File.WriteAllText(rootFile,        rootPEM + "\n");

        return new BenchTLS(fullChainFile, privateKeyFile, rootFile, rootPEM);

    }

    #endregion

    #region NewHttpClient(Timeout = null)

    /// <summary>
    /// An HTTP client of .NET - not Hermod's - that trusts the root of the
    /// bench and nothing else, and follows no redirect on its own.
    /// </summary>
    public HttpClient NewHttpClient(TimeSpan? Timeout = null)
    {

        var root = X509Certificate2.CreateFromPem(RootPEM);

        var handler = new SocketsHttpHandler {
                          AllowAutoRedirect  = false,
                          UseProxy           = false,
                          SslOptions         = {
                              RemoteCertificateValidationCallback = (_, certificate, _, errors) => {

                                  // The name: SslStream has compared it already and says so in
                                  // the errors. The chain it built against the machine's roots
                                  // is what this replaces, by one against the bench's root.
                                  if (certificate is null ||
                                      errors.HasFlag(System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch) ||
                                      errors.HasFlag(System.Net.Security.SslPolicyErrors.RemoteCertificateNotAvailable))
                                      return false;

                                  using var chain = new X509Chain();
                                  chain.ChainPolicy.TrustMode       = X509ChainTrustMode.CustomRootTrust;
                                  chain.ChainPolicy.RevocationMode  = X509RevocationMode.NoCheck;
                                  chain.ChainPolicy.CustomTrustStore.Add(root);

                                  return chain.Build(certificate as X509Certificate2 ?? X509CertificateLoader.LoadCertificate(certificate.GetRawCertData()));

                              }
                          }
                      };

        return new HttpClient(handler, disposeHandler: true) {
                   Timeout = Timeout ?? TimeSpan.FromSeconds(30)
               };

    }

    #endregion

}
