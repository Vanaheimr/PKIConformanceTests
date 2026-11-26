using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PKIConformance.Core.Scripted;

/// <summary>
/// The certificate authority behind <see cref="ScriptedACMEServer"/>: a root
/// and a chain of intermediates, made with .NET alone - neither by Hermod
/// nor by the PKI - that issues what the server decides.
/// </summary>
/// <remarks>
/// A chain as it goes to a client is the leaf and every intermediate, the
/// issuing one first, and no root - as Let's Encrypt and Pebble send it. With
/// no intermediate at all the root issues, and the chain is the leaf alone.
/// </remarks>
public sealed class BenchCA : IDisposable
{

    #region Data

    private readonly List<(X509Certificate2 Certificate, ECDsa Key)> authorities = [];
    private          X509Certificate2?                                 alternateRoot;
    private          X509Certificate2?                                 crossSigned;

    #endregion

    #region Properties

    /// <summary>The root.</summary>
    public X509Certificate2                Root
        => authorities[0].Certificate;

    /// <summary>The intermediates, the issuing one first.</summary>
    public IReadOnlyList<X509Certificate2> Intermediates
        => [.. authorities.Skip(1).Select(authority => authority.Certificate).Reverse()];

    /// <summary>The certificate that signs the leaves.</summary>
    public X509Certificate2                Issuing
        => authorities[^1].Certificate;

    #endregion

    #region Constructor(s)

    private BenchCA() { }

    /// <summary>
    /// A root and the given number of intermediates below it, valid from ten
    /// years ago to thirty years ahead - so that a clock of the bench far
    /// from today finds them valid all the same.
    /// </summary>
    public static BenchCA Create(Int32   Intermediates = 1,
                                 String  Name          = "PKIConformance Bench CA")
    {

        var ca        = new BenchCA();
        var notBefore = DateTimeOffset.UtcNow.AddYears(-10);
        var notAfter  = DateTimeOffset.UtcNow.AddYears(30);

        var rootKey   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var root      = new CertificateRequest($"CN={Name} Root", rootKey, HashAlgorithmName.SHA256);

        AuthorityExtensions(root, null);

        ca.authorities.Add((root.CreateSelfSigned(notBefore, notAfter), rootKey));

        for (var level = 1; level <= Intermediates; level++)
            ca.authorities.Add(ca.Subordinate($"CN={Name} Intermediate {level}", ca.authorities[^1], notBefore, notAfter));

        return ca;

    }

    #endregion


    #region Issue(PublicKey, Identifiers, NotBefore, NotAfter, CommonName = null)

    /// <summary>
    /// A leaf of the public key for the identifiers - as subject alternative
    /// names, dNSName and iPAddress - with the key identifier of its issuer
    /// (which ARI, RFC 9773, needs), serverAuth, and a random serial.
    /// </summary>
    public X509Certificate2 Issue(PublicKey                                  Key,
                                  IEnumerable<(String Type, String Value)>   Identifiers,
                                  DateTimeOffset                             NotBefore,
                                  DateTimeOffset                             NotAfter,
                                  String?                                    CommonName = null)
    {

        var (issuer, issuerKey) = authorities[^1];

        // Signed by the issuer's ECDSA key, whatever the leaf's is.
        var request = new CertificateRequest(new X500DistinguishedName(CommonName is not null ? $"CN={CommonName}" : ""), Key, HashAlgorithmName.SHA256);

        var names   = new SubjectAlternativeNameBuilder();

        foreach (var (type, value) in Identifiers)
        {
            if (type == "ip")
                names.AddIpAddress(IPAddress.Parse(value));
            else
                names.AddDnsName(value);
        }

        request.CertificateExtensions.Add(names.Build(critical: CommonName is null));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature |
                                                                    (Key.Oid.Value == "1.2.840.113549.1.1.1" ? X509KeyUsageFlags.KeyEncipherment : 0), true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1") ], false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(Key, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, true, false));

        return request.Create(issuer.SubjectName, X509SignatureGenerator.CreateForECDsa(issuerKey), NotBefore, NotAfter, Serial());

    }

    #endregion

    #region ChainPem(Leaf) / AlternateChainPem(Leaf)

    /// <summary>
    /// The chain of the leaf as an ACME server sends it (RFC 8555, section
    /// 9.1): the leaf, then every intermediate, issuing one first.
    /// </summary>
    public String ChainPem(X509Certificate2 Leaf)

        => Pem([ Leaf, .. Intermediates ]);

    /// <summary>
    /// Another chain of the same leaf (RFC 8555, section 7.4.2, "alternate"):
    /// its issuing intermediate cross-signed by a second root, as Let's
    /// Encrypt's ISRG X1/X2 chains were.
    /// </summary>
    public String AlternateChainPem(X509Certificate2 Leaf)
    {

        if (crossSigned is null)
        {

            var notBefore             = DateTimeOffset.UtcNow.AddYears(-10);
            var notAfter              = DateTimeOffset.UtcNow.AddYears(30);
            var rootKey               = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var root                  = new CertificateRequest($"CN={Root.GetNameInfo(X509NameType.SimpleName, false)} Alternate", rootKey, HashAlgorithmName.SHA256);
            AuthorityExtensions(root, null);
            alternateRoot             = root.CreateSelfSigned(notBefore, notAfter);

            var (issuing, issuingKey) = authorities[^1];
            var cross                 = new CertificateRequest(issuing.SubjectName, issuingKey, HashAlgorithmName.SHA256);
            AuthorityExtensions(cross, alternateRoot);
            crossSigned               = cross.Create(alternateRoot.SubjectName, X509SignatureGenerator.CreateForECDsa(rootKey), notBefore, notAfter, Serial());

        }

        return Pem([ Leaf, crossSigned ]);

    }

    /// <summary>
    /// Certificates as PEM, one block after the other, as .NET writes them.
    /// </summary>
    public static String Pem(IEnumerable<X509Certificate2> Certificates)
    {

        var text = new StringBuilder();

        foreach (var certificate in Certificates)
            text.Append(certificate.ExportCertificatePem()).Append('\n');

        return text.ToString();

    }

    #endregion


    #region (private) Subordinate(...) / AuthorityExtensions(...) / Serial()

    private (X509Certificate2, ECDsa) Subordinate(String                                   Subject,
                                                  (X509Certificate2 Certificate, ECDsa Key) Issuer,
                                                  DateTimeOffset                           NotBefore,
                                                  DateTimeOffset                           NotAfter)
    {

        var key     = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(Subject, key, HashAlgorithmName.SHA256);

        AuthorityExtensions(request, Issuer.Certificate);

        return (request.Create(Issuer.Certificate.SubjectName, X509SignatureGenerator.CreateForECDsa(Issuer.Key), NotBefore, NotAfter, Serial()).CopyWithPrivateKey(key), key);

    }

    private static void AuthorityExtensions(CertificateRequest  Request,
                                            X509Certificate2?   Issuer)
    {

        Request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        Request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        Request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(Request.PublicKey, false));

        if (Issuer is not null)
            Request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Issuer, true, false));

    }

    /// <summary>
    /// 16 random octets, positive and of their full length.
    /// </summary>
    private static Byte[] Serial()
    {

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0]  = (Byte) ((serial[0] & 0x7F) | 0x10);
        return serial;

    }

    #endregion


    #region Dispose()

    public void Dispose()
    {

        foreach (var (certificate, key) in authorities)
        {
            certificate.Dispose();
            key.Dispose();
        }

        alternateRoot?.Dispose();
        crossSigned?.  Dispose();

    }

    #endregion

}
