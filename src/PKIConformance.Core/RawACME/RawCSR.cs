using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PKIConformance.Core.RawACME;

/// <summary>
/// The CSR of a finalize request (RFC 8555, section 7.4): a PKCS#10 request
/// of RFC 2986, made with .NET's <see cref="CertificateRequest"/> alone - never
/// with the CSR code of a party under test.
/// </summary>
public static class RawCSR
{

    #region (static) Create(Key, Identifiers, CommonName = null)

    /// <summary>
    /// The DER of a CSR for the identifiers - "dns" names and "ip" addresses
    /// in the subjectAltName, in the order given - signed by the key.
    /// </summary>
    /// <param name="Key">The certificate key: ECDsa or RSA.</param>
    /// <param name="Identifiers">The identifiers, as (type, value).</param>
    /// <param name="CommonName">The common name of the subject; none where null.</param>
    public static Byte[] Create(AsymmetricAlgorithm                         Key,
                                IEnumerable<(String Type, String Value)>    Identifiers,
                                String?                                     CommonName = null)
    {

        var subject  = new X500DistinguishedName(CommonName is null ? "" : $"CN={CommonName}");

        var request  = Key switch {
                           ECDsa ec                            => new CertificateRequest(subject, ec,  HashAlgorithmName.SHA256),
                           System.Security.Cryptography.RSA rsa => new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                           _                                   => throw new ArgumentException($"A {Key.GetType().Name} makes no CSR here.", nameof(Key))
                       };

        var san      = new SubjectAlternativeNameBuilder();
        var any      = false;

        foreach (var (type, value) in Identifiers)
        {

            if (type == "dns")
                san.AddDnsName(value);

            else if (type == "ip")
                san.AddIpAddress(IPAddress.Parse(value));

            else
                throw new ArgumentException($"'{type}' is no identifier of a CSR here.", nameof(Identifiers));

            any = true;

        }

        if (any)
            request.CertificateExtensions.Add(san.Build());

        return request.CreateSigningRequest();

    }

    /// <summary>
    /// The CSR for the identifiers, signed by the key, base64url - the "csr"
    /// of a finalize request.
    /// </summary>
    public static String CreateBase64Url(AsymmetricAlgorithm                       Key,
                                         IEnumerable<(String Type, String Value)>  Identifiers,
                                         String?                                   CommonName = null)

        => RawBase64Url.Encode(Create(Key, Identifiers, CommonName));

    #endregion

}
