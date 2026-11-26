using System.Security.Cryptography;
using System.Text;

namespace PKIConformance.Core.RawACME;

/// <summary>
/// What answers a challenge (RFC 8555, section 8): the key authorization, and
/// what http-01 and dns-01 make of it.
/// </summary>
public static class RawChallenge
{

    /// <summary>
    /// <i>"keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))"</i>
    /// - RFC 8555, section 8.1.
    /// </summary>
    public static String KeyAuthorization(String  Token,
                                          RawJWK  AccountKey)

        => $"{Token}.{AccountKey.Thumbprint}";

    /// <summary>
    /// The text of the TXT record of dns-01: <i>"the base64url encoding of the
    /// SHA-256 digest [FIPS180-4] of the key authorization"</i> - RFC 8555,
    /// section 8.4.
    /// </summary>
    public static String DNS01Value(String KeyAuthorization)

        => RawBase64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(KeyAuthorization)));

    /// <summary>
    /// The name of the TXT record of dns-01: "_acme-challenge" below the name -
    /// below the base name for a wildcard (RFC 8555, sections 8.4 and 7.1.3).
    /// </summary>
    public static String DNS01Name(String Identifier)

        => $"_acme-challenge.{(Identifier.StartsWith("*.") ? Identifier[2..] : Identifier)}";

    /// <summary>
    /// The path of http-01: <i>"/.well-known/acme-challenge/" || token</i> -
    /// RFC 8555, section 8.3.
    /// </summary>
    public static String HTTP01Path(String Token)

        => $"/.well-known/acme-challenge/{Token}";

}
