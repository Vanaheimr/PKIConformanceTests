using System.Security.Cryptography;

namespace PKIConformance.Core.RawACME;

/// <summary>
/// The two JWS that ride inside a request of ACME: the external account
/// binding of a new account (RFC 8555, section 7.3.4), and the inner JWS of
/// a key change (section 7.3.5).
/// </summary>
public static class RawAccountJWS
{

    #region ExternalAccountBinding(KeyId, MACKey, AccountKey, NewAccountURL, Algorithm = "HS256")

    /// <summary>
    /// <i>"The "alg" field MUST indicate a MAC-based algorithm; The "kid" field
    /// MUST contain the key identifier provided by the CA; The "nonce" field
    /// MUST NOT be present; The "url" field MUST be set to the same value as
    /// the outer JWS"</i> - and the payload is the account key's JWK.
    /// </summary>
    /// <param name="KeyId">The key identifier the CA gave.</param>
    /// <param name="MACKey">The MAC key the CA gave, decoded.</param>
    /// <param name="AccountKey">The JWK of the account key - the "jwk" of the outer JWS.</param>
    /// <param name="NewAccountURL">The URL of newAccount - the "url" of the outer JWS.</param>
    /// <param name="Algorithm">HS256, HS384 or HS512.</param>
    public static RawJWS ExternalAccountBinding(String  KeyId,
                                                Byte[]  MACKey,
                                                RawJWK  AccountKey,
                                                String  NewAccountURL,
                                                String  Algorithm = "HS256")

        => RawJWS.Sign(data => Algorithm switch {
                                   "HS256" => HMACSHA256.HashData(MACKey, data),
                                   "HS384" => HMACSHA384.HashData(MACKey, data),
                                   "HS512" => HMACSHA512.HashData(MACKey, data),
                                   _       => throw new ArgumentException($"'{Algorithm}' is no MAC of RFC 7518.", nameof(Algorithm))
                               },
                       RawJson.Object(("alg", RawJson.Quote(Algorithm)),
                                      ("kid", RawJson.Quote(KeyId)),
                                      ("url", RawJson.Quote(NewAccountURL))),
                       AccountKey.ToJSON());

    #endregion

    #region KeyChange(NewKey, AccountURL, OldKey, KeyChangeURL)

    /// <summary>
    /// The inner JWS of a key change: <i>"The inner JWS MUST have a "jwk" header
    /// parameter containing the public key of the new key. The inner JWS MUST
    /// have the same "url" header parameter as the outer JWS. The inner JWS MAY
    /// omit the "nonce" header parameter."</i> - signed by the new key, with
    /// the account URL and the old key as its payload.
    /// </summary>
    public static RawJWS KeyChange(RawKey  NewKey,
                                   String  AccountURL,
                                   RawJWK  OldKey,
                                   String  KeyChangeURL)

        => RawJWS.ACME(NewKey,
                       KeyChangeURL,
                       Nonce:        null,
                       KeyId:        null,
                       PayloadJSON:  RawJson.Object(("account", RawJson.Quote(AccountURL)),
                                                    ("oldKey",  OldKey.ToJSON())));

    #endregion

}
