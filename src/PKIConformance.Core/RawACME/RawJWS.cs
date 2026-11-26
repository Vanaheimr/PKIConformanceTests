using System.Text;
using System.Text.Json;

namespace PKIConformance.Core.RawACME;

/// <summary>
/// A JWS (RFC 7515) as ACME uses it - the flattened JSON serialization of
/// one signature (RFC 8555, section 6.2) - made and read by hand.
/// </summary>
/// <remarks>
/// <para>
/// The protected header and the payload are JSON text the caller writes:
/// a test that wants a header member twice, a payload that is no object, or
/// an "alg" of "none" gets exactly that, and a test that wants a correct
/// request takes <see cref="ACME"/>.
/// </para>
/// </remarks>
public sealed class RawJWS
{

    #region Properties

    /// <summary>The protected header, base64url.</summary>
    public String  Protected  { get; }

    /// <summary>The payload, base64url - empty for a POST-as-GET (RFC 8555, section 6.3).</summary>
    public String  Payload    { get; }

    /// <summary>The signature, base64url.</summary>
    public String  Signature  { get; }

    /// <summary>
    /// What is signed: ASCII(BASE64URL(protected) || '.' || BASE64URL(payload)),
    /// RFC 7515, section 5.1.
    /// </summary>
    public Byte[]  SigningInput
        => Encoding.ASCII.GetBytes($"{Protected}.{Payload}");

    /// <summary>
    /// The protected header as JSON text.
    /// </summary>
    public String  ProtectedJSON
        => Encoding.UTF8.GetString(RawBase64Url.Decode(Protected));

    /// <summary>
    /// The payload as JSON text - empty for a POST-as-GET.
    /// </summary>
    public String  PayloadJSON
        => Encoding.UTF8.GetString(RawBase64Url.Decode(Payload));

    #endregion

    #region Constructor(s)

    /// <summary>
    /// A JWS of its three parts, each base64url as they go on the wire.
    /// </summary>
    public RawJWS(String  Protected,
                  String  Payload,
                  String  Signature)
    {
        this.Protected  = Protected;
        this.Payload    = Payload;
        this.Signature  = Signature;
    }

    #endregion


    #region (static) Sign(Signer, ProtectedJSON, PayloadJSON)

    /// <summary>
    /// The JWS of the header and the payload, signed by whatever the signer
    /// is - a key of the raw codec, one of a party under test, a MAC.
    /// </summary>
    /// <param name="Signer">The signature of the signing input.</param>
    /// <param name="ProtectedJSON">The protected header, as JSON text.</param>
    /// <param name="PayloadJSON">The payload, as JSON text; null for the empty payload of a POST-as-GET.</param>
    public static RawJWS Sign(Func<Byte[], Byte[]>  Signer,
                              String                ProtectedJSON,
                              String?               PayloadJSON)
    {

        var @protected  = RawBase64Url.Encode(ProtectedJSON);
        var payload     = PayloadJSON is null ? "" : RawBase64Url.Encode(PayloadJSON);

        return new RawJWS(@protected,
                          payload,
                          RawBase64Url.Encode(Signer(Encoding.ASCII.GetBytes($"{@protected}.{payload}"))));

    }

    /// <summary>
    /// The JWS of the header and the payload, signed by the key.
    /// </summary>
    public static RawJWS Sign(RawKey   Key,
                              String   ProtectedJSON,
                              String?  PayloadJSON)

        => Sign(data => Key.Sign(data), ProtectedJSON, PayloadJSON);

    #endregion

    #region (static) ACME(Key, URL, Nonce, KeyId, PayloadJSON)

    /// <summary>
    /// A request of ACME as RFC 8555, section 6.2, has it: "alg", "nonce",
    /// "url", and the "jwk" of the key where there is no account URL yet,
    /// its "kid" otherwise.
    /// </summary>
    /// <param name="Key">The account key.</param>
    /// <param name="URL">The URL the request is sent to.</param>
    /// <param name="Nonce">A nonce of the server; null for none at all, as in the inner JWS of a key change.</param>
    /// <param name="KeyId">The account URL; null to send the "jwk" instead.</param>
    /// <param name="PayloadJSON">The payload; null for a POST-as-GET.</param>
    public static RawJWS ACME(RawKey   Key,
                              String   URL,
                              String?  Nonce,
                              String?  KeyId,
                              String?  PayloadJSON)
    {

        var members = new List<(String, String)> { ("alg", RawJson.Quote(Key.Algorithm)) };

        if (KeyId is null)
            members.Add(("jwk",  Key.JWK.ToJSON()));
        else
            members.Add(("kid",  RawJson.Quote(KeyId)));

        if (Nonce is not null)
            members.Add(("nonce", RawJson.Quote(Nonce)));

        members.Add(("url", RawJson.Quote(URL)));

        return Sign(Key, RawJson.Object([.. members]), PayloadJSON);

    }

    #endregion


    #region ToFlattenedJSON() / ToCompact()

    /// <summary>
    /// The flattened JSON serialization (RFC 7515, section 7.2.2) - the body of
    /// a request of ACME.
    /// </summary>
    public String ToFlattenedJSON()

        => RawJson.Object(("protected",  RawJson.Quote(Protected)),
                          ("payload",    RawJson.Quote(Payload)),
                          ("signature",  RawJson.Quote(Signature)));

    /// <summary>
    /// The compact serialization (RFC 7515, section 7.1) - which ACME does not
    /// use, and which the examples of RFC 7515 are written in.
    /// </summary>
    public String ToCompact()
        => $"{Protected}.{Payload}.{Signature}";

    #endregion

    #region (static) ParseCompact(Text) / ParseFlattened(JSON)

    /// <summary>
    /// A JWS of the compact serialization.
    /// </summary>
    public static RawJWS ParseCompact(String Text)
    {

        var parts = Text.Split('.');

        if (parts.Length != 3)
            throw new FormatException($"A JWS of the compact serialization has three parts, not {parts.Length}.");

        return new RawJWS(parts[0], parts[1], parts[2]);

    }

    /// <summary>
    /// A JWS of the flattened JSON serialization.
    /// </summary>
    public static RawJWS ParseFlattened(String JSON)
    {

        using var document = JsonDocument.Parse(JSON);
        var       root     = document.RootElement;

        String Member(String Name)
            => root.TryGetProperty(Name, out var value) && value.ValueKind == JsonValueKind.String
                   ? value.GetString()!
                   : throw new FormatException($"A flattened JWS has \"{Name}\" as a string.");

        return new RawJWS(Member("protected"), Member("payload"), Member("signature"));

    }

    #endregion

    #region Header(Name)

    /// <summary>
    /// A member of the protected header, as raw JSON text - null where it has none.
    /// </summary>
    public String? Header(String Name)
    {

        using var document = JsonDocument.Parse(ProtectedJSON);

        return document.RootElement.TryGetProperty(Name, out var value)
                   ? value.GetRawText()
                   : null;

    }

    #endregion

    #region VerifiedBy(JWK, Algorithm = null)

    /// <summary>
    /// Whether the signature holds by the JWK - for the algorithm given, or
    /// for the "alg" of the protected header.
    /// </summary>
    public Boolean VerifiedBy(RawJWK   JWK,
                              String?  Algorithm = null)
    {

        Algorithm ??= JsonSerializer.Deserialize<String>(Header("alg") ?? "null");

        return Algorithm is not null &&
               RawBase64Url.TryDecode(Signature, out var signature, out _) &&
               RawKey.Verify(JWK, Algorithm, SigningInput, signature);

    }

    #endregion

}
