using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;

using PKIConformance.Core.RawACME;

namespace PKIConformance.Core.Scripted;

/// <summary>
/// A request the client under test sent to <see cref="ScriptedACMEServer"/>,
/// exactly as it came over the wire - and what the server made of it.
/// </summary>
public sealed class ACMERequest
{

    #region As it came

    /// <summary>Its number, from 1, in the order requests arrived.</summary>
    public required Int32                                 Number      { get; init; }

    /// <summary>The method.</summary>
    public required String                                Method      { get; init; }

    /// <summary>The request target, verbatim.</summary>
    public required String                                Target      { get; init; }

    /// <summary>The absolute URL of the request: the server's base and the target.</summary>
    public required String                                URL         { get; init; }

    /// <summary>The header fields, by name (case-insensitive); repeated ones joined by ", ".</summary>
    public required IReadOnlyDictionary<String, String>   Headers     { get; init; }

    /// <summary>The body, as UTF-8 text.</summary>
    public required String                                Body        { get; init; }

    /// <summary>When it came, by the system clock.</summary>
    public required DateTimeOffset                        At          { get; init; }

    /// <summary>When it came, by the server's clock.</summary>
    public required DateTimeOffset                        ServerTime  { get; init; }

    #endregion

    #region What the server made of it

    /// <summary>The kind of resource it was routed to: "directory", "newNonce", "newAccount", "order", ... - null for none.</summary>
    public String?               Resource       { get; internal set; }

    /// <summary>The identifier of that resource.</summary>
    public String?               ResourceId     { get; internal set; }

    /// <summary>The URL of that resource, exactly as the server handed it out.</summary>
    public String?               HandedOutURL   { get; internal set; }

    /// <summary>The names of the members of the JSON body, in their order.</summary>
    public IReadOnlyList<String> JWSMembers     { get; internal set; } = [];

    /// <summary>The JWS of the body, if it was a flattened one.</summary>
    public RawJWS?               JWS            { get; internal set; }

    /// <summary>The protected header.</summary>
    public JsonObject?           Protected      { get; internal set; }

    /// <summary>The payload as JSON text - empty for a POST-as-GET.</summary>
    public String?               PayloadJSON    { get; internal set; }

    /// <summary>The payload, parsed - null for a POST-as-GET.</summary>
    public JsonNode?             Payload        { get; internal set; }

    /// <summary>Whether the signature held by the key it names.</summary>
    public Boolean               Verified       { get; internal set; }

    /// <summary>The account it was signed for, by its "kid".</summary>
    public ScriptedAccount?      Account        { get; internal set; }

    /// <summary>The answer.</summary>
    public ScriptedAnswer?       Answer         { get; internal set; }

    /// <summary>The Replay-Nonce that went with the answer.</summary>
    public String?               AnswerNonce    { get; internal set; }

    #endregion


    #region Shorthands

    /// <summary>A header field, or null.</summary>
    public String? Header(String Name)
        => Headers.TryGetValue(Name, out var value) ? value : null;

    /// <summary>The Content-Type, verbatim.</summary>
    public String? ContentType
        => Header("Content-Type");

    /// <summary>A string member of the protected header.</summary>
    public String? ProtectedString(String Name)
        => Protected?[Name] is JsonValue value && value.TryGetValue<String>(out var text) ? text : null;

    /// <summary>"alg" of the protected header.</summary>
    public String? Alg        => ProtectedString("alg");

    /// <summary>"nonce" of the protected header.</summary>
    public String? Nonce      => ProtectedString("nonce");

    /// <summary>"url" of the protected header.</summary>
    public String? HeaderURL  => ProtectedString("url");

    /// <summary>"kid" of the protected header.</summary>
    public String? Kid        => ProtectedString("kid");

    /// <summary>"jwk" of the protected header.</summary>
    public JsonObject? JWK    => Protected?["jwk"] as JsonObject;

    /// <summary>Whether it is a POST-as-GET: a JWS of the empty payload (RFC 8555, section 6.3).</summary>
    public Boolean PostAsGet  => JWS is not null && JWS.Payload.Length == 0;

    /// <summary>The payload as an object.</summary>
    public JsonObject? PayloadObject
        => Payload as JsonObject;

    /// <summary>The evidence: the request in a few lines.</summary>
    public override String ToString()

        => $"#{Number} {ServerTime:yyyy-MM-dd HH:mm:ss.fff} {Method} {Target} [{Resource ?? "-"}] → {Answer?.Status.ToString() ?? "?"}" +
           (Protected   is not null ? $"; protected {Protected.ToJsonString()}"      : "") +
           (PayloadJSON is not null ? $"; payload {(PayloadJSON.Length > 0 ? PayloadJSON : "\"\"")}" : "") +
           (Answer?.Body is String body && body.Length > 0 ? $"; answer {(body.Length > 400 ? body[..400] + "..." : body)}" : "");

    #endregion

}


/// <summary>
/// What <see cref="ScriptedACMEServer"/> answers: a status, a body and header
/// fields - and the Replay-Nonce, fresh by default.
/// </summary>
public sealed record ScriptedAnswer(Int32                                        Status,
                                    String?                                      Body         = null,
                                    String?                                      ContentType  = null,
                                    IReadOnlyList<(String Name, String Value)>?  Headers      = null)
{

    /// <summary>The prefix of the error types of RFC 8555.</summary>
    public const String ErrorPrefix = "urn:ietf:params:acme:error:";

    /// <summary>The Replay-Nonce to send - a fresh one of the server's where null.</summary>
    public String?  ReplayNonce   { get; init; }

    /// <summary>Whether to send no Replay-Nonce at all.</summary>
    public Boolean  WithoutNonce  { get; init; }

    /// <summary>A JSON answer.</summary>
    public static ScriptedAnswer Json(Int32 Status, JsonNode Body, params (String Name, String Value)[] Headers)
        => new (Status, Body.ToJsonString(), "application/json", Headers);

    /// <summary>
    /// A problem document (RFC 7807) - of an error type of RFC 8555 where the
    /// type has no colon.
    /// </summary>
    public static ScriptedAnswer Problem(Int32        Status,
                                         String       Type,
                                         String?      Detail   = null,
                                         JsonObject?  Members  = null)
    {

        var problem = new JsonObject {
                          ["type"]   = Type.Contains(':') ? Type : ErrorPrefix + Type,
                          ["status"] = Status
                      };

        if (Detail is not null)
            problem["detail"] = Detail;

        if (Members is not null)
            foreach (var (name, value) in Members)
                problem[name] = value?.DeepClone();

        return new (Status, problem.ToJsonString(), "application/problem+json");

    }

    /// <summary>The answer with one more header field.</summary>
    public ScriptedAnswer With(String Name, String Value)
        => this with { Headers = [ .. Headers ?? [], (Name, Value) ] };

    /// <summary>The answer without a header field.</summary>
    public ScriptedAnswer Without(String Name)
        => this with { Headers = [ .. (Headers ?? []).Where(header => !header.Name.Equals(Name, StringComparison.OrdinalIgnoreCase)) ] };

    /// <summary>The answer with a header field set to the value, whatever it had.</summary>
    public ScriptedAnswer Replace(String Name, String Value)
        => Without(Name).With(Name, Value);

    /// <summary>A header field of the answer, or null.</summary>
    public String? Header(String Name)
        => Headers?.FirstOrDefault(header => header.Name.Equals(Name, StringComparison.OrdinalIgnoreCase)).Value;

    /// <summary>The body as a JSON object, or null.</summary>
    public JsonObject? JSON
    {
        get
        {
            try
            {
                return Body is not null && Body.TrimStart().StartsWith('{') ? JsonNode.Parse(Body) as JsonObject : null;
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }

    /// <summary>The body rewritten as JSON.</summary>
    public ScriptedAnswer MapJSON(Action<JsonObject> Change)
    {

        var json = JSON ?? throw new InvalidOperationException($"The answer has no JSON object: {Body}");
        Change(json);
        return this with { Body = json.ToJsonString() };

    }

    /// <summary>The error type of a problem document, without the prefix of RFC 8555.</summary>
    public String? ErrorType
        => JSON?["type"] is JsonValue value && value.TryGetValue<String>(out var type)
               ? (type.StartsWith(ErrorPrefix, StringComparison.Ordinal) ? type[ErrorPrefix.Length..] : type)
               : null;

}


/// <summary>An account of the scripted server.</summary>
public sealed class ScriptedAccount
{
    public required String  Id                    { get; init; }
    public required String  URL                   { get; init; }
    public required String  OrdersURL             { get; init; }
    public required RawJWK  Key                   { get; set; }
    public String           Status                { get; set; } = "valid";
    public List<String>     Contacts              { get; set; } = [];
    public Boolean          TermsOfServiceAgreed  { get; set; }
    public String?          ExternalAccountKeyId  { get; set; }
    public JsonObject?      ExternalAccountBinding { get; set; }
}

/// <summary>An identifier of an order (RFC 8555, section 9.7.7).</summary>
public sealed record ScriptedIdentifier(String Type, String Value)
{
    public JsonObject ToJSON() => new () { ["type"] = Type, ["value"] = Value };
    public override String ToString() => $"{Type}:{Value}";
}

/// <summary>An order of the scripted server.</summary>
public sealed class ScriptedOrder
{
    public required String                       Id              { get; init; }
    public required String                       URL             { get; init; }
    public required String                       FinalizeURL     { get; init; }
    public required ScriptedAccount              Account         { get; init; }
    public required List<ScriptedIdentifier>     Identifiers     { get; init; }
    public required List<ScriptedAuthorization>  Authorizations  { get; init; }
    public required DateTimeOffset               Expires         { get; init; }
    public String                                Status          { get; set; } = "pending";
    public String?                               Profile         { get; set; }
    public String?                               Replaces        { get; set; }
    public JsonObject?                           Error           { get; set; }
    public Int32                                 PollsLeft       { get; set; }
    public ScriptedCSR?                          CSR             { get; set; }
    public ScriptedCertificate?                  Certificate     { get; set; }
}

/// <summary>An authorization of the scripted server.</summary>
public sealed class ScriptedAuthorization
{
    public required String                   Id          { get; init; }
    public required String                   URL         { get; init; }
    public required ScriptedAccount          Account     { get; init; }
    public required ScriptedIdentifier       Identifier  { get; init; }
    public required Boolean                  Wildcard    { get; init; }
    public required List<ScriptedChallenge>  Challenges  { get; init; }
    public DateTimeOffset                    Expires     { get; set; }
    public String                            Status      { get; set; } = "pending";
    public Int32                             PollsLeft   { get; set; }
}

/// <summary>A challenge of the scripted server.</summary>
public sealed class ScriptedChallenge
{
    public required String                  Id             { get; init; }
    public required String                  URL            { get; init; }
    public required String                  Type           { get; init; }
    public required String                  Token          { get; init; }
    public required ScriptedAuthorization   Authorization  { get; init; }
    public String                           Status         { get; set; } = "pending";
    public JsonObject?                      Error          { get; set; }
    public DateTimeOffset?                  RespondedAt    { get; set; }
    public DateTimeOffset?                  Validated      { get; set; }
    public (Boolean Valid, String Detail)?  Result         { get; set; }
}

/// <summary>A certificate the scripted server issued.</summary>
public sealed class ScriptedCertificate
{
    public required String            Id         { get; init; }
    public required String            URL        { get; init; }
    public required X509Certificate2  Leaf       { get; init; }
    public required String            ChainPEM   { get; set; }
    public required ScriptedAccount   Account    { get; init; }
    public required ScriptedOrder     Order      { get; init; }
    public required String            ARIId      { get; init; }
    public List<String>               Alternates { get; } = [];
    public Boolean                    Revoked    { get; set; }
    public Int32?                     Reason     { get; set; }
    public Byte[]                     DER        => Leaf.RawData;
}

/// <summary>A certificate signing request as the scripted server read it, with .NET.</summary>
/// <param name="DER">The request.</param>
/// <param name="Names">Its subject alternative names: dns and ip.</param>
/// <param name="CommonName">The common name of its subject, if any.</param>
/// <param name="KeyAlgorithm">"EC" or "RSA".</param>
/// <param name="KeySize">The key size in bits.</param>
/// <param name="Curve">The curve of an EC key, as "P-256".</param>
/// <param name="SignatureAlgorithm">The OID of the signature algorithm.</param>
/// <param name="PublicKey">The public key.</param>
public sealed record ScriptedCSR(Byte[]                            DER,
                                 IReadOnlyList<ScriptedIdentifier>  Names,
                                 String?                           CommonName,
                                 String                            KeyAlgorithm,
                                 Int32                             KeySize,
                                 String?                           Curve,
                                 String                            SignatureAlgorithm,
                                 PublicKey                         PublicKey,
                                 RawJWK                            JWK);

/// <summary>A validation the scripted server made of a challenge.</summary>
public sealed record ScriptedValidation(ScriptedChallenge  Challenge,
                                        DateTimeOffset     At,
                                        Boolean            Valid,
                                        String             Detail);
