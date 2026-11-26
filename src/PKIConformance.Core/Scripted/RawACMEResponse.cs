using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace PKIConformance.Core.Scripted;

/// <summary>
/// What an ACME server answered, as it came: the status, every header field,
/// the body - and, read with System.Text.Json, its JSON where it has any.
/// </summary>
public sealed partial class RawACMEResponse
{

    #region Data

    /// <summary>
    /// The prefix of every error type of RFC 8555, section 6.7.
    /// </summary>
    public const String ErrorPrefix = "urn:ietf:params:acme:error:";

    private readonly IReadOnlyDictionary<String, IReadOnlyList<String>> headers;

    private JsonNode?  json;
    private Boolean    jsonRead;

    #endregion

    #region Properties

    /// <summary>The method of the request this answers.</summary>
    public String   Method       { get; }

    /// <summary>The URL of the request this answers.</summary>
    public String   URL          { get; }

    /// <summary>The HTTP status code.</summary>
    public Int32    Status       { get; }

    /// <summary>The body, as it came.</summary>
    public Byte[]   Body         { get; }

    /// <summary>The body as UTF-8 text.</summary>
    public String   Text
        => Encoding.UTF8.GetString(Body);

    /// <summary>The media type of the Content-Type, without its parameters; null where there is none.</summary>
    public String?  MediaType
        => Header("Content-Type")?.Split(';')[0].Trim().ToLowerInvariant();

    /// <summary>The Replay-Nonce, where the answer has one.</summary>
    public String?  ReplayNonce
        => Header("Replay-Nonce");

    /// <summary>The Location, where the answer has one.</summary>
    public String?  Location
        => Header("Location");

    /// <summary>The body as JSON - null where it is none.</summary>
    public JsonNode? JSON
    {
        get
        {

            if (!jsonRead)
            {
                jsonRead = true;
                try
                {
                    json = Body.Length > 0 ? JsonNode.Parse(Body) : null;
                }
                catch (System.Text.Json.JsonException)
                {
                    json = null;
                }
            }

            return json;

        }
    }

    /// <summary>The body as a JSON object - null where it is none.</summary>
    public JsonObject? Object
        => JSON as JsonObject;

    /// <summary>The "type" of a problem document, in full.</summary>
    public String? ProblemType
        => MediaType == "application/problem+json" || Object?["type"] is not null
               ? Object?["type"]?.GetValueKind() == System.Text.Json.JsonValueKind.String ? Object["type"]!.GetValue<String>() : null
               : null;

    /// <summary>The error type of RFC 8555, section 6.7, without its prefix - "badNonce", say - or null.</summary>
    public String? ErrorType
        => ProblemType is String type && type.StartsWith(ErrorPrefix, StringComparison.Ordinal)
               ? type[ErrorPrefix.Length..]
               : null;

    #endregion

    #region Constructor(s)

    public RawACMEResponse(String                                               Method,
                           String                                               URL,
                           Int32                                                Status,
                           IReadOnlyDictionary<String, IReadOnlyList<String>>  Headers,
                           Byte[]                                               Body)
    {

        this.Method   = Method;
        this.URL      = URL;
        this.Status   = Status;
        this.headers  = Headers;
        this.Body     = Body;

    }

    #endregion


    #region Header(Name) / Headers(Name)

    /// <summary>
    /// The value of a header field - all its lines joined by ", " as RFC 9110
    /// has it - or null.
    /// </summary>
    public String? Header(String Name)

        => headers.TryGetValue(Name, out var values) && values.Count > 0
               ? String.Join(", ", values)
               : null;

    /// <summary>
    /// Every line of a header field.
    /// </summary>
    public IReadOnlyList<String> Headers(String Name)

        => headers.TryGetValue(Name, out var values)
               ? values
               : [];

    #endregion

    #region Links

    /// <summary>
    /// The Link header fields (RFC 8288), as (URL, rel) - one per link, of
    /// every line.
    /// </summary>
    public IReadOnlyList<(String URL, String Rel)> Links
    {
        get
        {

            var links = new List<(String, String)>();

            foreach (var line in Headers("Link"))
                foreach (Match match in LinkPattern().Matches(line))
                    links.Add((match.Groups["url"].Value, match.Groups["rel"].Value));

            return links;

        }
    }

    /// <summary>
    /// The URLs of the links of the given relation.
    /// </summary>
    public IReadOnlyList<String> LinksOf(String Rel)

        => [.. Links.Where(link => link.Rel.Split(' ').Contains(Rel, StringComparer.OrdinalIgnoreCase)).Select(link => link.URL)];

    [GeneratedRegex("""<(?<url>[^>]*)>\s*(?:;[^,]*?\brel\s*=\s*"?(?<rel>[^";,]*)"?)""")]
    private static partial Regex LinkPattern();

    #endregion

    #region StringOf(Member) / StringsOf(Member)

    /// <summary>
    /// A member of the JSON object that is a string - or null.
    /// </summary>
    public String? StringOf(String Member)

        => Object?[Member] is JsonValue value && value.GetValueKind() == System.Text.Json.JsonValueKind.String
               ? value.GetValue<String>()
               : null;

    /// <summary>
    /// A member of the JSON object that is an array of strings - or empty.
    /// </summary>
    public IReadOnlyList<String> StringsOf(String Member)

        => Object?[Member] is JsonArray array
               ? [.. array.OfType<JsonValue>().Where(value => value.GetValueKind() == System.Text.Json.JsonValueKind.String).Select(value => value.GetValue<String>())]
               : [];

    #endregion


    #region ToString()

    /// <summary>
    /// The answer as a test message shows it: the request, the status, the
    /// fields that matter here, and the body - shortened.
    /// </summary>
    public override String ToString()
    {

        var text = Text;

        if (text.Length > 1200)
            text = text[..1200] + "...";

        return $"{Method} {URL} -> {Status} {Header("Content-Type")}" +
               (Location    is not null ? $", Location: {Location}"         : "") +
               (ReplayNonce is not null ? $", Replay-Nonce: {ReplayNonce}" : "") +
               (text.Length > 0 ? $"\n{text}" : "");

    }

    #endregion

}
