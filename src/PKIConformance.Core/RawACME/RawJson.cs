using System.Text.Encodings.Web;
using System.Text.Json;

namespace PKIConformance.Core.RawACME;

/// <summary>
/// The little JSON the raw codec writes by hand: strings quoted as RFC 8259
/// has them, and nothing escaped that need not be - a URL with a "+" in it
/// stays readable. Hermod and the PKI read and write JSON with Newtonsoft;
/// the reference uses System.Text.Json, so that it does not share their
/// mistakes.
/// </summary>
public static class RawJson
{

    private static readonly JsonSerializerOptions Relaxed = new () {
                                                                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                                                            };

    /// <summary>
    /// The text as a JSON string, quotes included.
    /// </summary>
    public static String Quote(String Text)
        => JsonSerializer.Serialize(Text, Relaxed);

    /// <summary>
    /// A JSON object of the given members, in the given order, without any
    /// whitespace - the values already JSON (a quoted string, an object...).
    /// </summary>
    public static String Object(params (String Name, String JSONValue)[] Members)
        => "{" + String.Join(",", Members.Select(member => $"{Quote(member.Name)}:{member.JSONValue}")) + "}";

}
