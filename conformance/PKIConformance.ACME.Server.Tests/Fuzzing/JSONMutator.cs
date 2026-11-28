using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PKIConformance.ACME.Server.Tests.Fuzzing;

/// <summary>
/// Spoils JSON, one change at a time and seeded, so that every spoiled
/// request can be made again: a node of the document replaced by a value of
/// another kind or by one that parsers choke on, changed in place, taken
/// away, wrapped, or given company - or the text itself cut, padded or
/// broken.
/// </summary>
/// <remarks>
/// What it makes is meant to be refused. A server under test that answers
/// any of it with a 5xx, or with no problem document, has a path where the
/// client's error becomes its own (<see cref="FuzzTests"/>).
/// </remarks>
public sealed class JSONMutator(Random Random)
{

    #region Data

    /// <summary>A text that stands for a token of JSON no JsonNode can hold, put in after serialization.</summary>
    private const String RawMark = "__pkiconformance_raw_";

    private readonly List<String> raws = [];

    /// <summary>Values of every kind, and the ones parsers choke on.</summary>
    private static readonly (String What, Func<Random, Object?> Value)[] Values = [
        ("null",                   _ => null),
        ("true",                   _ => true),
        ("false",                  _ => false),
        ("0",                      _ => 0),
        ("-1",                     _ => -1),
        ("1.5",                    _ => 1.5),
        ("2^63",                   _ => new Raw("9223372036854775808")),
        ("1e400",                  _ => new Raw("1e400")),
        ("-0",                     _ => new Raw("-0")),
        ("\"\"",                   _ => ""),
        ("\" \"",                  _ => " "),
        ("\"\\u0000\"",            _ => "\u0000"),
        ("a lone surrogate",       _ => new Raw("\"\\ud800\"")),
        ("\"☃\"",                  _ => "☃"),
        ("64 KiB of \"A\"",        _ => new String('A', 65536)),
        ("\"!!!\"",                _ => "!!!"),
        ("[]",                     _ => new JsonArray()),
        ("{}",                     _ => new JsonObject()),
        ("[null]",                 _ => new JsonArray((JsonNode?) null)),
        ("{\"\":null}",            _ => new JsonObject { [""] = null }),
        ("arrays 100 deep",        _ => new Raw(new String('[', 100) + new String(']', 100))),
        ("arrays 5000 deep",       _ => new Raw(new String('[', 5000) + new String(']', 5000))),
        ("objects 100 deep",       _ => new Raw(String.Concat(Enumerable.Repeat("{\"a\":", 100)) + "1" + new String('}', 100))),
        ("an array of 10000",      _ => new Raw("[" + String.Join(",", Enumerable.Repeat("0", 10000)) + "]")),
    ];

    /// <summary>Names a member added may have: the ones of ACME and JOSE, and odd ones.</summary>
    private static readonly String[] Names = [
        "", "x", "__proto__", "status", "identifiers", "contact", "csr", "certificate", "reason", "account", "oldKey",
        "jwk", "kid", "nonce", "url", "alg", "crit", "b64", "kty", "crv", "d", "externalAccountBinding", "onlyReturnExisting",
        "termsOfServiceAgreed", "replaces", "profile", "notBefore", "notAfter", "protected", "payload", "signature", "header", "signatures"
    ];

    #endregion


    #region Mutate(JSON)

    /// <summary>
    /// One change to the JSON text, and what it was.
    /// </summary>
    public (String Text, String What) Mutate(String JSON)
    {

        raws.Clear();

        JsonNode? root;

        try
        {
            root = JsonNode.Parse(JSON);
        }
        catch (JsonException)
        {
            return MutateText(JSON);
        }

        if (root is null || Random.NextDouble() < 0.25)
            return MutateText(JSON);

        var nodes                 = Walk(root).ToList();
        var (node, path)          = nodes[Random.Next(nodes.Count)];
        var dice                  = Random.NextDouble();
        String what;

        if      (dice < 0.40)
        {
            var (name, value) = Values[Random.Next(Values.Length)];
            root = Replace(root, node, ToNode(value(Random)));
            what = $"{path} replaced by {name}";
        }
        else if (dice < 0.60 && node is JsonValue scalar)
        {
            var (changed, how) = ChangeInPlace(scalar);
            root = Replace(root, node, changed);
            what = $"{path} {how}";
        }
        else if (dice < 0.72 && node.Parent is not null)
        {
            Remove(node);
            what = $"{path} taken away";
        }
        else if (dice < 0.84 && node is JsonObject or JsonArray)
        {
            var (name, value) = Values[Random.Next(Values.Length)];
            if (node is JsonObject @object)
            {
                var member = Names[Random.Next(Names.Length)];
                if (@object.ContainsKey(member))
                    member += "\u00a0";
                @object[member] = ToNode(value(Random));
                what = $"{path} given \"{member}\": {name}";
            }
            else
            {
                ((JsonArray) node).Add(ToNode(value(Random)));
                what = $"{path} given an item {name}";
            }
        }
        else if (dice < 0.92)
        {
            root = Replace(root, node, new JsonArray(node.DeepClone()));
            what = $"{path} wrapped in an array";
        }
        else
        {
            root = Replace(root, node, new JsonObject { ["value"] = node.DeepClone() });
            what = $"{path} wrapped in an object";
        }

        return (WithRaws(root?.ToJsonString() ?? "null"), what);

    }

    #endregion

    #region MutateText(JSON)

    /// <summary>
    /// One change to the text itself.
    /// </summary>
    public (String Text, String What) MutateText(String JSON)
    {

        var at = JSON.Length == 0 ? 0 : Random.Next(JSON.Length);

        switch (Random.Next(9))
        {

            case 0:
                return (JSON[..at], $"text cut at {at}");

            case 1:
                const String characters = "{}[]\",:\\ \u0000x";
                var inserted = characters[Random.Next(characters.Length)];
                return (JSON.Insert(at, inserted.ToString()), $"text given '{Escape(inserted.ToString())}' at {at}");

            case 2:
                return JSON.Length == 0
                           ? ("{", "text \"{\"")
                           : (JSON.Remove(at, 1), $"text without its character at {at}");

            case 3:
                return ("\uFEFF" + JSON, "text after a byte order mark");

            case 4:
                return (JSON + " x", "text with garbage after it");

            case 5:
                return (JSON + JSON, "text twice");

            case 6:
                var first = JSON.IndexOf('{');
                var name  = Names[Random.Next(Names.Length)];
                return first < 0
                           ? (JSON + "}", "text with a \"}\" after it")
                           : (JSON.Insert(first + 1, $"\"{name}\":{{}},"), $"text given \"{name}\": {{}} first - a member twice, where it has one");

            case 7:
                var whole = new[] { "", "null", "[]", "\"\"", "1", "{", "{}", "[{}]" }[Random.Next(8)];
                return (whole, $"text \"{whole}\" instead");

            default:
                return (JSON.ToUpperInvariant(), "text in upper case");

        }

    }

    #endregion

    #region Bytes(JSON)

    /// <summary>
    /// The octets of a text, spoiled where no text could be: not UTF-8.
    /// </summary>
    public (Byte[] Octets, String What) Bytes(String JSON)
    {

        switch (Random.Next(4))
        {

            case 0:
                return ([ .. Encoding.UTF8.GetBytes(JSON), 0xC3, 0x28 ], "octets ending in C3 28, no UTF-8");

            case 1:
                return ([ 0xED, 0xA0, 0x80, .. Encoding.UTF8.GetBytes(JSON) ], "octets of a surrogate in UTF-8 (ED A0 80) first");

            case 2:
                return (Encoding.Unicode.GetBytes(JSON), "octets of UTF-16");

            default:
                var octets = new Byte[1 + Random.Next(64)];
                Random.NextBytes(octets);
                return (octets, $"{octets.Length} random octets");

        }

    }

    #endregion


    #region (private) Helpers

    private sealed record Raw(String Text);

    private JsonNode? ToNode(Object? Value)
    {
        switch (Value)
        {
            case null:            return null;
            case JsonNode node:   return node;
            case Raw raw:
                raws.Add(raw.Text);
                return JsonValue.Create($"{RawMark}{raws.Count - 1}__");
            case String text:     return JsonValue.Create(text);
            case Boolean boolean: return JsonValue.Create(boolean);
            case Int32 number:    return JsonValue.Create(number);
            case Double number:   return JsonValue.Create(number);
            default:              throw new ArgumentException($"no JSON: {Value}");
        }
    }

    private String WithRaws(String Text)
    {
        for (var i = 0; i < raws.Count; i++)
            Text = Text.Replace($"\"{RawMark}{i}__\"", raws[i]);
        return Text;
    }

    private (JsonNode? Node, String How) ChangeInPlace(JsonValue Value)
    {

        if (Value.TryGetValue<String>(out var text))
        {
            var at = text.Length == 0 ? 0 : Random.Next(text.Length);
            return Random.Next(7) switch {
                0 when text.Length > 0  => (JsonValue.Create(text[..at] + (Char) (text[at] ^ 0x01) + text[(at + 1)..]), $"with its character at {at} changed"),
                1 when text.Length > 0  => (JsonValue.Create(text[..^1]),        "without its last character"),
                2                       => (JsonValue.Create(text + "="),        "with \"=\" after it"),
                3                       => (JsonValue.Create(" " + text),        "with a space before it"),
                4                       => (JsonValue.Create(text.ToUpperInvariant()), "in upper case"),
                5                       => (JsonValue.Create(text + text),       "twice"),
                _                       => (JsonValue.Create("\uFEFF" + text),   "after a byte order mark")
            };
        }

        if (Value.TryGetValue<Double>(out var number))
            return Random.Next(3) switch {
                0 => (JsonValue.Create(-number),        "negated"),
                1 => (JsonValue.Create(number + 0.5),   "plus 0.5"),
                _ => (JsonValue.Create(number.ToString(System.Globalization.CultureInfo.InvariantCulture)), "as a string")
            };

        if (Value.TryGetValue<Boolean>(out var boolean))
            return (JsonValue.Create(boolean ? "true" : "false"), "as a string");

        return (null, "as null");

    }

    private static IEnumerable<(JsonNode Node, String Path)> Walk(JsonNode Node)
    {

        yield return (Node, Node.GetPath());

        if (Node is JsonObject @object)
            foreach (var (_, child) in @object)
                if (child is not null)
                    foreach (var inner in Walk(child))
                        yield return inner;

        if (Node is JsonArray array)
            foreach (var child in array)
                if (child is not null)
                    foreach (var inner in Walk(child))
                        yield return inner;

    }

    /// <summary>The node replaced in its parent; the new root, where it was the root.</summary>
    private static JsonNode? Replace(JsonNode Root, JsonNode Node, JsonNode? With)
    {

        switch (Node.Parent)
        {

            case null:
                return With;

            case JsonObject parent:
                var name = parent.First(member => ReferenceEquals(member.Value, Node)).Key;
                parent[name] = With;
                return Root;

            case JsonArray parent:
                parent[parent.IndexOf(Node)] = With;
                return Root;

            default:
                return Root;

        }

    }

    private static void Remove(JsonNode Node)
    {
        switch (Node.Parent)
        {
            case JsonObject parent: parent.Remove(parent.First(member => ReferenceEquals(member.Value, Node)).Key); break;
            case JsonArray  parent: parent.Remove(Node); break;
        }
    }

    private static String Escape(String Text)
        => Text.Replace("\u0000", "\\0");

    #endregion

}
