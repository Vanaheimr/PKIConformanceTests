using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

using NUnit.Framework;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests.Fuzzing;

/// <summary>
/// The requests of every resource of ACME, spoiled one change at a time by
/// a seeded mutator (<see cref="JSONMutator"/>): their payload, signed as it
/// is; their protected header, signed as it is; their serialization, not
/// signed again. The server under test is to refuse what it cannot take as
/// the client's error - a 4xx with a problem document (RFC 8555, section
/// 6.7) - never as its own, and is to take nothing whose signature does not
/// hold.
/// </summary>
/// <remarks>
/// <para>
/// RFC 8555, section 6.7, has "malformed" for <i>"The request message was
/// malformed"</i> and "serverInternal" for <i>"The server experienced an
/// internal error"</i>; RFC 9110, section 15.6, has 5xx for <i>"the server
/// is aware that it has erred"</i>. A 5xx for a request no client should
/// have made is a path where the client's error became the server's - as
/// S-3 was. And section 6.2: the server MUST verify the JWS; one whose
/// protected header, payload or signature was changed after it was signed
/// is not one of its account.
/// </para>
/// <para>
/// Every run makes the same requests: the seed is the target's and the
/// layer's (and PKICONFORMANCE_FUZZ_SEED, 1 by default), the number of
/// requests per case PKICONFORMANCE_FUZZ_ITERATIONS (200). A red one says
/// which request it was by its number and its change, and the change is
/// the reproduction.
/// </para>
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §6.2, §6.7")]
public class FuzzTests(String ServerName) : ACMEServerFixture(ServerName)
{

    #region Data

    /// <summary>The resources a request is spoiled for.</summary>
    public static readonly String[] Targets = [
        "newAccount", "account", "newOrder", "order", "authorization", "challenge", "finalize", "revokeCert", "keyChange"
    ];

    /// <summary>Where a request is spoiled.</summary>
    public static readonly String[] Layers = [ "payload", "header", "serialization" ];

    /// <summary>Every target in every layer.</summary>
    public static IEnumerable<TestCaseData> Cases
        => from target in Targets
           from layer  in Layers
           select new TestCaseData(target, layer).SetArgDisplayNames(target, layer);

    private static Int32 Iterations
        => Int32.TryParse(Environment.GetEnvironmentVariable("PKICONFORMANCE_FUZZ_ITERATIONS"), out var iterations) && iterations > 0 ? iterations : 200;

    private static Int32 RunSeed
        => Int32.TryParse(Environment.GetEnvironmentVariable("PKICONFORMANCE_FUZZ_SEED"), out var seed) ? seed : 1;

    /// <summary>A request of a target, valid as it is - what is spoiled.</summary>
    private sealed record Template(String   Target,
                                   RawKey   Key,
                                   String?  KeyId,
                                   String   URL,
                                   String?  Payload);

    /// <summary>A spoiled request that went wrong: its number, its change, and the answer.</summary>
    private sealed record Wrong(Int32 Number, String What, String Answer)
    {
        public override String ToString()
            => $"#{Number} {What}: {Answer}";
    }

    /// <summary>
    /// A spoiled request: its body, what was changed, whether the server must
    /// refuse it, and the text of the layer as it was and as it was sent.
    /// </summary>
    private sealed record Spoiled(Byte[]   Body,
                                  String   What,
                                  Boolean  MustRefuse,
                                  String   Original,
                                  String   Text);

    #endregion


    #region Spoiled requests

    /// <summary>
    /// The requests of the target, spoiled in the layer: refused as 4xx with
    /// a problem document of ACME, never a 5xx, never without an answer; and
    /// in the header and the serialization, none taken whose signed content
    /// changed.
    /// </summary>
    [TestCaseSource(nameof(Cases))]
    [Property("Level", "SHOULD")]
    public async Task Spoiled_Requests_Are_The_Client_s_Error(String Target, String Layer)
    {

        var random       = new Random(Seed(Target, Layer));
        var mutator      = new JSONMutator(random);
        var template     = await FreshAsync(Target);

        var serverErrors = new List<Wrong>();
        var unanswered   = new List<Wrong>();
        var undocumented = new List<Wrong>();
        var taken        = new List<Wrong>();
        var known        = new SortedDictionary<String, Int32>();

        for (var number = 0; number < Iterations; number++)
        {

            if (Target == "newAccount")
                template = template with { Key = RawKey.Generate("ES256") };

            var spoiled = await SpoilAsync(template, Layer, mutator, random);
            var what    = spoiled.What;

            RawACMEResponse answer;

            try
            {
                answer = await Client.SendAsync(HttpMethod.Post, template.URL, spoiled.Body);
            }
            catch (HttpRequestException e)
            {
                unanswered.Add(new Wrong(number, what, $"no answer: {e.Message}"));
                Client.ForgetNonces();
                continue;
            }

            if (answer.Status >= 500)
            {
                if (Known(Target, Layer, ServerError, spoiled) is String finding)
                    known[finding] = known.GetValueOrDefault(finding) + 1;
                else
                    serverErrors.Add(new Wrong(number, what, Excerpt(answer)));
            }

            else if (answer.Status >= 400 && (answer.MediaType != "application/problem+json" || answer.ErrorType is null))
                undocumented.Add(new Wrong(number, what, Excerpt(answer)));

            else if (answer.Status is >= 200 and < 300)
            {

                if (spoiled.MustRefuse)
                {
                    if (Known(Target, Layer, Taken, spoiled) is String finding)
                        known[finding] = known.GetValueOrDefault(finding) + 1;
                    else
                        taken.Add(new Wrong(number, what, Excerpt(answer)));
                }

                // What a request was for is used up when it is taken: the
                // next one gets a template of its own.
                template = await FreshAsync(Target);

            }

        }

        TestContext.Out.WriteLine($"{Iterations} spoiled requests of {Target}, in the {Layer}, seed {Seed(Target, Layer)}");

        foreach (var (finding, count) in known)
            TestContext.Out.WriteLine($"  {count} of them went wrong as {finding} has it - known, and red in its own tests");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(serverErrors, Is.Empty, Report("answered with a 5xx - the client's error as the server's own", serverErrors));
            Assert.That(unanswered,   Is.Empty, Report("not answered at all",                                         unanswered));
            Assert.That(undocumented, Is.Empty, Report("refused without a problem document of ACME (section 6.7)",    undocumented));
            Assert.That(taken,        Is.Empty, Report("taken, though what was signed changed after it was (section 6.2)", taken));
        }

    }

    /// <summary>
    /// The identifier of a certificate in a renewalInfo URL (RFC 9773,
    /// section 4.1), spoiled: unknown, 404 or 400, never a 5xx.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.1")]
    [Property("Level", "SHOULD")]
    public async Task Spoiled_Identifiers_Of_renewalInfo_Are_The_Client_s_Error()
    {

        var random       = new Random(Seed("renewalInfo", "path"));
        var mutator      = new JSONMutator(random);
        var account      = await NewAccountAsync();
        var issued       = await Client.IssueAsync(account, Host, Loopback4);
        var id           = RawARI.CertificateId(issued.LeafDER)!;
        var url          = Client.Resource("renewalInfo");

        var serverErrors = new List<Wrong>();
        var undocumented = new List<Wrong>();

        for (var number = 0; number < Iterations; number++)
        {

            var (text, what) = random.Next(4) == 0
                                   ? (Uri.EscapeDataString(new[] { "..", "%00", "/", "?", "#", "..%2F..", new String('A', 65536), "." }[random.Next(8)]), "an odd identifier")
                                   : mutator.MutateText(id);

            RawACMEResponse answer;

            try
            {
                answer = await Client.SendAsync(HttpMethod.Get, $"{url}/{Uri.EscapeDataString(text)}", ContentType: null);
            }
            catch (HttpRequestException e)
            {
                // A request line of 64 KiB: Hermod's HTTP server answers 431
                // and closes, which the client may see before the answer.
                if (ReachesTheResource(text))
                    serverErrors.Add(new Wrong(number, $"{what}: {Shorten(text)}", $"no answer: {e.Message}"));
                continue;
            }

            if (answer.Status >= 500)
                serverErrors.Add(new Wrong(number, $"{what}: {Shorten(text)}", Excerpt(answer)));

            // Only an identifier of the alphabet of base64url and its dot, of
            // a length a request line has, is sure to reach the resource;
            // others - ".", "..", a control character, percent-encoded octets,
            // 64 KiB - Hermod's HTTP server may refuse before ACME sees them.
            else if (answer.Status >= 400 && answer.MediaType != "application/problem+json" && ReachesTheResource(text))
                undocumented.Add(new Wrong(number, $"{what}: {Shorten(text)}", Excerpt(answer)));

        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(serverErrors, Is.Empty, Report("answered with a 5xx", serverErrors));
            Assert.That(undocumented, Is.Empty, Report("refused without a problem document", undocumented));
        }

    }

    #endregion


    private static Boolean ReachesTheResource(String Identifier)
        => Identifier.Trim('.').Length > 0 &&
           Identifier.Length <= 4096 &&
           Identifier.All(character => character is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_' or '.');

    #region (private) Known(Target, Layer, Kind, Spoiled)

    private const String ServerError = "5xx";
    private const String Taken       = "taken";

    /// <summary>
    /// The finding a wrong answer is, where it is a known one: the request is
    /// of the kind the finding's own tests make, and those are red for it.
    /// The fuzzer stays green of it, and red of every other path.
    /// </summary>
    private static String? Known(String   Target,
                                 String   Layer,
                                 String   Kind,
                                 Spoiled  Spoiled)
    {

        var what = Spoiled.What;

        if (Kind == ServerError)
        {

            // S-15: "alg", or a member of "jwk", that is no string.
            if (Layer == "header" && Regex.IsMatch(what, @"^header: \$\.(alg|jwk\.(kty|crv|x|y|n|e)) (replaced by (?!""|a lone surrogate|64 KiB)|wrapped in)"))
                return "S-15";

            // S-18: a "reason" of revokeCert beyond 32 bits.
            if (Target == "revokeCert" && Layer == "payload" && LastWins(Spoiled.Text) is { } payload &&
                payload.TryGetValue("reason", out var reason) && reason.ValueKind == JsonValueKind.Number && !reason.TryGetInt32(out _))
                return "S-18";

            // S-3: on Windows, a "jwk" whose point is no point of P-256 - its
            // coordinate spoiled in the header, or in the base64url of the
            // header (the request's, or the inner JWS's of a key change).
            if (OperatingSystem.IsWindows() &&
                ((Layer == "header" && Regex.IsMatch(what, @"^header: \$\.jwk\.(x|y) ")) ||
                 (Layer == "serialization" && OnlyThePointDiffers(HeaderOf(Spoiled.Original), HeaderOf(Spoiled.Text))) ||
                 (Layer == "payload" && Target == "keyChange" && OnlyThePointDiffers(HeaderOf(Spoiled.Original), HeaderOf(Spoiled.Text)))))
                return "S-3";

            // S-19: a CSR of a key on a curve nobody knows - and, on Windows,
            // of a point off its curve.
            if (Target == "finalize" && Layer == "payload" && what.StartsWith("payload: $.csr ", StringComparison.Ordinal))
                return "S-19";

            return null;

        }

        var original = LastWins(Spoiled.Original);
        var spoiled  = LastWins(Spoiled.Text);

        // S-17: a text that is no JSON, taken.
        if (spoiled is null)
            return "S-17";

        if (original is null)
            return null;

        if (Layer == "header")
        {

            // S-16: a "kid" and a "jwk" both, whatever the one of them is.
            if (spoiled.ContainsKey("kid") && spoiled.ContainsKey("jwk"))
                return "S-16";

            // S-14 and S-1: a coordinate of the "jwk" with whitespace, or padded.
            if (original.TryGetValue("jwk", out var jwk) && spoiled.TryGetValue("jwk", out var spoiledJWK) && spoiledJWK.ValueKind == JsonValueKind.Object)
                foreach (var name in new[] { "x", "y", "n", "e" })
                {
                    var a = jwk.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
                    var b = spoiledJWK.TryGetProperty(name, out var other) && other.ValueKind == JsonValueKind.String ? other.GetString() : null;
                    if (a is null || b is null || a == b)
                        continue;
                    if (WithoutWhitespace(b) == a)
                        return "S-14";
                    if (b.TrimEnd('=') == a)
                        return "S-1";
                }

        }

        // S-14: the signature with whitespace in it, the signed parts unchanged.
        if (Layer == "serialization" &&
            Text(original, "protected") == Text(spoiled, "protected") &&
            Text(original, "payload")   == Text(spoiled, "payload")   &&
            Text(spoiled,  "signature") is String signature && WithoutWhitespace(signature) == Text(original, "signature"))
            return "S-14";

        return null;

    }

    private static String WithoutWhitespace(String Text)
        => String.Concat(Text.Where(character => !Char.IsWhiteSpace(character)));

    /// <summary>The protected header of a flattened JWS, decoded - or null.</summary>
    private static Dictionary<String, JsonElement>? HeaderOf(String JWS)
        => LastWins(JWS) is { } members &&
           Text(members, "protected") is String encoded &&
           Decoded(encoded) is Byte[] octets
               ? LastWins(Encoding.UTF8.GetString(octets))
               : null;

    /// <summary>Whether the two headers differ in a coordinate of the point of their "jwk" alone.</summary>
    private static Boolean OnlyThePointDiffers(Dictionary<String, JsonElement>? Original,
                                               Dictionary<String, JsonElement>? Spoiled)
    {

        if (Original is null || Spoiled is null || !Original.TryGetValue("jwk", out var a) || !Spoiled.TryGetValue("jwk", out var b) || b.ValueKind != JsonValueKind.Object)
            return false;

        foreach (var name in new[] { "alg", "nonce", "url", "kid" })
            if (Text(Original, name) != Text(Spoiled, name))
                return false;

        var original = LastWins(a.GetRawText())!;
        var spoiled  = LastWins(b.GetRawText());

        return spoiled is not null &&
               Text(original, "kty") == Text(spoiled, "kty") &&
               Text(original, "crv") == Text(spoiled, "crv") &&
               (Text(original, "x") != Text(spoiled, "x") || Text(original, "y") != Text(spoiled, "y"));

    }

    #endregion

    #region (private) SpoilAsync(Template, Layer, Mutator, Random)

    /// <summary>
    /// A request of the template, spoiled in the layer.
    /// </summary>
    private async Task<Spoiled> SpoilAsync(Template     Template,
                                           String       Layer,
                                           JSONMutator  Mutator,
                                           Random       Random)
    {

        var header  = await HeaderAsync(Template);
        var payload = Template.Payload ?? "";

        switch (Layer)
        {

            case "payload":
            {
                if (Random.NextDouble() < 0.15)
                {
                    var (octets, what) = Mutator.Bytes(payload.Length > 0 ? payload : "{}");
                    return new Spoiled(Body(Template.Key, Encoding.UTF8.GetBytes(header), octets), $"payload: {what}", false, payload, "");
                }
                var (text, how) = Mutator.Mutate(payload);
                return new Spoiled(Body(Template.Key, Encoding.UTF8.GetBytes(header), Encoding.UTF8.GetBytes(text)), $"payload: {how}", false, payload, text);
            }

            case "header":
            {
                var (text, what) = Mutator.Mutate(header);
                return new Spoiled(Body(Template.Key, Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(payload)), $"header: {what}", !SameHeader(header, text), header, text);
            }

            default:
            {
                var valid        = Body(Template.Key, Encoding.UTF8.GetBytes(header), Encoding.UTF8.GetBytes(payload));
                var flattened    = Encoding.UTF8.GetString(valid);
                var (text, what) = Mutator.Mutate(flattened);
                return new Spoiled(Encoding.UTF8.GetBytes(text), $"serialization: {what}", !SameJWS(flattened, text), flattened, text);
            }

        }

    }

    /// <summary>The protected header of a request of the template, with a nonce of the server.</summary>
    private async Task<String> HeaderAsync(Template Template)
    {

        var header = new JsonObject { ["alg"] = Template.Key.Algorithm };

        if (Template.KeyId is null)
            header["jwk"] = JsonNode.Parse(Template.Key.JWK.ToJSON());
        else
            header["kid"] = Template.KeyId;

        header["nonce"] = await Client.NonceAsync();
        header["url"]   = Template.URL;

        return header.ToJsonString();

    }

    /// <summary>A JWS of the octets, signed by the key, flattened - as the body of a request.</summary>
    private static Byte[] Body(RawKey  Key,
                               Byte[]  Protected,
                               Byte[]  Payload)
    {

        var @protected = RawBase64Url.Encode(Protected);
        var payload    = RawBase64Url.Encode(Payload);
        var signature  = RawBase64Url.Encode(Key.Sign(Encoding.ASCII.GetBytes($"{@protected}.{payload}")));

        return Encoding.UTF8.GetBytes(new RawJWS(@protected, payload, signature).ToFlattenedJSON());

    }

    #endregion

    #region (private) SameHeader(Original, Spoiled) / SameJWS(Original, Spoiled)

    /// <summary>
    /// Whether the spoiled header says what the original says: "alg", "kid",
    /// "nonce", "url" and the public members of "jwk" alike - read as a parser
    /// may (RFC 8259, section 8.1: a byte order mark ignored; RFC 7515,
    /// section 4: the last of a name twice). What is added besides is
    /// another header parameter, which RFC 7515, section 4, has ignored.
    /// </summary>
    private static Boolean SameHeader(String Original, String Spoiled)
    {

        var original = LastWins(Original);
        var spoiled  = LastWins(Spoiled);

        if (original is null || spoiled is null)
            return false;

        foreach (var name in new[] { "alg", "kid", "nonce", "url" })
            if (Text(original, name) != Text(spoiled, name))
                return false;

        if (original.ContainsKey("jwk") != spoiled.ContainsKey("jwk"))
            return false;

        if (original.TryGetValue("jwk", out var jwk))
        {
            var spoiledJWK = spoiled["jwk"].ValueKind == JsonValueKind.Object ? LastWins(spoiled["jwk"].GetRawText()) : null;
            var originalJWK = LastWins(jwk.GetRawText())!;
            if (spoiledJWK is null)
                return false;
            foreach (var name in new[] { "kty", "crv", "x", "y", "n", "e" })
                if (Text(originalJWK, name) != Text(spoiledJWK, name))
                    return false;
        }

        return true;

    }

    /// <summary>
    /// Whether the spoiled serialization has the protected header, the
    /// payload and the signature of the original - decoded alike, padding and
    /// unused bits of base64url aside (those are S-1's, and RFC 4648, section
    /// 3.5, lets a decoder take them).
    /// </summary>
    private static Boolean SameJWS(String Original, String Spoiled)
    {

        var original = LastWins(Original);
        var spoiled  = LastWins(Spoiled);

        if (original is null || spoiled is null)
            return false;

        foreach (var name in new[] { "protected", "payload", "signature" })
        {
            var a = Text(original, name);
            var b = Text(spoiled, name);
            if (b is null || !Decoded(a!).AsSpan().SequenceEqual(Decoded(b) ?? [ 0xFF, 0xFF ]))
                return false;
        }

        return true;

    }

    /// <summary>The members of a JSON object, the last of a name twice winning - or null where it is none.</summary>
    private static Dictionary<String, JsonElement>? LastWins(String JSON)
    {
        try
        {
            using var document = JsonDocument.Parse(JSON.TrimStart('﻿'));
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return null;
            var members = new Dictionary<String, JsonElement>();
            foreach (var member in document.RootElement.EnumerateObject())
                members[member.Name] = member.Value.Clone();
            return members;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            // Not JSON - or a name of a lone surrogate, which no parser reads alike.
            return null;
        }
    }

    /// <summary>A member as text: a string as it decodes - a lone surrogate as it is written - anything else as its JSON, marked.</summary>
    private static String? Text(Dictionary<String, JsonElement> Members, String Name)
    {

        if (!Members.TryGetValue(Name, out var value))
            return null;

        if (value.ValueKind != JsonValueKind.String)
            return "\u0001" + value.GetRawText();

        try
        {
            return value.GetString();
        }
        catch (InvalidOperationException)
        {
            return "\u0002" + value.GetRawText();
        }

    }

    private static Byte[]? Decoded(String Base64Url)
    {
        var text = Base64Url.TrimEnd('=').Replace('-', '+').Replace('_', '/');
        text    += new String('=', (4 - text.Length % 4) % 4);
        var buffer = new Byte[text.Length];
        return Convert.TryFromBase64String(text, buffer, out var written) ? buffer[..written] : null;
    }

    #endregion

    #region (private) FreshAsync(Target)

    /// <summary>
    /// A request of the target, valid as it stands now: an account of its
    /// own for the ones of an account, the order, authorization, challenge
    /// or certificate it is about.
    /// </summary>
    private async Task<Template> FreshAsync(String Target)
    {

        if (Target == "newAccount")
            return new Template(Target, RawKey.Generate("ES256"), null, Client.Resource("newAccount"),
                                """{"termsOfServiceAgreed":true,"contact":["mailto:fuzz@acme.test"]}""");

        var account = await NewAccountAsync();

        switch (Target)
        {

            case "account":
                return new Template(Target, account.Key, account.URL, account.URL, """{"contact":["mailto:fuzz@acme.test"]}""");

            case "newOrder":
                return new Template(Target, account.Key, account.URL, Client.Resource("newOrder"),
                                    RawJson.Object(("identifiers", RawACMEClient.IdentifiersJSON([ Loopback4 ]))));

            case "order":
            {
                var order = await Client.OrderAsync(account, Loopback4);
                return new Template(Target, account.Key, account.URL, order.URL, null);
            }

            case "authorization":
            {
                var order = await Client.OrderAsync(account, Loopback4);
                return new Template(Target, account.Key, account.URL, order.Authorizations[0], """{"status":"deactivated"}""");
            }

            case "challenge":
            {
                var order         = await Client.OrderAsync(account, Loopback4);
                var authorization = await Client.PostAsGetAsync(account, order.Authorizations[0]);
                var challenge     = RawACMEClient.ChallengeOf(authorization, "http-01")
                                        ?? throw new InvalidOperationException($"No http-01: {authorization}");
                return new Template(Target, account.Key, account.URL, challenge.URL, "{}");
            }

            case "finalize":
            {
                var order = await Client.ReadyOrderAsync(account, Host, Loopback4);
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                return new Template(Target, account.Key, account.URL, order.Finalize,
                                    RawJson.Object(("csr", RawJson.Quote(RawCSR.CreateBase64Url(key, [ Loopback4 ])))));
            }

            case "revokeCert":
            {
                var issued = await Client.IssueAsync(account, Host, Loopback4);
                return new Template(Target, account.Key, account.URL, Client.Resource("revokeCert"),
                                    RawJson.Object(("certificate", RawJson.Quote(RawBase64Url.Encode(issued.LeafDER))), ("reason", "1")));
            }

            case "keyChange":
            {
                var url   = Client.Resource("keyChange");
                var next  = RawKey.Generate("ES256");
                var inner = RawJWS.ACME(next, url, null, null,
                                        RawJson.Object(("account", RawJson.Quote(account.URL)), ("oldKey", account.Key.JWK.ToJSON())));
                return new Template(Target, account.Key, account.URL, url, inner.ToFlattenedJSON());
            }

            default:
                throw new ArgumentException($"No target '{Target}'.");

        }

    }

    #endregion

    #region (private) Seed / Report / Excerpt

    /// <summary>The seed of a case: FNV-1a of its name - the same in every run, unlike String.GetHashCode.</summary>
    private static Int32 Seed(String Target, String Layer)
    {
        var hash = 2166136261u;
        foreach (var octet in Encoding.UTF8.GetBytes($"{Target}/{Layer}/{RunSeed}"))
            hash = (hash ^ octet) * 16777619u;
        return (Int32) (hash & 0x7FFFFFFF);
    }

    private static String Report(String How, List<Wrong> Wrongs)
        => Wrongs.Count == 0
               ? ""
               : $"{Wrongs.Count} spoiled requests {How}:\n" + String.Join("\n", Wrongs.Take(12)) + (Wrongs.Count > 12 ? $"\n... and {Wrongs.Count - 12} more" : "");

    private static String Excerpt(RawACMEResponse Answer)
        => $"{Answer.Status} {Answer.MediaType} {Shorten(Answer.Text, 240)}";

    private static String Shorten(String Text, Int32 Length = 80)
        => Text.Length <= Length ? Text : Text[..Length] + "...";

    #endregion

}
