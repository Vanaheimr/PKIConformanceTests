using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

using PKIConformance.Core.RawACME;

namespace PKIConformance.Core.Peers;

/// <summary>
/// The judge of what a client sent a real ACME server, request by request,
/// by RawACME - what ScriptedACMEServer checks of every request (phase 3),
/// read off a recording instead, where the server is not the suite's.
/// </summary>
/// <remarks>
/// <list type="bullet">
///   <item>A POST is "application/jose+json", a JWS of the flattened JSON serialization - "protected", "payload", "signature" and no more (RFC 8555, section 6.2).</item>
///   <item>Its protected header has "alg", "nonce", "url", and exactly one of "jwk" and "kid" (section 6.2); the signature holds by the "jwk", or by the one of the account the "kid" names.</item>
///   <item>Its "url" is the URL it is sent to (section 6.4).</item>
///   <item>Its nonce was handed out by the server, and is used once (section 6.5).</item>
///   <item>A request retried after "badNonce" carries the nonce of that answer (section 6.5).</item>
///   <item>A GET or HEAD is for the directory, a nonce, or a renewal window (sections 6.3 and 7.2, RFC 9773, section 4.3) - everything else is a POST-as-GET.</item>
///   <item>A certificate is asked for as "application/pem-certificate-chain" (section 7.4.2).</item>
/// </list>
/// </remarks>
public static class WireForm
{

    /// <summary>
    /// What is wrong with the recorded exchanges - nothing, where the client
    /// spoke RFC 8555.
    /// </summary>
    public static IReadOnlyList<String> Judge(IReadOnlyList<HTTPExchange> Exchanges)
    {

        var wrong            = new List<String>();
        var handedOut        = new HashSet<String>(StringComparer.Ordinal);
        var used             = new Dictionary<String, Int32>(StringComparer.Ordinal);
        var accounts         = new Dictionary<String, RawJWK>(StringComparer.Ordinal);
        var certificates     = new HashSet<String>(StringComparer.Ordinal);
        var directory        = (String?) null;
        var newNonce         = (String?) null;
        var renewalInfo      = (String?) null;
        var lastPost         = (HTTPExchange?) null;

        foreach (var exchange in Exchanges.OrderBy(exchange => exchange.Number))
        {

            var where = $"#{exchange.Number} {exchange.Method} {exchange.URL}";

            if (exchange.Method == "POST")
            {

                if (exchange.ContentType != "application/jose+json")
                    wrong.Add($"{where}: Content-Type '{exchange.ContentType}', not application/jose+json (RFC 8555, section 6.2)");

                JsonObject? body = null;

                try
                {
                    body = JsonNode.Parse(exchange.RequestBody) as JsonObject;
                }
                catch (JsonException) { }

                if (body is null)
                {
                    wrong.Add($"{where}: the body is no JSON object");
                    lastPost = exchange;
                    continue;
                }

                var members = body.Select(member => member.Key).Order(StringComparer.Ordinal).ToArray();

                if (!members.SequenceEqual([ "payload", "protected", "signature" ]))
                    wrong.Add($"{where}: the JWS has {System.String.Join(", ", members)}, not exactly protected, payload and signature (RFC 8555, section 6.2)");

                RawJWS      jws;
                JsonObject  header;

                try
                {
                    jws    = RawJWS.ParseFlattened(exchange.RequestBody);
                    header = JsonNode.Parse(jws.ProtectedJSON) as JsonObject ?? throw new FormatException("not an object");
                }
                catch (Exception e) when (e is FormatException or JsonException)
                {
                    wrong.Add($"{where}: no JWS of the flattened JSON serialization: {e.Message}");
                    lastPost = exchange;
                    continue;
                }

                var alg    = Member(header, "alg");
                var nonce  = Member(header, "nonce");
                var url    = Member(header, "url");
                var kid    = Member(header, "kid");
                var jwk    = header["jwk"] as JsonObject;

                if (alg is null)
                    wrong.Add($"{where}: no \"alg\" (RFC 8555, section 6.2)");

                if (url != exchange.URL.OriginalString)
                    wrong.Add($"{where}: \"url\" is '{url}', not the URL the request went to (RFC 8555, section 6.4)");

                if (nonce is null)
                    wrong.Add($"{where}: no \"nonce\" (RFC 8555, section 6.5)");

                else
                {

                    if (used.TryGetValue(nonce, out var before))
                        wrong.Add($"{where}: the nonce of #{before} used again (RFC 8555, section 6.5)");

                    else if (!handedOut.Contains(nonce))
                        wrong.Add($"{where}: a nonce the server never handed out (RFC 8555, section 6.5)");

                    used.TryAdd(nonce, exchange.Number);

                    if (lastPost is { ProblemType: "urn:ietf:params:acme:error:badNonce", ReplayNonce: String fresh } &&
                        lastPost.URL == exchange.URL &&
                        nonce != fresh)
                        wrong.Add($"{where}: retried after the badNonce of #{lastPost.Number} with a nonce other than the one of that answer (RFC 8555, section 6.5)");

                }

                if ((jwk is null) == (kid is null))
                    wrong.Add($"{where}: {(jwk is null ? "neither" : "both")} \"jwk\" {(jwk is null ? "nor" : "and")} \"kid\" (RFC 8555, section 6.2)");

                RawJWK? key = null;

                if (jwk is not null)
                {
                    try
                    {
                        key = RawJWK.Parse(jwk.ToJsonString());
                    }
                    catch (FormatException e)
                    {
                        wrong.Add($"{where}: a \"jwk\" RawACME cannot read: {e.Message}");
                    }
                }
                // A "kid" of an account opened before the recording: unsigned here.
                else if (kid is not null)
                    accounts.TryGetValue(kid, out key);

                if (key is not null && alg is not null)
                {

                    Boolean verified;

                    try
                    {
                        verified = jws.VerifiedBy(key, alg);
                    }
                    catch (CryptographicException)
                    {
                        verified = false;
                    }

                    if (!verified)
                        wrong.Add($"{where}: the signature does not hold by {(jwk is not null ? "its \"jwk\"" : "the key of the account")}");

                }

                // The account of a "jwk": where the server says it is.
                if (jwk is not null && key is not null && exchange.Status is 200 or 201 && exchange.Location is String location)
                    accounts[location] = key;

                if (certificates.Contains(exchange.URL.OriginalString) &&
                    exchange.Accept?.Contains("application/pem-certificate-chain", StringComparison.OrdinalIgnoreCase) != true)
                    wrong.Add($"{where}: a certificate asked for as '{exchange.Accept}', not application/pem-certificate-chain (RFC 8555, section 7.4.2)");

                lastPost = exchange;

            }

            else
            {

                var target = exchange.URL.OriginalString;

                // The directory is what a client GETs first.
                if (directory is null && exchange.Method == "GET")
                    directory = target;

                var allowed = exchange.Method == "GET"  && target == directory
                              || exchange.Method is "GET" or "HEAD" && target == newNonce      // section 7.2
                              || exchange.Method == "GET"  && renewalInfo is not null && target.StartsWith(renewalInfo + "/", StringComparison.Ordinal);

                if (!allowed)
                    wrong.Add($"{where}: a {exchange.Method} where RFC 8555, section 6.3 has a POST-as-GET");

            }

            if (exchange.ReplayNonce is String handed)
                handedOut.Add(handed);

            // What the answers name: the renewal window's resource, the certificates.
            try
            {
                if (exchange.Header("Content-Type")?.Contains("json", StringComparison.OrdinalIgnoreCase) == true &&
                    JsonNode.Parse(exchange.ResponseBody) is JsonObject answer)
                {

                    if (Member(answer, "newNonce") is String nonceURL)
                        newNonce = nonceURL;

                    if (Member(answer, "renewalInfo") is String info)
                        renewalInfo = info.TrimEnd('/');

                    if (Member(answer, "certificate") is String certificate)
                        certificates.Add(certificate);

                }
            }
            catch (JsonException) { }

        }

        return wrong;

    }

    private static String? Member(JsonObject Object, String Name)

        => Object[Name] is JsonValue value && value.TryGetValue<String>(out var text)
               ? text
               : null;

}
