using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

namespace PKIConformance.Core.Peers;

/// <summary>
/// One request of a client and the answer to it, as they went over the wire.
/// </summary>
public sealed record HTTPExchange(Int32                                Number,
                                  DateTimeOffset                       Sent,
                                  DateTimeOffset                       Received,
                                  String                               Method,
                                  Uri                                  URL,
                                  String?                              ContentType,
                                  String?                              Accept,
                                  String                               RequestBody,
                                  Int32                                Status,
                                  IReadOnlyDictionary<String, String>  ResponseHeaders,
                                  String                               ResponseBody)
{

    /// <summary>The answer's Replay-Nonce, if any.</summary>
    public String? ReplayNonce
        => Header("Replay-Nonce");

    /// <summary>The answer's Location, if any.</summary>
    public String? Location
        => Header("Location");

    /// <summary>The answer's Retry-After, if any.</summary>
    public String? RetryAfter
        => Header("Retry-After");

    /// <summary>The "type" of the answer's problem document, if it is one.</summary>
    public String? ProblemType
    {
        get
        {
            if (Header("Content-Type")?.StartsWith("application/problem+json", StringComparison.OrdinalIgnoreCase) != true)
                return null;
            try
            {
                return JsonNode.Parse(ResponseBody)?["type"]?.GetValue<String>();
            }
            catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException)
            {
                return null;
            }
        }
    }

    /// <summary>A header of the answer, by its name in any case.</summary>
    public String? Header(String Name)
        => ResponseHeaders.FirstOrDefault(header => String.Equals(header.Key, Name, StringComparison.OrdinalIgnoreCase)).Value;

    /// <inheritdoc/>
    public override String ToString()

        => $"#{Number} {Sent:HH:mm:ss.fff} {Method} {URL} -> {Status}" +
           (ProblemType is String problem ? $" {problem}" : "") +
           (RetryAfter  is String retry   ? $" Retry-After: {retry}" : "");

}


/// <summary>
/// What a client of the suite's sends to a real ACME server, and what comes
/// back, kept - the recording proxy of PLAN.md, section 6, as the handler of
/// the client's own HttpClient: it changes nothing, and it is not Hermod's.
/// It trusts the TLS of the server by the bench's root alone.
/// </summary>
public sealed class RecordingHandler : DelegatingHandler
{

    #region Data

    private readonly ConcurrentQueue<HTTPExchange> exchanges = new ();
    private          Int32                         counter;

    #endregion

    #region Properties

    /// <summary>Every exchange so far, in the order the requests were sent.</summary>
    public IReadOnlyList<HTTPExchange> Exchanges
        => [ .. exchanges.OrderBy(exchange => exchange.Number) ];

    /// <summary>Every exchange so far, one a line - the evidence of a test.</summary>
    public String Log
        => String.Join("\n", Exchanges);

    #endregion

    #region Constructor(s)

    /// <summary>
    /// A handler that trusts the TLS of a server by the given root - a PEM
    /// file - and nothing else.
    /// </summary>
    public RecordingHandler(String TrustedRootFile)
        : base(TrustingHandler(TrustedRootFile))
    { }

    /// <summary>
    /// A handler of HttpClient that trusts the TLS of a server by the given
    /// root alone, the name checked as ever.
    /// </summary>
    public static SocketsHttpHandler TrustingHandler(String TrustedRootFile)
    {

        var roots = new X509Certificate2Collection();
        roots.ImportFromPemFile(TrustedRootFile);

        return new SocketsHttpHandler {
                   SslOptions = new SslClientAuthenticationOptions {
                       RemoteCertificateValidationCallback = (sender, certificate, chain, errors) => {

                           if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                               return false;

                           using var custom = new X509Chain();
                           custom.ChainPolicy.TrustMode          = X509ChainTrustMode.CustomRootTrust;
                           custom.ChainPolicy.RevocationMode     = X509RevocationMode.NoCheck;
                           custom.ChainPolicy.CustomTrustStore.AddRange(roots);

                           if (chain is not null)
                               foreach (var element in chain.ChainElements)
                                   custom.ChainPolicy.ExtraStore.Add(element.Certificate);

                           return custom.Build(new X509Certificate2(certificate));

                       }
                   }
               };

    }

    #endregion


    #region SendAsync(Request, CancellationToken)

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage  Request,
                                                                 CancellationToken   CancellationToken)
    {

        var number    = Interlocked.Increment(ref counter);
        var body      = Request.Content is not null ? await Request.Content.ReadAsStringAsync(CancellationToken) : "";
        var sent      = DateTimeOffset.UtcNow;
        var response  = await base.SendAsync(Request, CancellationToken);

        await response.Content.LoadIntoBufferAsync(CancellationToken);

        var text      = await response.Content.ReadAsStringAsync(CancellationToken);
        var headers   = response.Headers.Concat(response.Content.Headers).
                                 GroupBy (header => header.Key, StringComparer.OrdinalIgnoreCase).
                                 ToDictionary(group => group.Key, group => String.Join(", ", group.SelectMany(header => header.Value)), StringComparer.OrdinalIgnoreCase);

        exchanges.Enqueue(new HTTPExchange(number,
                                           sent,
                                           DateTimeOffset.UtcNow,
                                           Request.Method.Method,
                                           Request.RequestUri!,
                                           Request.Content?.Headers.ContentType?.ToString(),
                                           Request.Headers.Accept.Count > 0 ? Request.Headers.Accept.ToString() : null,
                                           body,
                                           (Int32) response.StatusCode,
                                           headers,
                                           text));

        return response;

    }

    #endregion

}
