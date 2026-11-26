using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using PKIConformance.Core.RawACME;

namespace PKIConformance.Core.Scripted;

/// <summary>
/// An ACME server (RFC 8555) of the bench for the client under test: written
/// from the RFC - not from Hermod's TestACMEServer, not from the PKI - strict
/// where the RFC is, and scriptable test by test: every request is kept as it
/// came (<see cref="Requests"/>), and every answer can be replaced or
/// rewritten (<see cref="Before"/>, <see cref="After"/>).
/// </summary>
/// <remarks>
/// <para>
/// HTTP/1.1 on a <see cref="TcpListener"/> on 127.0.0.1, plain HTTP: what a
/// client sends is what a test reads, and what it is answered is what a test
/// says - a relative Location, a problem without a type, an HTML page of a
/// proxy, a chain with a private key in it.
/// </para>
/// <para>
/// <b>Strict.</b> Every POST is checked as RFC 8555, section 6 has it - the
/// Content-Type, the flattened JWS, "alg", "jwk" or "kid", a nonce handed out
/// and not used before, a "url" equal to the string the server handed out
/// (section 6.4), the signature by RawACME - and refused with the problem
/// the RFC names. A client that gets something wrong fails here as it would
/// at Let's Encrypt.
/// </para>
/// <para>
/// <b>Validation</b> of http-01 is a GET of http://127.0.0.1:<see cref="HTTP01Port"/>/.well-known/acme-challenge/{token}
/// (::1 for an IPv6 identifier) with the identifier as the Host, as a CA asks
/// port 80 of the name - every name of the bench is on the loopback; of
/// dns-01 a look into <see cref="Zone"/>, which the client's responder
/// writes into. Either can be replaced by <see cref="Validate"/>.
/// </para>
/// </remarks>
public sealed class ScriptedACMEServer : IAsyncDisposable
{

    #region Data

    /// <summary>The media type of every POST (RFC 8555, section 6.2).</summary>
    public const String JOSE = "application/jose+json";

    private const Int32 MaxHead = 64 * 1024;

    private static readonly String[] Algorithms = [ "ES256", "ES384", "ES512", "RS256", "PS256" ];

    private readonly TcpListener                                  listener;
    private readonly CancellationTokenSource                      stop       = new();
    private readonly Task                                         loop;
    private readonly Lock                                         gate       = new();
    private          Int32                                        numbers;

    private readonly ConcurrentDictionary<String, Byte>           nonces     = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<String, Byte>           usedNonces = new(StringComparer.Ordinal);
    private readonly Dictionary<String, Resource>                 resources  = new(StringComparer.Ordinal);
    private readonly Dictionary<String, ScriptedAccount>          accounts   = new(StringComparer.Ordinal);
    private readonly Dictionary<String, ScriptedOrder>            orders     = new(StringComparer.Ordinal);
    private readonly Dictionary<String, ScriptedAuthorization>    authzs     = new(StringComparer.Ordinal);
    private readonly Dictionary<String, ScriptedChallenge>        challenges = new(StringComparer.Ordinal);
    private readonly Dictionary<String, ScriptedCertificate>      certs      = new(StringComparer.Ordinal);
    private readonly HashSet<String>                              usedEAB    = new(StringComparer.Ordinal);

    private sealed record Resource(String Kind, String Id, String URL, IReadOnlyList<String> Targets);

    #endregion

    #region Properties - where

    /// <summary>The port on 127.0.0.1.</summary>
    public UInt16  Port          { get; }

    /// <summary>"http://127.0.0.1:{port}".</summary>
    public String  BaseURL       { get; }

    /// <summary>The URL of the directory - the one URL a client is given.</summary>
    public String  DirectoryURL  { get; }

    /// <summary>The certificate authority that issues.</summary>
    public BenchCA CA            { get; }

    /// <summary>
    /// The URL of every resource, by its kind and identifier. A test changes
    /// it before a client asks - to hand out URLs of a shape of its own.
    /// </summary>
    public Func<String, String, String>  URLFor  { get; set; }

    #endregion

    #region Properties - what the server is like

    /// <summary>The clock of certificates, orders and windows.</summary>
    public Func<DateTimeOffset>   Now                         { get; set; } = () => DateTimeOffset.UtcNow;

    /// <summary>The port of the client's http-01 responder - port 80 of every name, on the bench.</summary>
    public UInt16                 HTTP01Port                  { get; set; }

    /// <summary>The terms of service in the directory's meta, or none.</summary>
    public String?                TermsOfService              { get; set; } = "https://pkiconformance.test/terms/v1";

    /// <summary>Whether a new account must agree to them (RFC 8555, section 7.3).</summary>
    public Boolean                RequireTermsOfService       { get; set; } = true;

    /// <summary>Whether accounts are opened only with an external account binding (section 7.3.4).</summary>
    public Boolean                ExternalAccountRequired     { get; set; }

    /// <summary>The MAC keys of external accounts, by key identifier.</summary>
    public ConcurrentDictionary<String, Byte[]> ExternalAccountKeys { get; } = new(StringComparer.Ordinal);

    /// <summary>Whether the directory has "renewalInfo" (RFC 9773).</summary>
    public Boolean                RenewalInfo                 { get; set; } = true;

    /// <summary>The profiles of the directory's meta (draft-ietf-acme-profiles), by name, or none.</summary>
    public IReadOnlyDictionary<String, String>? Profiles      { get; set; }

    /// <summary>How long a certificate is valid.</summary>
    public TimeSpan               CertificateLifetime         { get; set; } = TimeSpan.FromDays(90);

    /// <summary>Whether a valid authorization of the account is taken for a new order of the identifier.</summary>
    public Boolean                ReuseAuthorizations         { get; set; } = true;

    /// <summary>For how many polls an authorization stays pending after its validation is done.</summary>
    public Int32                  AuthorizationProcessingPolls { get; set; }

    /// <summary>For how many polls an order stays "processing" after it was finalized.</summary>
    public Int32                  OrderProcessingPolls        { get; set; }

    /// <summary>The Retry-After of an answer to a poll of something not done yet, or none.</summary>
    public String?                PollRetryAfter              { get; set; }

    /// <summary>How long a validation waits before it asks.</summary>
    public TimeSpan               ValidationDelay             { get; set; }

    /// <summary>The challenge types of an identifier: http-01 and dns-01 for a name, dns-01 for a wildcard, http-01 for an address (RFC 8738).</summary>
    public Func<ScriptedIdentifier, Boolean, IReadOnlyList<String>> ChallengeTypes { get; set; } = DefaultChallengeTypes;

    /// <summary>A validation of the test's instead of the server's own: the challenge and its key authorization.</summary>
    public Func<ScriptedChallenge, String, Task<(Boolean Valid, String Detail)>>? Validate { get; set; }

    /// <summary>The token of a new challenge of the type - 256 random bits, base64url, by default.</summary>
    public Func<String, String>? TokenFor { get; set; }

    /// <summary>The PEM of a certificate, rewritten - into what a test wants a client to read.</summary>
    public Func<ScriptedCertificate, String, String>? RewriteChain { get; set; }

    /// <summary>How many alternate chains a certificate has (RFC 8555, section 7.4.2).</summary>
    public Int32                  AlternateChains             { get; set; }

    /// <summary>The suggested window of a certificate (RFC 9773, section 4.2); the last third but one sixth of its lifetime by default.</summary>
    public Func<ScriptedCertificate, (DateTimeOffset Start, DateTimeOffset End)>? RenewalWindow { get; set; }

    /// <summary>The Retry-After of a RenewalInfo, or none.</summary>
    public String?                RenewalRetryAfter           { get; set; } = "21600";

    /// <summary>The explanationURL of a RenewalInfo, or none.</summary>
    public String?                RenewalExplanationURL       { get; set; }

    /// <summary>The directory, rewritten as a test wants it.</summary>
    public Action<JsonObject>?    RewriteDirectory            { get; set; }

    /// <summary>
    /// What to answer a request instead - asked once the request passed the
    /// checks of section 6 (and for every GET and HEAD); null for the
    /// server's own answer.
    /// </summary>
    public Func<ACMERequest, ScriptedAnswer?>?                Before  { get; set; }

    /// <summary>Every answer rewritten, the server's and <see cref="Before"/>'s.</summary>
    public Func<ACMERequest, ScriptedAnswer, ScriptedAnswer>? After   { get; set; }

    #endregion

    #region Properties - what happened

    /// <summary>Every request, in the order they came.</summary>
    public ConcurrentQueue<ACMERequest>         Requests     { get; } = new();

    /// <summary>Every validation, in the order they were made.</summary>
    public ConcurrentQueue<ScriptedValidation>  Validations  { get; } = new();

    /// <summary>The TXT records of dns-01, by name (case-insensitive), as the client's responder wrote them.</summary>
    public ConcurrentDictionary<String, ConcurrentDictionary<String, Byte>> Zone { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Every nonce handed out.</summary>
    public ConcurrentDictionary<String, Byte>   HandedOutNonces { get; } = new(StringComparer.Ordinal);

    /// <summary>The accounts.</summary>
    public IReadOnlyList<ScriptedAccount>       Accounts       { get { lock (gate) return [ .. accounts.Values ]; } }

    /// <summary>The orders, in the order they were made.</summary>
    public IReadOnlyList<ScriptedOrder>         Orders         { get { lock (gate) return [ .. orders.Values ]; } }

    /// <summary>The authorizations.</summary>
    public IReadOnlyList<ScriptedAuthorization> Authorizations { get { lock (gate) return [ .. authzs.Values ]; } }

    /// <summary>The certificates issued.</summary>
    public IReadOnlyList<ScriptedCertificate>   Certificates   { get { lock (gate) return [ .. certs.Values ]; } }

    /// <summary>Every URL handed out, exactly as handed out.</summary>
    public IReadOnlyList<String>                HandedOutURLs  { get { lock (gate) return [ .. resources.Values.Select(resource => resource.URL) ]; } }

    /// <summary>The requests of a kind of resource.</summary>
    public IReadOnlyList<ACMERequest> RequestsOf(String Resource)
        => [ .. Requests.Where(request => request.Resource == Resource) ];

    /// <summary>The signed requests - every POST that was a JWS.</summary>
    public IReadOnlyList<ACMERequest> SignedRequests
        => [ .. Requests.Where(request => request.JWS is not null) ];

    #endregion

    #region Constructor(s)

    private ScriptedACMEServer(TcpListener  Listener,
                               BenchCA      CA)
    {

        this.listener      = Listener;
        this.Port          = (UInt16) ((IPEndPoint) Listener.LocalEndpoint).Port;
        this.BaseURL       = $"http://127.0.0.1:{Port}";
        this.CA            = CA;
        this.URLFor        = DefaultURLFor;
        this.DirectoryURL  = $"{BaseURL}/directory";

        lock (gate)
            resources["directory:"] = new Resource("directory", "", DirectoryURL, Targets(DirectoryURL));

        this.loop          = Task.Run(AcceptLoop);

    }

    /// <summary>
    /// A server on a free port of 127.0.0.1, with a CA of the given number of
    /// intermediates.
    /// </summary>
    public static ScriptedACMEServer Start(Int32 Intermediates = 1)
    {

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        return new ScriptedACMEServer(listener, BenchCA.Create(Intermediates));

    }

    #endregion


    #region URLs

    /// <summary>
    /// The URL of a resource as the server hands it out unless told otherwise.
    /// </summary>
    public String DefaultURLFor(String Kind, String Id)

        => Kind switch {
               "newNonce"     => $"{BaseURL}/acme/new-nonce",
               "newAccount"   => $"{BaseURL}/acme/new-acct",
               "newOrder"     => $"{BaseURL}/acme/new-order",
               "revokeCert"   => $"{BaseURL}/acme/revoke-cert",
               "keyChange"    => $"{BaseURL}/acme/key-change",
               "renewalInfo"  => $"{BaseURL}/acme/renewal-info",
               _              => $"{BaseURL}/acme/{Kind}/{Id}"
           };

    /// <summary>
    /// The URL of a resource - registered at its first use, and the same ever
    /// after.
    /// </summary>
    private String URL(String Kind, String Id = "")
    {

        lock (gate)
        {

            if (resources.TryGetValue($"{Kind}:{Id}", out var known))
                return known.URL;

            var url = URLFor(Kind, Id);
            resources[$"{Kind}:{Id}"] = new Resource(Kind, Id, url, Targets(url));
            return url;

        }

    }

    /// <summary>
    /// The request targets a URL may arrive as: as written, as .NET's Uri
    /// writes it, and either of them unescaped - so that a client that
    /// re-encodes a URL still reaches the resource, and is told by the "url"
    /// check what it got wrong.
    /// </summary>
    private static IReadOnlyList<String> Targets(String URL)
    {

        var targets = new List<String>();

        var schemeEnd = URL.IndexOf("://", StringComparison.Ordinal);
        var pathStart = schemeEnd >= 0 ? URL.IndexOf('/', schemeEnd + 3) : -1;
        var asWritten = pathStart >= 0 ? URL[pathStart..] : "/";

        targets.Add(asWritten);

        if (Uri.TryCreate(URL, UriKind.Absolute, out var uri))
            targets.Add(uri.PathAndQuery);

        foreach (var target in targets.ToArray())
            targets.Add(Uri.UnescapeDataString(target));

        return [ .. targets.Distinct() ];

    }

    private Resource? Route(String Target)
    {

        var unescaped = Uri.UnescapeDataString(Target);

        lock (gate)
        {

            foreach (var resource in resources.Values)
                if (resource.Targets.Contains(Target) || resource.Targets.Contains(unescaped))
                    return resource;

            if (resources.TryGetValue("renewalInfo:", out var renewalInfo))
            {
                var prefix = Targets(renewalInfo.URL)[0].TrimEnd('/') + "/";
                if (Target.StartsWith(prefix, StringComparison.Ordinal))
                    return renewalInfo with { Id = Target[prefix.Length..] };
            }

        }

        return null;

    }

    private static String NewId()
        => Convert.ToHexString(RandomNumberGenerator.GetBytes(10)).ToLowerInvariant();

    #endregion


    #region Nonces

    /// <summary>A fresh nonce: 16 random octets, base64url.</summary>
    public String NewNonce()
    {
        var nonce = RawBase64Url.Encode(RandomNumberGenerator.GetBytes(16));
        nonces[nonce] = 0;
        HandedOutNonces[nonce] = 0;
        return nonce;
    }

    /// <summary>Forget every nonce handed out so far - as a server does after a restart.</summary>
    public void ForgetNonces()
        => nonces.Clear();

    #endregion


    #region HTTP

    private async Task AcceptLoop()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(stop.Token);
                _ = Task.Run(() => ServeAsync(client));
            }
        }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException)    { }
        catch (SocketException)            { }
    }

    private async Task ServeAsync(TcpClient Client)
    {

        using (Client)
        {
            try
            {

                var stream     = Client.GetStream();
                var connection = new Connection(stream);

                while (!stop.IsCancellationRequested)
                {

                    var head = await connection.ReadHeadAsync(stop.Token);

                    if (head is null)
                        return;

                    var lines   = head.Split("\r\n");
                    var first   = lines[0].Split(' ');

                    if (first.Length < 3)
                        return;

                    var headers = new Dictionary<String, String>(StringComparer.OrdinalIgnoreCase);

                    foreach (var line in lines.Skip(1).Where(line => line.Length > 0))
                    {
                        var colon = line.IndexOf(':');
                        if (colon <= 0)
                            continue;
                        var name  = line[..colon].Trim();
                        var value = line[(colon + 1)..].Trim();
                        headers[name] = headers.TryGetValue(name, out var before) ? $"{before}, {value}" : value;
                    }

                    if (headers.ContainsKey("Transfer-Encoding"))
                    {
                        await WriteAsync(stream, first[0], new ScriptedAnswer(411), null);
                        return;
                    }

                    var length  = headers.TryGetValue("Content-Length", out var text) && Int32.TryParse(text, out var count) ? count : 0;
                    var body    = length > 0 ? await connection.ReadBodyAsync(length, stop.Token) : [];

                    var request = new ACMERequest {
                                      Number      = Interlocked.Increment(ref numbers),
                                      Method      = first[0],
                                      Target      = first[1],
                                      URL         = BaseURL + first[1],
                                      Headers     = headers,
                                      Body        = Encoding.UTF8.GetString(body),
                                      At          = DateTimeOffset.UtcNow,
                                      ServerTime  = Now()
                                  };

                    Requests.Enqueue(request);

                    ScriptedAnswer answer;

                    try
                    {
                        answer = await HandleAsync(request);
                    }
                    catch (Exception e)
                    {
                        answer = ScriptedAnswer.Problem(500, "serverInternal", $"The scripted server failed: {e}");
                    }

                    if (After is not null)
                        answer = After(request, answer);

                    request.Answer = answer;

                    await WriteAsync(stream, request.Method, answer, request);

                    if (headers.TryGetValue("Connection", out var connectionHeader) &&
                        connectionHeader.Contains("close", StringComparison.OrdinalIgnoreCase))
                        return;

                }

            }
            catch (OperationCanceledException) { }
            catch (IOException)                { }
            catch (SocketException)            { }
        }

    }

    private async Task WriteAsync(NetworkStream    Stream,
                                  String           Method,
                                  ScriptedAnswer   Answer,
                                  ACMERequest?     Request)
    {

        var body = Encoding.UTF8.GetBytes(Answer.Body ?? "");
        var text = new StringBuilder();

        text.Append($"HTTP/1.1 {Answer.Status} {ReasonOf(Answer.Status)}\r\n");
        text.Append($"Content-Length: {body.Length}\r\n");

        if (Answer.ContentType is not null)
            text.Append($"Content-Type: {Answer.ContentType}\r\n");

        if (!Answer.WithoutNonce)
        {
            var nonce = Answer.ReplayNonce ?? NewNonce();
            text.Append($"Replay-Nonce: {nonce}\r\n");
            if (Request is not null)
                Request.AnswerNonce = nonce;
        }

        if (Request?.Resource is not "directory" and not null)
            text.Append($"Link: <{DirectoryURL}>;rel=\"index\"\r\n");

        foreach (var (name, value) in Answer.Headers ?? [])
            text.Append($"{name}: {value}\r\n");

        text.Append("\r\n");

        await Stream.WriteAsync(Encoding.ASCII.GetBytes(text.ToString()), stop.Token);

        if (Method != "HEAD")
            await Stream.WriteAsync(body, stop.Token);

    }

    private static String ReasonOf(Int32 Status)

        => Status switch {
               200 => "OK",
               201 => "Created",
               204 => "No Content",
               400 => "Bad Request",
               401 => "Unauthorized",
               403 => "Forbidden",
               404 => "Not Found",
               405 => "Method Not Allowed",
               409 => "Conflict",
               411 => "Length Required",
               415 => "Unsupported Media Type",
               429 => "Too Many Requests",
               500 => "Internal Server Error",
               502 => "Bad Gateway",
               503 => "Service Unavailable",
               _   => "Status"
           };

    /// <summary>
    /// A connection's octets: heads up to the empty line, bodies by their
    /// Content-Length, several requests one after the other.
    /// </summary>
    private sealed class Connection(NetworkStream Stream)
    {

        private readonly Byte[] buffer = new Byte[MaxHead];
        private          Int32  start;
        private          Int32  end;

        public async Task<String?> ReadHeadAsync(CancellationToken CancellationToken)
        {

            while (true)
            {

                for (var i = start; i + 3 < end; i++)
                {
                    if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                    {
                        var head = Encoding.ASCII.GetString(buffer, start, i - start);
                        start = i + 4;
                        return head;
                    }
                }

                if (start > 0)
                {
                    Array.Copy(buffer, start, buffer, 0, end - start);
                    end  -= start;
                    start = 0;
                }

                if (end == buffer.Length)
                    return null;

                var read = await Stream.ReadAsync(buffer.AsMemory(end), CancellationToken);

                if (read == 0)
                    return null;

                end += read;

            }

        }

        public async Task<Byte[]> ReadBodyAsync(Int32 Length, CancellationToken CancellationToken)
        {

            var body = new Byte[Length];
            var have = Math.Min(Length, end - start);

            Array.Copy(buffer, start, body, 0, have);
            start += have;

            while (have < Length)
            {
                var read = await Stream.ReadAsync(body.AsMemory(have), CancellationToken);
                if (read == 0)
                    throw new IOException("The connection closed in the middle of a body.");
                have += read;
            }

            return body;

        }

    }

    #endregion


    #region HandleAsync(Request)

    private async Task<ScriptedAnswer> HandleAsync(ACMERequest Request)
    {

        var resource = Route(Request.Target);

        if (resource is null)
            return ScriptedAnswer.Problem(404, "malformed", $"There is no resource at {Request.Target}.");

        Request.Resource     = resource.Kind;
        Request.ResourceId   = resource.Id;
        Request.HandedOutURL = resource.Kind == "renewalInfo" ? URL("renewalInfo") : resource.URL;

        if (Request.Method == "POST")
        {

            var refusal = Check(Request, resource);

            if (refusal is not null)
                return refusal;

            if (Before?.Invoke(Request) is ScriptedAnswer scripted)
                return scripted;

            return await PostAsync(Request, resource);

        }

        if (Before?.Invoke(Request) is ScriptedAnswer scriptedGet)
            return scriptedGet;

        return (Request.Method, resource.Kind) switch {
                   ("GET",  "directory")    => ScriptedAnswer.Json(200, Directory()),
                   ("HEAD", "newNonce")     => new ScriptedAnswer(200, Headers: [ ("Cache-Control", "no-store") ]),
                   ("GET",  "newNonce")     => new ScriptedAnswer(204, Headers: [ ("Cache-Control", "no-store") ]),
                   ("GET",  "renewalInfo")  => RenewalInfoOf(resource.Id),
                   _                        => ScriptedAnswer.Problem(405, "malformed", $"{Request.Method} is not allowed here; ACME reads by POST-as-GET (RFC 8555, section 6.3).").With("Allow", "POST")
               };

    }

    #endregion

    #region Check(Request, Resource) - RFC 8555, section 6

    private ScriptedAnswer? Check(ACMERequest  Request,
                                  Resource     Resource)
    {

        // Section 6.2: "application/jose+json", and nothing else.
        if (!String.Equals(Request.ContentType, JOSE, StringComparison.OrdinalIgnoreCase))
            return ScriptedAnswer.Problem(415, "malformed", $"The Content-Type of a POST is {JOSE}, not '{Request.ContentType}'.");

        // Section 6.2: the flattened JSON serialization.
        JsonObject body;

        try
        {
            body = JsonNode.Parse(Request.Body) as JsonObject ?? throw new JsonException("not an object");
        }
        catch (JsonException e)
        {
            return ScriptedAnswer.Problem(400, "malformed", $"The body is no JSON object: {e.Message}");
        }

        Request.JWSMembers = [ .. body.Select(member => member.Key) ];

        if (body["protected"] is not JsonValue p || !p.TryGetValue<String>(out var @protected) ||
            body["payload"]   is not JsonValue l || !l.TryGetValue<String>(out var payload)    ||
            body["signature"] is not JsonValue s || !s.TryGetValue<String>(out var signature))
            return ScriptedAnswer.Problem(400, "malformed", "A request is a JWS of the flattened JSON serialization: \"protected\", \"payload\" and \"signature\".");

        if (body.ContainsKey("header") || body.ContainsKey("signatures"))
            return ScriptedAnswer.Problem(400, "malformed", "A JWS of ACME has no unprotected header and one signature (RFC 8555, section 6.2).");

        Request.JWS = new RawJWS(@protected, payload, signature);

        if (!RawBase64Url.TryDecode(@protected, out var protectedOctets, out var whyNot) ||
            !RawBase64Url.TryDecode(payload,    out var payloadOctets,   out whyNot))
            return ScriptedAnswer.Problem(400, "malformed", $"Not base64url as RFC 8555, section 5 has it: {whyNot}");

        try
        {
            Request.Protected   = JsonNode.Parse(Encoding.UTF8.GetString(protectedOctets)) as JsonObject ?? throw new JsonException("not an object");
            Request.PayloadJSON = Encoding.UTF8.GetString(payloadOctets);
            Request.Payload     = Request.PayloadJSON.Length > 0 ? JsonNode.Parse(Request.PayloadJSON) : null;
        }
        catch (JsonException e)
        {
            return ScriptedAnswer.Problem(400, "malformed", $"The protected header or the payload is no JSON: {e.Message}");
        }

        // Section 6.2: an asymmetric signature of an algorithm the server knows.
        if (Request.Alg is not String alg || !Algorithms.Contains(alg))
            return ScriptedAnswer.Problem(400, "badSignatureAlgorithm", $"\"alg\" is {Request.Protected["alg"]?.ToJsonString() ?? "missing"}.",
                                          new JsonObject { ["algorithms"] = new JsonArray([ .. Algorithms.Select(a => JsonValue.Create(a)) ]) });

        // Section 6.5: a nonce of the server's, used once.
        if (Request.Nonce is not String nonce || !nonces.TryRemove(nonce, out _))
        {
            if (Request.Nonce is String reused)
                usedNonces[reused] = 0;
            return ScriptedAnswer.Problem(400, "badNonce", Request.Nonce is null ? "The protected header has no \"nonce\"." : $"The nonce {Request.Nonce} is none of the server's, or used already.");
        }

        usedNonces[nonce] = 0;

        // Section 6.4: the "url" is the string handed out, exactly.
        if (Request.HeaderURL != Request.HandedOutURL)
            return ScriptedAnswer.Problem(401, "unauthorized", $"The \"url\" is '{Request.HeaderURL}', not the URL handed out: '{Request.HandedOutURL}' (RFC 8555, section 6.4).");

        // Section 6.2: "jwk" or "kid", never both.
        var hasJWK = Request.Protected.ContainsKey("jwk");
        var hasKid = Request.Protected.ContainsKey("kid");

        if (hasJWK == hasKid)
            return ScriptedAnswer.Problem(400, "malformed", "The protected header has exactly one of \"jwk\" and \"kid\".");

        RawJWK key;

        if (hasJWK)
        {

            if (Resource.Kind is not "newAccount" and not "revokeCert")
                return ScriptedAnswer.Problem(400, "malformed", $"A request of {Resource.Kind} is signed by an account, its \"kid\" (RFC 8555, section 6.2).");

            if (Request.JWK is not JsonObject jwk || jwk.ContainsKey("d") || jwk.ContainsKey("p") || jwk.ContainsKey("q"))
                return ScriptedAnswer.Problem(400, "malformed", "\"jwk\" is a public key, and no more.");

            try
            {
                key = RawJWK.Parse(jwk.ToJsonString());
            }
            catch (FormatException e)
            {
                return ScriptedAnswer.Problem(400, "badPublicKey", e.Message);
            }

        }
        else
        {

            if (Resource.Kind == "newAccount")
                return ScriptedAnswer.Problem(400, "malformed", "newAccount is signed by a \"jwk\" (RFC 8555, section 6.2).");

            ScriptedAccount? account;

            lock (gate)
                account = accounts.Values.FirstOrDefault(candidate => candidate.URL == Request.Kid);

            if (account is null)
                return ScriptedAnswer.Problem(400, "accountDoesNotExist", $"There is no account '{Request.Kid}'.");

            if (account.Status != "valid")
                return ScriptedAnswer.Problem(403, "unauthorized", $"The account is {account.Status}.");

            Request.Account = account;
            key             = account.Key;

        }

        try
        {
            Request.Verified = Request.JWS.VerifiedBy(key, alg);
        }
        catch (CryptographicException)
        {
            Request.Verified = false;
        }

        if (!Request.Verified)
            return ScriptedAnswer.Problem(400, "malformed", "The signature does not hold.");

        return null;

    }

    #endregion

    #region PostAsync(Request, Resource)

    private async Task<ScriptedAnswer> PostAsync(ACMERequest  Request,
                                                 Resource     Resource)
    {

        switch (Resource.Kind)
        {

            case "newAccount":   return NewAccount(Request);
            case "newOrder":     return NewOrder(Request);
            case "revokeCert":   return Revoke(Request);
            case "keyChange":    return KeyChange(Request);

            case "account":      return Account(Request, Resource.Id);
            case "orders":       return OrdersOf(Request, Resource.Id);
            case "order":        return Order(Request, Resource.Id);
            case "authz":        return Authorization(Request, Resource.Id);
            case "challenge":    return await ChallengeAsync(Request, Resource.Id);
            case "finalize":     return Finalize(Request, Resource.Id);
            case "certificate":  return CertificateOf(Request, Resource.Id, Alternate: null);
            case "alternate":    return CertificateOf(Request, Resource.Id[..Resource.Id.LastIndexOf('-')], Alternate: Int32.Parse(Resource.Id[(Resource.Id.LastIndexOf('-') + 1)..]));

            default:             return ScriptedAnswer.Problem(405, "malformed", $"{Resource.Kind} is not POSTed to.");

        }

    }

    #endregion


    #region Directory()

    private JsonObject Directory()
    {

        var meta = new JsonObject {
                       ["website"]       = "https://pkiconformance.test/",
                       ["caaIdentities"] = new JsonArray("pkiconformance.test")
                   };

        if (TermsOfService is not null)
            meta["termsOfService"] = TermsOfService;

        if (ExternalAccountRequired)
            meta["externalAccountRequired"] = true;

        if (Profiles is not null)
        {
            var profiles = new JsonObject();
            foreach (var (name, description) in Profiles)
                profiles[name] = description;
            meta["profiles"] = profiles;
        }

        var directory = new JsonObject {
                            ["newNonce"]    = URL("newNonce"),
                            ["newAccount"]  = URL("newAccount"),
                            ["newOrder"]    = URL("newOrder"),
                            ["revokeCert"]  = URL("revokeCert"),
                            ["keyChange"]   = URL("keyChange"),
                        };

        if (RenewalInfo)
            directory["renewalInfo"] = URL("renewalInfo");

        directory["meta"] = meta;

        RewriteDirectory?.Invoke(directory);

        return directory;

    }

    #endregion

    #region NewAccount(Request) - section 7.3

    private ScriptedAnswer NewAccount(ACMERequest Request)
    {

        if (Request.PayloadObject is not JsonObject payload)
            return ScriptedAnswer.Problem(400, "malformed", "The payload of newAccount is an object.");

        var key = RawJWK.Parse(Request.JWK!.ToJsonString());

        lock (gate)
        {

            var existing = accounts.Values.FirstOrDefault(account => account.Key.Thumbprint == key.Thumbprint);

            // Section 7.3.1: the same key finds the same account, 200 and its Location.
            if (existing is not null)
                return ScriptedAnswer.Json(200, AccountJSON(existing), ("Location", existing.URL));

        }

        if (payload["onlyReturnExisting"] is JsonValue only && only.TryGetValue<Boolean>(out var onlyExisting) && onlyExisting)
            return ScriptedAnswer.Problem(400, "accountDoesNotExist", "There is no account of this key.");

        var agreed = payload["termsOfServiceAgreed"] is JsonValue terms && terms.TryGetValue<Boolean>(out var yes) && yes;

        if (TermsOfService is not null && RequireTermsOfService && !agreed)
            return ScriptedAnswer.Problem(403, "userActionRequired", $"The terms of service at {TermsOfService} are to be agreed to.")
                                 .With("Link", $"<{TermsOfService}>;rel=\"terms-of-service\"");

        var contacts = new List<String>();

        if (payload["contact"] is JsonArray array)
        {
            foreach (var contact in array)
            {

                var text = contact is JsonValue value && value.TryGetValue<String>(out var c) ? c : null;

                if (text is null || !text.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                    return ScriptedAnswer.Problem(400, "unsupportedContact", $"Only mailto: contacts are taken, not {contact?.ToJsonString()}.");

                // Section 7.3: no hfields, and one addr-spec.
                if (text.Contains('?') || text.Contains(',') || !text.Contains('@'))
                    return ScriptedAnswer.Problem(400, "invalidContact", $"'{text}' is no mailto: URL of one address without hfields (RFC 8555, section 7.3).");

                contacts.Add(text);

            }
        }

        JsonObject? binding = null;
        String?     kid     = null;

        if (payload["externalAccountBinding"] is JsonObject eab)
        {

            var refusal = CheckExternalAccountBinding(eab, Request, key, out kid);

            if (refusal is not null)
                return refusal;

            binding = eab;

        }
        else if (ExternalAccountRequired)
            return ScriptedAnswer.Problem(403, "externalAccountRequired", "An account is opened here with an external account binding only.");

        var id      = NewId();
        var account = new ScriptedAccount {
                          Id                      = id,
                          URL                     = URL("account", id),
                          OrdersURL               = URL("orders", id),
                          Key                     = key,
                          Contacts                = contacts,
                          TermsOfServiceAgreed    = agreed,
                          ExternalAccountKeyId    = kid,
                          ExternalAccountBinding  = binding
                      };

        lock (gate)
            accounts[id] = account;

        return ScriptedAnswer.Json(201, AccountJSON(account), ("Location", account.URL));

    }

    private ScriptedAnswer? CheckExternalAccountBinding(JsonObject       EAB,
                                                        ACMERequest      Request,
                                                        RawJWK           OuterKey,
                                                        out String?      KeyId)
    {

        KeyId = null;

        if (EAB["protected"] is not JsonValue p || !p.TryGetValue<String>(out var @protected) ||
            EAB["payload"]   is not JsonValue l || !l.TryGetValue<String>(out var payload)    ||
            EAB["signature"] is not JsonValue s || !s.TryGetValue<String>(out var signature)  ||
            !RawBase64Url.TryDecode(@protected, out var protectedOctets, out _) ||
            !RawBase64Url.TryDecode(payload,    out var payloadOctets,   out _) ||
            !RawBase64Url.TryDecode(signature,  out var mac,             out _))
            return ScriptedAnswer.Problem(400, "malformed", "The external account binding is no flattened JWS of base64url.");

        JsonObject header;

        try
        {
            header = JsonNode.Parse(Encoding.UTF8.GetString(protectedOctets)) as JsonObject ?? throw new JsonException();
        }
        catch (JsonException)
        {
            return ScriptedAnswer.Problem(400, "malformed", "The protected header of the external account binding is no JSON object.");
        }

        var alg = header["alg"]?.GetValue<String>();
        KeyId   = header["kid"]?.GetValue<String>();

        if (alg is not "HS256" and not "HS384" and not "HS512")
            return ScriptedAnswer.Problem(400, "malformed", $"The external account binding is MACed (RFC 8555, section 7.3.4), not '{alg}'.");

        if (header.ContainsKey("nonce"))
            return ScriptedAnswer.Problem(400, "malformed", "The external account binding has no \"nonce\" (RFC 8555, section 7.3.4).");

        if (header["url"]?.GetValue<String>() != Request.HeaderURL)
            return ScriptedAnswer.Problem(400, "malformed", "The \"url\" of the external account binding is that of the outer JWS (RFC 8555, section 7.3.4).");

        if (KeyId is null || !ExternalAccountKeys.TryGetValue(KeyId, out var macKey))
            return ScriptedAnswer.Problem(400, "unauthorized", $"There is no external account '{KeyId}'.");

        var input    = Encoding.ASCII.GetBytes($"{@protected}.{payload}");
        var expected = alg switch {
                           "HS384" => HMACSHA384.HashData(macKey, input),
                           "HS512" => HMACSHA512.HashData(macKey, input),
                           _       => HMACSHA256.HashData(macKey, input)
                       };

        if (!CryptographicOperations.FixedTimeEquals(expected, mac))
            return ScriptedAnswer.Problem(400, "unauthorized", "The MAC of the external account binding does not hold.");

        RawJWK inner;

        try
        {
            inner = RawJWK.Parse(Encoding.UTF8.GetString(payloadOctets));
        }
        catch (Exception)
        {
            return ScriptedAnswer.Problem(400, "malformed", "The payload of the external account binding is no JWK.");
        }

        if (inner.Thumbprint != OuterKey.Thumbprint)
            return ScriptedAnswer.Problem(400, "unauthorized", "The external account binding binds another key than the outer \"jwk\".");

        lock (gate)
        {
            if (!usedEAB.Add(KeyId))
                return ScriptedAnswer.Problem(400, "unauthorized", $"The external account '{KeyId}' is bound already.");
        }

        return null;

    }

    /// <summary>An account as the server writes it (RFC 8555, section 7.1.2).</summary>
    public static JsonObject AccountJSON(ScriptedAccount Account)
    {

        var json = new JsonObject {
                       ["status"]                = Account.Status,
                       ["contact"]               = new JsonArray([ .. Account.Contacts.Select(contact => JsonValue.Create(contact)) ]),
                       ["termsOfServiceAgreed"]  = Account.TermsOfServiceAgreed,
                       ["orders"]                = Account.OrdersURL
                   };

        if (Account.ExternalAccountBinding is not null)
            json["externalAccountBinding"] = Account.ExternalAccountBinding.DeepClone();

        return json;

    }

    #endregion

    #region Account(Request, Id) / OrdersOf(Request, Id) - sections 7.3.2, 7.3.6, 7.1.2.1

    private ScriptedAnswer Account(ACMERequest Request, String Id)
    {

        lock (gate)
        {

            if (!accounts.TryGetValue(Id, out var account) || account != Request.Account)
                return ScriptedAnswer.Problem(403, "unauthorized", "Not this account's.");

            if (Request.PayloadObject is JsonObject payload)
            {

                if (payload["status"]?.GetValue<String>() == "deactivated")
                    account.Status = "deactivated";

                if (payload["contact"] is JsonArray contacts)
                    account.Contacts = [ .. contacts.Select(contact => contact?.GetValue<String>() ?? "") ];

            }

            return ScriptedAnswer.Json(200, AccountJSON(account));

        }

    }

    private ScriptedAnswer OrdersOf(ACMERequest Request, String Id)
    {

        lock (gate)
        {

            if (!accounts.TryGetValue(Id, out var account) || account != Request.Account)
                return ScriptedAnswer.Problem(403, "unauthorized", "Not this account's.");

            return ScriptedAnswer.Json(200, new JsonObject {
                                                ["orders"] = new JsonArray([ .. orders.Values.Where(order => order.Account == account).Select(order => JsonValue.Create(order.URL)) ])
                                            });

        }

    }

    #endregion

    #region KeyChange(Request) - section 7.3.5

    private ScriptedAnswer KeyChange(ACMERequest Request)
    {

        var account = Request.Account!;

        if (Request.PayloadObject is not JsonObject inner ||
            inner["protected"]?.GetValue<String>() is not String @protected ||
            inner["payload"]?.  GetValue<String>() is not String payload    ||
            inner["signature"]?.GetValue<String>() is not String signature)
            return ScriptedAnswer.Problem(400, "malformed", "The payload of keyChange is a JWS (RFC 8555, section 7.3.5).");

        var jws    = new RawJWS(@protected, payload, signature);
        var header = JsonNode.Parse(jws.ProtectedJSON) as JsonObject;

        if (header?["jwk"] is not JsonObject jwk)
            return ScriptedAnswer.Problem(400, "malformed", "The inner JWS has a \"jwk\".");

        if (header["nonce"] is not null)
            return ScriptedAnswer.Problem(400, "malformed", "The inner JWS has no \"nonce\".");

        if (header["url"]?.GetValue<String>() != Request.HeaderURL)
            return ScriptedAnswer.Problem(400, "malformed", "The inner JWS has the \"url\" of the outer one.");

        var newKey = RawJWK.Parse(jwk.ToJsonString());

        if (!jws.VerifiedBy(newKey))
            return ScriptedAnswer.Problem(400, "malformed", "The inner JWS is not signed by the new key.");

        var change = JsonNode.Parse(jws.PayloadJSON) as JsonObject;

        if (change?["account"]?.GetValue<String>() != account.URL ||
            change["oldKey"] is not JsonObject oldKey ||
            RawJWK.Parse(oldKey.ToJsonString()).Thumbprint != account.Key.Thumbprint)
            return ScriptedAnswer.Problem(400, "malformed", "The key change names this account and its key.");

        lock (gate)
        {

            if (accounts.Values.FirstOrDefault(other => other.Key.Thumbprint == newKey.Thumbprint) is ScriptedAccount other)
                return ScriptedAnswer.Problem(409, "conflict", "The new key is another account's.").With("Location", other.URL);

            account.Key = newKey;

        }

        return ScriptedAnswer.Json(200, AccountJSON(account));

    }

    #endregion

    #region NewOrder(Request) - section 7.4

    /// <summary>
    /// The challenge types of an identifier, as RFC 8555 and RFC 8738 allow
    /// them: http-01 and dns-01 for a name, dns-01 only for a wildcard
    /// (section 7.1.3), http-01 only for an address (RFC 8738, section 7).
    /// </summary>
    public static IReadOnlyList<String> DefaultChallengeTypes(ScriptedIdentifier  Identifier,
                                                              Boolean             Wildcard)

        => Identifier.Type == "ip" ? [ "http-01" ]
         : Wildcard               ? [ "dns-01" ]
         :                          [ "http-01", "dns-01" ];

    private ScriptedAnswer NewOrder(ACMERequest Request)
    {

        var account = Request.Account!;

        if (Request.PayloadObject?["identifiers"] is not JsonArray array || array.Count == 0)
            return ScriptedAnswer.Problem(400, "malformed", "An order has at least one identifier.");

        var identifiers = new List<ScriptedIdentifier>();

        foreach (var node in array)
        {

            var type  = node?["type"]?.GetValue<String>();
            var value = node?["value"]?.GetValue<String>();

            if (type is null || value is null)
                return ScriptedAnswer.Problem(400, "malformed", $"An identifier has a \"type\" and a \"value\": {node?.ToJsonString()}.");

            if (type is not "dns" and not "ip")
                return ScriptedAnswer.Problem(400, "unsupportedIdentifier", $"Identifiers of the type '{type}' are not taken.");

            if (type == "ip")
            {
                // RFC 8738, section 3: the textual form of RFC 1123 or of RFC 5952.
                if (!IPAddress.TryParse(value, out var address) || address.ToString() != value || value.Contains('%'))
                    return ScriptedAnswer.Problem(400, "malformed", $"'{value}' is no address in the textual form of RFC 1123, section 2.1 or RFC 5952, section 4 (RFC 8738, section 3).");
            }
            else if (value != value.ToLowerInvariant() || value.EndsWith('.') || Uri.CheckHostName(value.StartsWith("*.") ? value[2..] : value) != UriHostNameType.Dns)
                return ScriptedAnswer.Problem(400, "rejectedIdentifier", $"'{value}' is no lower-case name without a final dot.");

            var identifier = new ScriptedIdentifier(type, value);

            if (!identifiers.Contains(identifier))
                identifiers.Add(identifier);

        }

        var profile = Request.PayloadObject["profile"]?.GetValue<String>();

        if (profile is not null && Profiles is not null && !Profiles.ContainsKey(profile))
            return ScriptedAnswer.Problem(400, "invalidProfile", $"There is no profile '{profile}' here.");

        var replaces = Request.PayloadObject["replaces"]?.GetValue<String>();

        lock (gate)
        {

            if (replaces is not null && RenewalInfo)
            {

                var replaced = certs.Values.FirstOrDefault(certificate => certificate.ARIId == replaces);

                if (replaced is null)
                    return ScriptedAnswer.Problem(400, "malformed", $"There is no certificate '{replaces}' to replace.");

                if (replaced.Account != account)
                    return ScriptedAnswer.Problem(403, "unauthorized", "The certificate to replace is another account's.");

                if (orders.Values.Any(order => order.Replaces == replaces && order.Status != "invalid"))
                    return ScriptedAnswer.Problem(409, "alreadyReplaced", $"The certificate '{replaces}' is replaced already.");

            }

            var now            = Now();
            var authorizations = new List<ScriptedAuthorization>();

            foreach (var identifier in identifiers)
            {

                var wildcard = identifier.Type == "dns" && identifier.Value.StartsWith("*.");
                var name     = new ScriptedIdentifier(identifier.Type, wildcard ? identifier.Value[2..] : identifier.Value);

                var reused   = ReuseAuthorizations
                                   ? authzs.Values.FirstOrDefault(authz => authz.Account == account && authz.Identifier == name && authz.Wildcard == wildcard &&
                                                                           authz.Status == "valid" && authz.Expires > now)
                                   : null;

                authorizations.Add(reused ?? NewAuthorization(account, name, wildcard, now));

            }

            var id    = NewId();
            var order = new ScriptedOrder {
                            Id              = id,
                            URL             = URL("order", id),
                            FinalizeURL     = URL("finalize", id),
                            Account         = account,
                            Identifiers     = identifiers,
                            Authorizations  = authorizations,
                            Expires         = now.AddDays(7),
                            Profile         = profile,
                            Replaces        = RenewalInfo ? replaces : null,
                            Status          = authorizations.All(authz => authz.Status == "valid") ? "ready" : "pending"
                        };

            orders[id] = order;

            return ScriptedAnswer.Json(201, OrderJSON(order), ("Location", order.URL));

        }

    }

    private ScriptedAuthorization NewAuthorization(ScriptedAccount     Account,
                                                   ScriptedIdentifier  Identifier,
                                                   Boolean             Wildcard,
                                                   DateTimeOffset      Now)
    {

        var id            = NewId();
        var challengeList = new List<ScriptedChallenge>();
        var authorization = new ScriptedAuthorization {
                                Id          = id,
                                URL         = URL("authz", id),
                                Account     = Account,
                                Identifier  = Identifier,
                                Wildcard    = Wildcard,
                                Challenges  = challengeList,
                                Expires     = Now.AddDays(7)
                            };

        foreach (var type in ChallengeTypes(Identifier, Wildcard))
        {

            var challengeId = NewId();
            var challenge   = new ScriptedChallenge {
                                  Id             = challengeId,
                                  URL            = URL("challenge", challengeId),
                                  Type           = type,
                                  Token          = TokenFor?.Invoke(type) ?? RawBase64Url.Encode(RandomNumberGenerator.GetBytes(32)),
                                  Authorization  = authorization
                              };

            challengeList.Add(challenge);
            challenges[challengeId] = challenge;

        }

        authzs[id] = authorization;

        return authorization;

    }

    private static String Timestamp(DateTimeOffset Time)
        => Time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>An order as the server writes it (RFC 8555, section 7.1.3).</summary>
    public static JsonObject OrderJSON(ScriptedOrder Order)
    {

        var json = new JsonObject {
                       ["status"]          = Order.Status,
                       ["expires"]         = Timestamp(Order.Expires),
                       ["identifiers"]     = new JsonArray([ .. Order.Identifiers.Select(identifier => identifier.ToJSON()) ]),
                       ["authorizations"]  = new JsonArray([ .. Order.Authorizations.Select(authz => JsonValue.Create(authz.URL)) ]),
                       ["finalize"]        = Order.FinalizeURL
                   };

        if (Order.Profile is not null)
            json["profile"] = Order.Profile;

        if (Order.Replaces is not null)
            json["replaces"] = Order.Replaces;

        if (Order.Certificate is not null && Order.Status == "valid")
            json["certificate"] = Order.Certificate.URL;

        if (Order.Error is not null)
            json["error"] = Order.Error.DeepClone();

        return json;

    }

    #endregion

    #region Order(Request, Id) - section 7.1.3

    private ScriptedAnswer Order(ACMERequest Request, String Id)
    {

        lock (gate)
        {

            if (!orders.TryGetValue(Id, out var order) || order.Account != Request.Account)
                return ScriptedAnswer.Problem(403, "unauthorized", "Not this account's order.");

            if (order.Status == "processing")
            {
                if (order.PollsLeft > 0)
                    order.PollsLeft--;
                if (order.PollsLeft == 0)
                    Issue(order);
            }

            var answer = ScriptedAnswer.Json(200, OrderJSON(order));

            return order.Status is "processing" or "pending" && PollRetryAfter is not null
                       ? answer.With("Retry-After", PollRetryAfter)
                       : answer;

        }

    }

    #endregion

    #region Authorization(Request, Id) - sections 7.1.4, 7.5, 7.5.2

    private ScriptedAnswer Authorization(ACMERequest Request, String Id)
    {

        lock (gate)
        {

            if (!authzs.TryGetValue(Id, out var authorization) || authorization.Account != Request.Account)
                return ScriptedAnswer.Problem(403, "unauthorized", "Not this account's authorization.");

            if (Request.PayloadObject is JsonObject payload)
            {

                if (payload["status"]?.GetValue<String>() != "deactivated")
                    return ScriptedAnswer.Problem(400, "malformed", "An authorization is changed only to \"deactivated\" (RFC 8555, section 7.5.2).");

                authorization.Status = "deactivated";
                Settle(authorization);

            }
            else if (authorization.Status == "pending")
            {
                if (authorization.PollsLeft > 0)
                    authorization.PollsLeft--;
                Finish(authorization);
            }

            var answer = ScriptedAnswer.Json(200, AuthorizationJSON(authorization));

            return authorization.Status == "pending" && PollRetryAfter is not null && authorization.Challenges.Any(challenge => challenge.RespondedAt is not null)
                       ? answer.With("Retry-After", PollRetryAfter)
                       : answer;

        }

    }

    /// <summary>An authorization as the server writes it (RFC 8555, section 7.1.4).</summary>
    public static JsonObject AuthorizationJSON(ScriptedAuthorization Authorization)
    {

        var json = new JsonObject {
                       ["identifier"]  = Authorization.Identifier.ToJSON(),
                       ["status"]      = Authorization.Status,
                       ["expires"]     = Timestamp(Authorization.Expires),
                       ["challenges"]  = new JsonArray([ .. Authorization.Challenges.Select(ChallengeJSON) ])
                   };

        if (Authorization.Wildcard)
            json["wildcard"] = true;

        return json;

    }

    /// <summary>A challenge as the server writes it (RFC 8555, section 7.1.5).</summary>
    public static JsonObject ChallengeJSON(ScriptedChallenge Challenge)
    {

        var json = new JsonObject {
                       ["type"]    = Challenge.Type,
                       ["url"]     = Challenge.URL,
                       ["status"]  = Challenge.Status,
                       ["token"]   = Challenge.Token
                   };

        if (Challenge.Validated is DateTimeOffset validated)
            json["validated"] = Timestamp(validated);

        if (Challenge.Error is not null)
            json["error"] = Challenge.Error.DeepClone();

        return json;

    }

    #endregion

    #region ChallengeAsync(Request, Id) - sections 7.5.1, 8

    private async Task<ScriptedAnswer> ChallengeAsync(ACMERequest Request, String Id)
    {

        ScriptedChallenge challenge;

        lock (gate)
        {

            if (!challenges.TryGetValue(Id, out var known) || known.Authorization.Account != Request.Account)
                return ScriptedAnswer.Problem(403, "unauthorized", "Not this account's challenge.");

            challenge = known;

            if (Request.PostAsGet || challenge.Status != "pending" || challenge.Authorization.Status != "pending")
                return ScriptedAnswer.Json(200, ChallengeJSON(challenge), ("Link", $"<{challenge.Authorization.URL}>;rel=\"up\""));

            // Section 7.5.1: "the client sends an empty JSON body ("{}")".
            if (Request.PayloadObject is not JsonObject { Count: 0 })
                return ScriptedAnswer.Problem(400, "malformed", $"The response to a challenge is an empty object, not {Request.PayloadJSON}.");

            challenge.Status                  = "processing";
            challenge.RespondedAt             = Now();
            challenge.Authorization.PollsLeft = AuthorizationProcessingPolls;

        }

        _ = Task.Run(() => ValidateAsync(challenge));

        await Task.Yield();

        lock (gate)
            return ScriptedAnswer.Json(200, ChallengeJSON(challenge), ("Link", $"<{challenge.Authorization.URL}>;rel=\"up\""));

    }

    private async Task ValidateAsync(ScriptedChallenge Challenge)
    {

        try
        {

            if (ValidationDelay > TimeSpan.Zero)
                await Task.Delay(ValidationDelay, stop.Token);

            var keyAuthorization = RawChallenge.KeyAuthorization(Challenge.Token, Challenge.Authorization.Account.Key);
            var started          = DateTimeOffset.UtcNow;

            var (valid, detail)  = Validate is not null
                                       ? await Validate(Challenge, keyAuthorization)
                                       : Challenge.Type switch {
                                             "http-01" => await HTTP01Async(Challenge, keyAuthorization),
                                             "dns-01"  => DNS01(Challenge, keyAuthorization),
                                             _         => (false, $"{Challenge.Type} is not validated by this server.")
                                         };

            Validations.Enqueue(new ScriptedValidation(Challenge, started, valid, detail));

            lock (gate)
            {
                Challenge.Result = (valid, detail);
                Finish(Challenge.Authorization);
            }

        }
        catch (OperationCanceledException) { }

    }

    private async Task<(Boolean, String)> HTTP01Async(ScriptedChallenge  Challenge,
                                                      String             KeyAuthorization)
    {

        var identifier = Challenge.Authorization.Identifier;
        var v6         = identifier.Type == "ip" && identifier.Value.Contains(':');
        var address    = identifier.Type == "ip" ? (v6 ? $"[{identifier.Value}]" : identifier.Value) : "127.0.0.1";
        var url        = $"http://{address}:{HTTP01Port}{RawChallenge.HTTP01Path(Challenge.Token)}";

        try
        {

            using var http    = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 }) { Timeout = TimeSpan.FromSeconds(10) };
            using var request = new HttpRequestMessage(HttpMethod.Get, url);

            // RFC 8555, section 8.3: the Host of the name; RFC 8738, section 7: the address.
            request.Headers.Host = identifier.Type == "ip" ? (v6 ? $"[{identifier.Value}]" : identifier.Value) : identifier.Value;

            using var response = await http.SendAsync(request, stop.Token);
            var       body     = await response.Content.ReadAsStringAsync(stop.Token);

            if (!response.IsSuccessStatusCode)
                return (false, $"{url} answered {(Int32) response.StatusCode}.");

            return body.TrimEnd() == KeyAuthorization
                       ? (true,  $"{url} answered the key authorization.")
                       : (false, $"{url} answered '{(body.Length > 200 ? body[..200] : body)}', not the key authorization.");

        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            return (false, $"{url} could not be fetched: {e.Message}");
        }

    }

    private (Boolean, String) DNS01(ScriptedChallenge  Challenge,
                                    String             KeyAuthorization)
    {

        var name   = RawChallenge.DNS01Name(Challenge.Authorization.Identifier.Value);
        var digest = RawChallenge.DNS01Value(KeyAuthorization);

        return Zone.TryGetValue(name, out var values) && values.ContainsKey(digest)
                   ? (true,  $"{name} has the digest.")
                   : (false, $"{name} has no TXT record of the digest; it has {(values is null ? "none" : String.Join(", ", values.Keys))}.");

    }

    /// <summary>
    /// The result of a validation applied - once the polls the authorization
    /// is to stay pending for are over.
    /// </summary>
    private void Finish(ScriptedAuthorization Authorization)
    {

        if (Authorization.Status != "pending" || Authorization.PollsLeft > 0)
            return;

        var challenge = Authorization.Challenges.FirstOrDefault(candidate => candidate.Result is not null && candidate.Status == "processing");

        if (challenge is null)
            return;

        var (valid, detail) = challenge.Result!.Value;

        if (valid)
        {
            challenge.Status      = "valid";
            challenge.Validated   = Now();
            Authorization.Status  = "valid";
            Authorization.Expires = Now().AddDays(30);
        }
        else
        {
            challenge.Status      = "invalid";
            challenge.Error       = new JsonObject { ["type"] = ScriptedAnswer.ErrorPrefix + "incorrectResponse", ["detail"] = detail, ["status"] = 403 };
            Authorization.Status  = "invalid";
        }

        Settle(Authorization);

    }

    /// <summary>
    /// The orders of an authorization that changed: ready when all of theirs
    /// are valid, invalid when one is not to be won any more.
    /// </summary>
    private void Settle(ScriptedAuthorization Authorization)
    {

        foreach (var order in orders.Values.Where(order => order.Authorizations.Contains(Authorization) && order.Status == "pending"))
        {

            if (order.Authorizations.All(authz => authz.Status == "valid"))
                order.Status = "ready";

            else if (order.Authorizations.FirstOrDefault(authz => authz.Status is "invalid" or "deactivated" or "revoked" or "expired") is ScriptedAuthorization failed)
            {
                order.Status = "invalid";
                order.Error  = new JsonObject {
                                   ["type"]   = ScriptedAnswer.ErrorPrefix + "unauthorized",
                                   ["detail"] = $"The authorization of {failed.Identifier.Value} is {failed.Status}.",
                                   ["status"] = 403
                               };
            }

        }

    }

    #endregion

    #region Finalize(Request, Id) - section 7.4

    private ScriptedAnswer Finalize(ACMERequest Request, String Id)
    {

        lock (gate)
        {

            if (!orders.TryGetValue(Id, out var order) || order.Account != Request.Account)
                return ScriptedAnswer.Problem(403, "unauthorized", "Not this account's order.");

            if (order.Status != "ready")
                return ScriptedAnswer.Problem(403, "orderNotReady", $"The order is {order.Status}, not ready.");

            if (Request.PayloadObject?["csr"]?.GetValue<String>() is not String text ||
                !RawBase64Url.TryDecode(text, out var der, out var whyNot))
                return ScriptedAnswer.Problem(400, "malformed", "\"csr\" is a CSR in base64url without padding (RFC 8555, sections 5 and 7.4).");

            ScriptedCSR csr;

            try
            {
                csr = ReadCSR(der);
            }
            catch (Exception e) when (e is CryptographicException or AsnContentException or InvalidOperationException or ArgumentException)
            {
                return ScriptedAnswer.Problem(400, "badCSR", $"The CSR cannot be read: {e.Message}");
            }

            order.CSR = csr;

            var asked = order.Identifiers.Select(identifier => identifier.ToString()).ToHashSet();
            var given = csr.Names.Select(identifier => identifier.ToString()).ToHashSet();

            if (!asked.SetEquals(given))
                return ScriptedAnswer.Problem(400, "badCSR", $"The CSR is for {String.Join(", ", given)}, the order for {String.Join(", ", asked)}.");

            if (csr.CommonName is not null && !given.Contains($"dns:{csr.CommonName.ToLowerInvariant()}") && !given.Contains($"ip:{csr.CommonName}"))
                return ScriptedAnswer.Problem(400, "badCSR", $"The common name {csr.CommonName} is none of the subject alternative names.");

            if (accounts.Values.Any(account => account.Key.Thumbprint == csr.JWK.Thumbprint))
                return ScriptedAnswer.Problem(400, "badCSR", "The key of the CSR is an account key (RFC 8555, section 11.1).");

            if (OrderProcessingPolls > 0)
            {
                order.Status    = "processing";
                order.PollsLeft = OrderProcessingPolls;
            }
            else
                Issue(order);

            var answer = ScriptedAnswer.Json(200, OrderJSON(order), ("Location", order.URL));

            return order.Status == "processing" && PollRetryAfter is not null
                       ? answer.With("Retry-After", PollRetryAfter)
                       : answer;

        }

    }

    /// <summary>
    /// A CSR read with .NET, its signature checked: the names, the common
    /// name, the key and the signature algorithm.
    /// </summary>
    public static ScriptedCSR ReadCSR(Byte[] DER)
    {

        // The extensions - the names - are read only when asked for; the signature is checked all the same.
        var request = CertificateRequest.LoadSigningRequest(DER, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions, RSASignaturePadding.Pkcs1);
        var names   = new List<ScriptedIdentifier>();

        foreach (var extension in request.CertificateExtensions)
        {
            if (extension.Oid?.Value == "2.5.29.17")
            {
                var san = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
                names.AddRange(san.EnumerateDnsNames().   Select(name    => new ScriptedIdentifier("dns", name.ToLowerInvariant())));
                names.AddRange(san.EnumerateIPAddresses().Select(address => new ScriptedIdentifier("ip",  address.ToString())));
            }
        }

        var commonName = request.SubjectName.EnumerateRelativeDistinguishedNames().
                                             FirstOrDefault(rdn => rdn.GetSingleElementType().Value == "2.5.4.3")?.
                                             GetSingleElementValue();

        // The signature algorithm: the second element of CertificationRequest (RFC 2986, section 4.2).
        var reader    = new AsnReader(DER, AsnEncodingRules.DER).ReadSequence();
        reader.ReadEncodedValue();
        var algorithm = reader.ReadSequence().ReadObjectIdentifier();

        using var ec  = request.PublicKey.GetECDsaPublicKey();
        using var rsa = ec is null ? request.PublicKey.GetRSAPublicKey() : null;

        AsymmetricAlgorithm key = (AsymmetricAlgorithm?) ec ?? rsa ?? throw new CryptographicException($"The key of the CSR is {request.PublicKey.Oid.FriendlyName}, neither EC nor RSA.");

        return new ScriptedCSR(DER,
                               names,
                               commonName,
                               ec is not null ? "EC" : "RSA",
                               key.KeySize,
                               ec is not null ? RawJWK.CurveOf(ec.ExportParameters(false).Curve).Name : null,
                               algorithm,
                               request.PublicKey,
                               RawJWK.Of(key));

    }

    private void Issue(ScriptedOrder Order)
    {

        var csr        = Order.CSR!;
        var commonName = csr.CommonName;
        var now        = Now();
        var leaf       = CA.Issue(csr.PublicKey,
                                  Order.Identifiers.Select(identifier => (identifier.Type, identifier.Value)),
                                  now.AddMinutes(-1),
                                  now + CertificateLifetime,
                                  commonName);

        var id          = NewId();
        var certificate = new ScriptedCertificate {
                              Id        = id,
                              URL       = URL("certificate", id),
                              Leaf      = leaf,
                              ChainPEM  = CA.ChainPem(leaf),
                              Account   = Order.Account,
                              Order     = Order,
                              ARIId     = RawARI.CertificateId(leaf.RawData)!
                          };

        for (var alternate = 1; alternate <= AlternateChains; alternate++)
            certificate.Alternates.Add(URL("alternate", $"{id}-{alternate}"));

        if (RewriteChain is not null)
            certificate.ChainPEM = RewriteChain(certificate, certificate.ChainPEM);

        certs[id]         = certificate;
        Order.Certificate = certificate;
        Order.Status      = "valid";

    }

    #endregion

    #region CertificateOf(Request, Id, Alternate) - section 7.4.2

    private ScriptedAnswer CertificateOf(ACMERequest Request, String Id, Int32? Alternate)
    {

        lock (gate)
        {

            if (!certs.TryGetValue(Id, out var certificate) || certificate.Account != Request.Account)
                return ScriptedAnswer.Problem(403, "unauthorized", "Not this account's certificate.");

            if (!Request.PostAsGet)
                return ScriptedAnswer.Problem(400, "malformed", "A certificate is fetched by POST-as-GET (RFC 8555, section 7.4.2).");

            var answer = new ScriptedAnswer(200,
                                            Alternate is null ? certificate.ChainPEM : CA.AlternateChainPem(certificate.Leaf),
                                            "application/pem-certificate-chain");

            foreach (var alternate in certificate.Alternates)
                answer = answer.With("Link", $"<{alternate}>;rel=\"alternate\"");

            return answer;

        }

    }

    #endregion

    #region Revoke(Request) - section 7.6

    private ScriptedAnswer Revoke(ACMERequest Request)
    {

        if (Request.PayloadObject?["certificate"]?.GetValue<String>() is not String text ||
            !RawBase64Url.TryDecode(text, out var der, out _))
            return ScriptedAnswer.Problem(400, "malformed", "\"certificate\" is a certificate in base64url.");

        var reason = Request.PayloadObject["reason"] is JsonValue value && value.TryGetValue<Int32>(out var code) ? code : (Int32?) null;

        lock (gate)
        {

            var certificate = certs.Values.FirstOrDefault(candidate => candidate.DER.AsSpan().SequenceEqual(der));

            if (certificate is null)
                return ScriptedAnswer.Problem(404, "malformed", "There is no such certificate of this server.");

            if (Request.Account is not null)
            {
                if (certificate.Account != Request.Account)
                    return ScriptedAnswer.Problem(403, "unauthorized", "The certificate is another account's.");
            }
            else
            {
                using var key = (AsymmetricAlgorithm?) certificate.Leaf.GetECDsaPublicKey() ?? certificate.Leaf.GetRSAPublicKey()!;
                if (RawJWK.Of(key).Thumbprint != RawJWK.Parse(Request.JWK!.ToJsonString()).Thumbprint)
                    return ScriptedAnswer.Problem(403, "unauthorized", "The \"jwk\" is not the certificate's key.");
            }

            if (certificate.Revoked)
                return ScriptedAnswer.Problem(400, "alreadyRevoked", "The certificate is revoked already.");

            if (reason is not null and not (0 or 1 or 3 or 4 or 5))
                return ScriptedAnswer.Problem(400, "badRevocationReason", $"The reason {reason} is not taken.");

            certificate.Revoked = true;
            certificate.Reason  = reason;

            return new ScriptedAnswer(200);

        }

    }

    #endregion

    #region RenewalInfoOf(Id) - RFC 9773, section 4

    private ScriptedAnswer RenewalInfoOf(String Id)
    {

        var parts = Id.Split('.');

        if (parts.Length != 2 || !RawBase64Url.TryDecode(parts[0], out _, out _) || !RawBase64Url.TryDecode(parts[1], out _, out _))
            return ScriptedAnswer.Problem(400, "malformed", $"'{Id}' is no certificate identifier of RFC 9773, section 4.1.");

        ScriptedCertificate? certificate;

        lock (gate)
            certificate = certs.Values.FirstOrDefault(candidate => candidate.ARIId == Id);

        if (certificate is null)
            return ScriptedAnswer.Problem(404, "malformed", $"There is no certificate '{Id}' here.");

        var notBefore = new DateTimeOffset(certificate.Leaf.NotBefore.ToUniversalTime());
        var notAfter  = new DateTimeOffset(certificate.Leaf.NotAfter. ToUniversalTime());
        var lifetime  = notAfter - notBefore;

        var (start, end) = RenewalWindow?.Invoke(certificate)
                               ?? (certificate.Revoked
                                       ? (Now().AddHours(-1), Now())
                                       : (notAfter - lifetime / 3, notAfter - lifetime / 6));

        var json = new JsonObject {
                       ["suggestedWindow"] = new JsonObject {
                                                 ["start"] = Timestamp(start),
                                                 ["end"]   = Timestamp(end)
                                             }
                   };

        if (RenewalExplanationURL is not null)
            json["explanationURL"] = RenewalExplanationURL;

        var answer = ScriptedAnswer.Json(200, json);

        return RenewalRetryAfter is not null
                   ? answer.With("Retry-After", RenewalRetryAfter)
                   : answer;

    }

    #endregion


    #region DisposeAsync()

    private Int32 disposed;

    public async ValueTask DisposeAsync()
    {

        if (Interlocked.Exchange(ref disposed, 1) == 1)
            return;

        await stop.CancelAsync();
        listener.Stop();

        try
        {
            await loop.WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch { /* a loop stuck in accept goes with the process */ }

        CA.Dispose();
        stop.Dispose();

    }

    #endregion

}
