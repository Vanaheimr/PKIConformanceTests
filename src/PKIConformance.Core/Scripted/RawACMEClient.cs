using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Servers;

namespace PKIConformance.Core.Scripted;

/// <summary>
/// The protected header of a JWS as it is put together: its members in the
/// order they are given, each already JSON - so that a test can leave one out,
/// put one in twice over, or say what no client would.
/// </summary>
public sealed class JWSHeader
{

    private readonly List<(String Name, String JSON)> members = [];

    /// <summary>
    /// Set a member to a JSON value - where it is, or at the end.
    /// </summary>
    public JWSHeader Set(String Name, String JSONValue)
    {

        var index = members.FindIndex(member => member.Name == Name);

        if (index >= 0)
            members[index] = (Name, JSONValue);
        else
            members.Add((Name, JSONValue));

        return this;

    }

    /// <summary>
    /// Set a member to a string.
    /// </summary>
    public JWSHeader SetString(String Name, String Value)
        => Set(Name, RawJson.Quote(Value));

    /// <summary>
    /// Take a member away.
    /// </summary>
    public JWSHeader Remove(String Name)
    {
        members.RemoveAll(member => member.Name == Name);
        return this;
    }

    /// <summary>
    /// The JSON value of a member, or null.
    /// </summary>
    public String? this[String Name]
        => members.FirstOrDefault(member => member.Name == Name).JSON;

    /// <summary>
    /// The header as JSON text, without whitespace.
    /// </summary>
    public String ToJSON()
        => RawJson.Object([.. members]);

}

/// <summary>
/// An account of an ACME server as the raw client holds it: its key, and its
/// URL - the "kid" of every request after the first.
/// </summary>
public sealed record RawACMEAccount(RawKey  Key,
                                    String  URL);

/// <summary>
/// An order as the raw client was last told it.
/// </summary>
public sealed record RawACMEOrder(String      URL,
                                  JsonObject  JSON)
{

    public String                 Status          => JSON["status"]?.GetValue<String>() ?? "";
    public String                 Finalize        => JSON["finalize"]?.GetValue<String>() ?? "";
    public String?                Certificate     => JSON["certificate"]?.GetValue<String>();
    public IReadOnlyList<String>  Authorizations  => [.. (JSON["authorizations"] as JsonArray ?? []).Select(node => node!.GetValue<String>())];

}

/// <summary>
/// A certificate of ACME as the raw client got it: the order, the PEM chain
/// as it came, and the key of its CSR.
/// </summary>
public sealed record RawACMEIssued(RawACMEOrder         Order,
                                   String               CertificateURL,
                                   String               ChainPEM,
                                   AsymmetricAlgorithm  CertificateKey)
{

    /// <summary>The certificates of the chain, leaf first, as DER.</summary>
    public IReadOnlyList<Byte[]> Chain
        => [.. PEMBlocks(ChainPEM)];

    /// <summary>The leaf, as DER.</summary>
    public Byte[] LeafDER
        => Chain[0];

    private static IEnumerable<Byte[]> PEMBlocks(String PEM)
    {

        const String begin = "-----BEGIN CERTIFICATE-----";
        const String end   = "-----END CERTIFICATE-----";

        var at = 0;

        while ((at = PEM.IndexOf(begin, at, StringComparison.Ordinal)) >= 0)
        {
            var stop = PEM.IndexOf(end, at, StringComparison.Ordinal);
            if (stop < 0)
                yield break;
            yield return Convert.FromBase64String(PEM[(at + begin.Length)..stop]);
            at = stop + end.Length;
        }

    }

}


/// <summary>
/// A client of ACME (RFC 8555) written for the suite on the raw codec: it
/// does what a client should where a test asks it to, and anything else
/// where a test asks for that - another Content-Type, a header member left
/// out, a nonce used twice, a URL a byte off, a body that is no JWS.
/// </summary>
/// <remarks>
/// <para>
/// It shares nothing with Hermod's client or the PKI's server: HTTP through
/// .NET's <see cref="HttpClient"/>, JSON through System.Text.Json, JWS and
/// keys through <see cref="RawACME"/>. What it reads of an answer it reads
/// only to go on with a flow; whether an answer is right is the tests' to say.
/// </para>
/// <para>
/// Nonces are pooled from every Replay-Nonce, as RFC 8555, section 6.5,
/// allows, and fetched from newNonce when the pool is empty.
/// </para>
/// </remarks>
public sealed class RawACMEClient : IDisposable
{

    #region Data

    /// <summary>The media type of every request of ACME (RFC 8555, section 6.2).</summary>
    public const String JOSE = "application/jose+json";

    private readonly HttpClient                  http;
    private readonly ConcurrentQueue<String>     nonces     = new();
    private readonly ConcurrentQueue<RawACMEResponse> exchanges = new();

    #endregion

    #region Properties

    /// <summary>The directory URL the client was pointed at.</summary>
    public Uri         DirectoryURL  { get; }

    /// <summary>The directory, as it was read.</summary>
    public JsonObject  Directory     { get; private set; } = [];

    /// <summary>Every answer, in order - the evidence of a failed test.</summary>
    public IReadOnlyCollection<RawACMEResponse> Exchanges
        => exchanges;

    /// <summary>How long a flow waits for a challenge to be looked at.</summary>
    public TimeSpan    PollTimeout   { get; set; } = TimeSpan.FromSeconds(30);

    #endregion

    #region Constructor(s)

    public RawACMEClient(HttpClient  HTTP,
                         Uri         DirectoryURL)
    {
        this.http          = HTTP;
        this.DirectoryURL  = DirectoryURL;
    }

    /// <summary>
    /// A client of the server under test, its directory read.
    /// </summary>
    public static async Task<RawACMEClient> ConnectAsync(IACMEServerUnderTest Server)
    {

        var client     = new RawACMEClient(Server.TLS.NewHttpClient(TimeSpan.FromSeconds(60)), Server.DirectoryURL);
        var directory  = await client.SendAsync(HttpMethod.Get, Server.DirectoryURL.ToString());

        if (directory.Status != 200 || directory.Object is null)
            throw new InvalidOperationException($"The directory of {Server.Name} could not be read: {directory}");

        client.Directory = directory.Object;

        return client;

    }

    #endregion


    #region Resource(Name)

    /// <summary>
    /// The URL of a resource of the directory - "newAccount", say.
    /// </summary>
    public String Resource(String Name)

        => Directory[Name] is JsonValue value && value.GetValueKind() == System.Text.Json.JsonValueKind.String
               ? value.GetValue<String>()
               : throw new InvalidOperationException($"The directory has no \"{Name}\": {Directory.ToJsonString()}");

    #endregion

    #region SendAsync(Method, URL, Body = null, ContentType = JOSE, KeepNonce = true)

    /// <summary>
    /// Send a request as it is given, and take the answer as it comes.
    /// </summary>
    /// <param name="Method">The method.</param>
    /// <param name="URL">The URL.</param>
    /// <param name="Body">The body; none where null.</param>
    /// <param name="ContentType">The Content-Type of the body, verbatim; none where null.</param>
    /// <param name="KeepNonce">Whether the Replay-Nonce of the answer goes into the pool.</param>
    public async Task<RawACMEResponse> SendAsync(HttpMethod  Method,
                                                 String      URL,
                                                 Byte[]?     Body         = null,
                                                 String?     ContentType  = JOSE,
                                                 Boolean     KeepNonce    = true)
    {

        using var request = new HttpRequestMessage(Method, URL);

        if (Body is not null)
        {
            request.Content = new ByteArrayContent(Body);
            if (ContentType is not null)
                request.Content.Headers.TryAddWithoutValidation("Content-Type", ContentType);
        }

        using var response  = await http.SendAsync(request);
        var       body      = await response.Content.ReadAsByteArrayAsync();
        var       headers   = new Dictionary<String, IReadOnlyList<String>>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in response.Headers.Concat(response.Content.Headers))
            headers[header.Key] = [.. header.Value];

        var answer = new RawACMEResponse(Method.Method, URL, (Int32) response.StatusCode, headers, body);

        exchanges.Enqueue(answer);

        if (KeepNonce && answer.ReplayNonce is String nonce && RawBase64Url.TryDecode(nonce, out _, out _))
            nonces.Enqueue(nonce);

        return answer;

    }

    #endregion

    #region NonceAsync() / FreshNonceAsync()

    /// <summary>
    /// A nonce of the pool - or a fresh one from newNonce.
    /// </summary>
    public async Task<String> NonceAsync()

        => nonces.TryDequeue(out var nonce)
               ? nonce
               : await FreshNonceAsync();

    /// <summary>
    /// A fresh nonce, by HEAD of newNonce (RFC 8555, section 7.2).
    /// </summary>
    public async Task<String> FreshNonceAsync()
    {

        var answer = await SendAsync(HttpMethod.Head, Resource("newNonce"), KeepNonce: false);

        return answer.ReplayNonce
                   ?? throw new InvalidOperationException($"newNonce gave no nonce: {answer}");

    }

    /// <summary>
    /// Forget the nonces of the pool.
    /// </summary>
    public void ForgetNonces()
        => nonces.Clear();

    #endregion

    #region SignAsync(Key, KeyId, URL, PayloadJSON, Header = null, SignWith = null)

    /// <summary>
    /// The JWS of a request as RFC 8555, section 6.2, has it - "alg", "jwk" or
    /// "kid", "nonce", "url" - with the header changed as the test says, and
    /// signed by the key or by another one.
    /// </summary>
    /// <param name="Key">The key: its algorithm and, without a key identifier, its JWK.</param>
    /// <param name="KeyId">The account URL; null for the "jwk" of the key.</param>
    /// <param name="URL">The URL the request goes to.</param>
    /// <param name="PayloadJSON">The payload; null for a POST-as-GET.</param>
    /// <param name="Header">How the test changes the protected header.</param>
    /// <param name="SignWith">Another key than the one the header names.</param>
    public async Task<RawJWS> SignAsync(RawKey               Key,
                                        String?              KeyId,
                                        String               URL,
                                        String?              PayloadJSON,
                                        Action<JWSHeader>?   Header    = null,
                                        RawKey?              SignWith  = null)
    {

        var header = new JWSHeader().SetString("alg", Key.Algorithm);

        if (KeyId is null)
            header.Set("jwk", Key.JWK.ToJSON());
        else
            header.SetString("kid", KeyId);

        header.SetString("nonce", await NonceAsync());
        header.SetString("url",   URL);

        Header?.Invoke(header);

        return RawJWS.Sign(SignWith ?? Key, header.ToJSON(), PayloadJSON);

    }

    #endregion

    #region PostAsync(...)

    /// <summary>
    /// POST a JWS signed by the key - with its JWK, or as the account of the
    /// key identifier.
    /// </summary>
    /// <param name="Key">The key.</param>
    /// <param name="KeyId">The account URL; null for the "jwk" of the key.</param>
    /// <param name="URL">The URL.</param>
    /// <param name="PayloadJSON">The payload; null for a POST-as-GET.</param>
    /// <param name="Header">How the test changes the protected header.</param>
    /// <param name="Body">How the test serializes - or spoils - the JWS; flattened JSON where null.</param>
    /// <param name="ContentType">The Content-Type, verbatim.</param>
    /// <param name="SignWith">Another key than the one the header names.</param>
    public async Task<RawACMEResponse> PostAsync(RawKey                 Key,
                                                 String?                KeyId,
                                                 String                 URL,
                                                 String?                PayloadJSON,
                                                 Action<JWSHeader>?     Header       = null,
                                                 Func<RawJWS, String>?  Body         = null,
                                                 String?                ContentType  = JOSE,
                                                 RawKey?                SignWith     = null)
    {

        var jws = await SignAsync(Key, KeyId, URL, PayloadJSON, Header, SignWith);

        return await SendAsync(HttpMethod.Post,
                               URL,
                               Encoding.UTF8.GetBytes(Body is null ? jws.ToFlattenedJSON() : Body(jws)),
                               ContentType);

    }

    /// <summary>
    /// POST a JWS as the account.
    /// </summary>
    public Task<RawACMEResponse> PostAsync(RawACMEAccount         Account,
                                           String                 URL,
                                           String?                PayloadJSON,
                                           Action<JWSHeader>?     Header       = null,
                                           Func<RawJWS, String>?  Body         = null,
                                           String?                ContentType  = JOSE,
                                           RawKey?                SignWith     = null)

        => PostAsync(Account.Key, Account.URL, URL, PayloadJSON, Header, Body, ContentType, SignWith);

    /// <summary>
    /// A POST-as-GET of the account (RFC 8555, section 6.3): the payload empty.
    /// </summary>
    public Task<RawACMEResponse> PostAsGetAsync(RawACMEAccount  Account,
                                                String          URL)

        => PostAsync(Account, URL, null);

    #endregion


    #region NewAccountAsync(Key = null, PayloadJSON = null, Header = null)

    /// <summary>
    /// Ask newAccount for an account of the key - a new key of ES256 where
    /// none is given - with the payload given, or with the terms agreed to.
    /// </summary>
    public async Task<(RawACMEAccount? Account, RawACMEResponse Response)> NewAccountAsync(RawKey?             Key          = null,
                                                                                         String?             PayloadJSON  = null,
                                                                                         Action<JWSHeader>?  Header       = null)
    {

        Key ??= RawKey.Generate("ES256");

        var answer = await PostAsync(Key, null, Resource("newAccount"), PayloadJSON ?? """{"termsOfServiceAgreed":true}""", Header);

        return (answer.Status is 200 or 201 && answer.Location is String location
                    ? new RawACMEAccount(Key, location)
                    : null,
                answer);

    }

    /// <summary>
    /// An account, for a test that arranges with it - or an exception that
    /// says why there is none.
    /// </summary>
    public async Task<RawACMEAccount> AccountAsync(RawKey?  Key          = null,
                                                   String?  PayloadJSON  = null)
    {

        var (account, answer) = await NewAccountAsync(Key, PayloadJSON);

        return account
                   ?? throw new InvalidOperationException($"No account could be opened: {answer}");

    }

    #endregion

    #region NewOrderAsync(Account, Identifiers) / OrderAsync(Account, Identifiers)

    /// <summary>
    /// The JSON of an identifiers array.
    /// </summary>
    public static String IdentifiersJSON(IEnumerable<(String Type, String Value)> Identifiers)

        => "[" + String.Join(",", Identifiers.Select(identifier => RawJson.Object(("type",  RawJson.Quote(identifier.Type)),
                                                                                  ("value", RawJson.Quote(identifier.Value))))) + "]";

    /// <summary>
    /// Ask newOrder for the identifiers.
    /// </summary>
    public Task<RawACMEResponse> NewOrderAsync(RawACMEAccount                         Account,
                                               params (String Type, String Value)[]  Identifiers)

        => PostAsync(Account, Resource("newOrder"), RawJson.Object(("identifiers", IdentifiersJSON(Identifiers))));

    /// <summary>
    /// An order, for a test that arranges with it - or an exception.
    /// </summary>
    public async Task<RawACMEOrder> OrderAsync(RawACMEAccount                         Account,
                                               params (String Type, String Value)[]  Identifiers)
    {

        var answer = await NewOrderAsync(Account, Identifiers);

        return answer.Status == 201 && answer.Location is String location && answer.Object is JsonObject json
                   ? new RawACMEOrder(location, json)
                   : throw new InvalidOperationException($"No order could be placed: {answer}");

    }

    /// <summary>
    /// The order as it stands now.
    /// </summary>
    public async Task<RawACMEOrder> RefreshAsync(RawACMEAccount  Account,
                                                 RawACMEOrder    Order)
    {

        var answer = await PostAsGetAsync(Account, Order.URL);

        return answer.Status == 200 && answer.Object is JsonObject json
                   ? new RawACMEOrder(Order.URL, json)
                   : throw new InvalidOperationException($"The order could not be read: {answer}");

    }

    #endregion

    #region PollAsync(Account, URL, Done)

    /// <summary>
    /// POST-as-GET a resource until the answer is done, or the poll timeout
    /// is up - and the last answer.
    /// </summary>
    public async Task<RawACMEResponse> PollAsync(RawACMEAccount                Account,
                                                 String                        URL,
                                                 Func<RawACMEResponse, Boolean> Done)
    {

        var watch = Stopwatch.StartNew();

        while (true)
        {

            var answer = await PostAsGetAsync(Account, URL);

            if (Done(answer) || watch.Elapsed > PollTimeout)
                return answer;

            await Task.Delay(100);

        }

    }

    /// <summary>
    /// POST-as-GET a resource until its "status" is none of the given ones.
    /// </summary>
    public Task<RawACMEResponse> PollWhileAsync(RawACMEAccount   Account,
                                                String           URL,
                                                params String[]  Statuses)

        => PollAsync(Account, URL, answer => answer.Status != 200 || !Statuses.Contains(answer.StringOf("status")));

    #endregion

    #region ChallengeOf(Authorization, Type)

    /// <summary>
    /// The challenge of the type in an authorization, as (url, token) - or null.
    /// </summary>
    public static (String URL, String Token)? ChallengeOf(RawACMEResponse  Authorization,
                                                         String           Type)
    {

        foreach (var challenge in (Authorization.Object?["challenges"] as JsonArray ?? []).OfType<JsonObject>())
            if (challenge["type"]?.GetValue<String>() == Type &&
                challenge["url"]  ?.GetValue<String>() is String url &&
                challenge["token"]?.GetValue<String>() is String token)
            {
                return (url, token);
            }

        return null;

    }

    #endregion

    #region ProveHTTP01Async(Account, AuthorizationURL, Host)

    /// <summary>
    /// Prove an authorization by http-01: the key authorization provisioned at
    /// the host, the challenge answered with "{}", the authorization polled
    /// until it is not pending any more - and the last answer of it.
    /// </summary>
    public async Task<RawACMEResponse> ProveHTTP01Async(RawACMEAccount         Account,
                                                        String                 AuthorizationURL,
                                                        ScriptedChallengeHost  Host)
    {

        var authorization = await PostAsGetAsync(Account, AuthorizationURL);

        if (authorization.StringOf("status") == "valid")
            return authorization;

        var challenge = ChallengeOf(authorization, "http-01")
                            ?? throw new InvalidOperationException($"The authorization has no http-01: {authorization}");

        Host.Provision(challenge.Token, RawChallenge.KeyAuthorization(challenge.Token, Account.Key.JWK));

        var answer = await PostAsync(Account, challenge.URL, "{}");

        if (answer.Status != 200)
            throw new InvalidOperationException($"The challenge was not taken: {answer}");

        return await PollWhileAsync(Account, AuthorizationURL, "pending");

    }

    #endregion

    #region ReadyOrderAsync(Account, Host, Identifiers)

    /// <summary>
    /// An order whose every authorization was proven by http-01 at the host -
    /// as it stands then, "ready" where all went well.
    /// </summary>
    public async Task<RawACMEOrder> ReadyOrderAsync(RawACMEAccount                         Account,
                                                    ScriptedChallengeHost                  Host,
                                                    params (String Type, String Value)[]  Identifiers)
    {

        var order = await OrderAsync(Account, Identifiers);

        foreach (var authorization in order.Authorizations)
        {
            var proven = await ProveHTTP01Async(Account, authorization, Host);
            if (proven.StringOf("status") != "valid")
                throw new InvalidOperationException($"An authorization was not proven: {proven}");
        }

        var ready = await PollAsync(Account, order.URL, answer => answer.StringOf("status") != "pending");

        return ready.Object is JsonObject json
                   ? new RawACMEOrder(order.URL, json)
                   : throw new InvalidOperationException($"The order could not be read: {ready}");

    }

    #endregion

    #region FinalizeAsync(Account, Order, CSR)

    /// <summary>
    /// Finalize an order with the CSR, base64url.
    /// </summary>
    public Task<RawACMEResponse> FinalizeAsync(RawACMEAccount  Account,
                                               RawACMEOrder    Order,
                                               String          CSRBase64Url)

        => PostAsync(Account, Order.Finalize, RawJson.Object(("csr", RawJson.Quote(CSRBase64Url))));

    #endregion

    #region IssueAsync(Account, Host, Identifiers)

    /// <summary>
    /// A certificate for the identifiers, the whole way: order, http-01 at the
    /// host, a CSR of a new P-256 key, finalize, download - or an exception
    /// that says where it stopped.
    /// </summary>
    public async Task<RawACMEIssued> IssueAsync(RawACMEAccount                         Account,
                                                ScriptedChallengeHost                  Host,
                                                params (String Type, String Value)[]  Identifiers)
    {

        var order     = await ReadyOrderAsync(Account, Host, Identifiers);

        if (order.Status != "ready")
            throw new InvalidOperationException($"The order is not ready: {order.JSON.ToJsonString()}");

        var key       = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var finalize  = await FinalizeAsync(Account, order, RawCSR.CreateBase64Url(key, Identifiers));

        if (finalize.Status != 200)
            throw new InvalidOperationException($"The order was not finalized: {finalize}");

        var done      = await PollAsync(Account, order.URL, answer => answer.StringOf("status") is not ("processing" or "ready"));
        var finished  = new RawACMEOrder(order.URL, done.Object ?? throw new InvalidOperationException($"The order could not be read: {done}"));

        if (finished.Certificate is not String certificateURL)
            throw new InvalidOperationException($"The order has no certificate: {done}");

        var chain     = await PostAsGetAsync(Account, certificateURL);

        if (chain.Status != 200)
            throw new InvalidOperationException($"The certificate could not be downloaded: {chain}");

        return new RawACMEIssued(finished, certificateURL, chain.Text, key);

    }

    #endregion


    #region Dispose()

    public void Dispose()
        => http.Dispose();

    #endregion

}
