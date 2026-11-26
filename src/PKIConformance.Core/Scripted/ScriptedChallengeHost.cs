using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PKIConformance.Core.Scripted;

/// <summary>
/// A request the host was sent: what a validator asked, and how.
/// </summary>
public sealed record HostRequest(String                                Method,
                                 String                                Target,
                                 String?                               Host,
                                 IReadOnlyDictionary<String, String>   Headers,
                                 IPEndPoint                            Local,
                                 IPEndPoint                            Remote,
                                 DateTimeOffset                        At)
{

    /// <summary>The path of the request target, without a query.</summary>
    public String Path
        => Target.Split('?')[0];

}

/// <summary>
/// What the host answers a request: a status, header fields and a body - or
/// raw octets, or nothing at all for as long as it takes.
/// </summary>
/// <param name="Status">The status code.</param>
/// <param name="Body">The body.</param>
/// <param name="Headers">More header fields, verbatim.</param>
/// <param name="Delay">How long to wait before answering.</param>
/// <param name="Raw">The octets of the whole answer, sent as they are instead of all the above.</param>
/// <param name="Hang">Never answer, and keep the connection open until the host stops.</param>
public sealed record HostAnswer(Int32                                     Status   = 200,
                                Byte[]?                                   Body     = null,
                                IReadOnlyList<(String Name, String Value)>? Headers  = null,
                                TimeSpan                                  Delay    = default,
                                Byte[]?                                   Raw      = null,
                                Boolean                                   Hang     = false)
{

    /// <summary>The text as the body, ASCII, as application/octet-stream as RFC 8555, section 8.3, shows it.</summary>
    public static HostAnswer Text(String Body, Int32 Status = 200)
        => new (Status, Encoding.ASCII.GetBytes(Body), [ ("Content-Type", "application/octet-stream") ]);

    /// <summary>A redirect to the location.</summary>
    public static HostAnswer Redirect(String Location, Int32 Status = 302)
        => new (Status, [], [ ("Location", Location) ]);

    /// <summary>404, nothing here.</summary>
    public static HostAnswer NotFound
        => new (404, Encoding.ASCII.GetBytes("not found"), [ ("Content-Type", "text/plain") ]);

}

/// <summary>
/// The web server of the names a test proves by http-01 (RFC 8555, section
/// 8.3): a small HTTP/1.1 server of its own on the loopback addresses - 127.0.0.1
/// and ::1 on the same port - that answers what the test scripted, and keeps
/// every request it was sent.
/// </summary>
/// <remarks>
/// <para>
/// It is written here on a <see cref="TcpListener"/>, not on Hermod's HTTP
/// server and not on Kestrel: what it is to answer is exactly what a test
/// says - a body of 9000 bytes, a redirect in a loop, a status line that is
/// none, an answer that never comes - and what it was asked is exactly what
/// came over the wire.
/// </para>
/// <para>
/// The server under test is started with its http-01 port set to
/// <see cref="Port"/>, which is why the host is made before the server.
/// </para>
/// </remarks>
public sealed class ScriptedChallengeHost : IAsyncDisposable
{

    #region Data

    private const    Int32                                                 MaxHead   = 16 * 1024;

    private readonly List<TcpListener>                                     listeners = [];
    private readonly CancellationTokenSource                               stop      = new();
    private readonly List<Task>                                            loops     = [];
    private readonly ConcurrentDictionary<String, Func<HostRequest, HostAnswer>> routes = new(StringComparer.Ordinal);

    #endregion

    #region Properties

    /// <summary>The port, the same on 127.0.0.1 and on ::1.</summary>
    public UInt16                         Port       { get; }

    /// <summary>Whether ::1 is listened on as well.</summary>
    public Boolean                        IPv6       { get; }

    /// <summary>Every request, in the order they came.</summary>
    public ConcurrentQueue<HostRequest>   Requests   { get; } = new();

    /// <summary>What is answered where no route is scripted: 404.</summary>
    public Func<HostRequest, HostAnswer>  Fallback   { get; set; } = _ => HostAnswer.NotFound;

    #endregion

    #region Constructor(s)

    private ScriptedChallengeHost(UInt16              Port,
                                  IEnumerable<TcpListener> Listeners)
    {

        this.Port  = Port;
        this.listeners.AddRange(Listeners);
        this.IPv6  = listeners.Count > 1;

        foreach (var listener in listeners)
            loops.Add(Task.Run(() => AcceptLoop(listener)));

    }

    /// <summary>
    /// A host on a port that is free on both loopback addresses.
    /// </summary>
    public static ScriptedChallengeHost Start()
    {

        for (var attempt = 0; attempt < 20; attempt++)
        {

            var v4 = new TcpListener(IPAddress.Loopback, 0);
            v4.Start();

            var port = (UInt16) ((IPEndPoint) v4.LocalEndpoint).Port;

            if (!Socket.OSSupportsIPv6)
                return new ScriptedChallengeHost(port, [ v4 ]);

            try
            {
                var v6 = new TcpListener(IPAddress.IPv6Loopback, port);
                v6.Start();
                return new ScriptedChallengeHost(port, [ v4, v6 ]);
            }
            catch (SocketException)
            {
                v4.Stop();
            }

        }

        throw new InvalidOperationException("No port is free on both 127.0.0.1 and ::1.");

    }

    #endregion


    #region Provision(Token, KeyAuthorization) / Answer(Path, Answer) / AnswerChallenge(Token, Answer) / Forget(Path)

    /// <summary>
    /// The path of a token's key authorization (RFC 8555, section 8.3).
    /// </summary>
    public static String ChallengePath(String Token)
        => $"/.well-known/acme-challenge/{Token}";

    /// <summary>
    /// Serve the key authorization at the path of the token - as a client of
    /// ACME should.
    /// </summary>
    public void Provision(String  Token,
                          String  KeyAuthorization)

        => routes[ChallengePath(Token)] = _ => HostAnswer.Text(KeyAuthorization);

    /// <summary>
    /// Answer requests of the path as the test says.
    /// </summary>
    public void Answer(String                         Path,
                       Func<HostRequest, HostAnswer>  Answer)

        => routes[Path] = Answer;

    /// <summary>
    /// Answer requests of the path of a token as the test says.
    /// </summary>
    public void AnswerChallenge(String                         Token,
                                Func<HostRequest, HostAnswer>  Answer)

        => routes[ChallengePath(Token)] = Answer;

    /// <summary>
    /// The requests of a path.
    /// </summary>
    public IReadOnlyList<HostRequest> RequestsOf(String Path)
        => [.. Requests.Where(request => request.Path == Path)];

    #endregion


    #region (private) AcceptLoop(Listener) / ServeAsync(Client)

    private async Task AcceptLoop(TcpListener Listener)
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                var client = await Listener.AcceptTcpClientAsync(stop.Token);
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

                var stream  = Client.GetStream();
                var head    = await ReadHeadAsync(stream);

                if (head is null)
                    return;

                var lines   = head.Split("\r\n");
                var request = lines[0].Split(' ');

                if (request.Length < 3)
                    return;

                var headers = new Dictionary<String, String>(StringComparer.OrdinalIgnoreCase);

                foreach (var line in lines.Skip(1).Where(line => line.Length > 0))
                {
                    var colon = line.IndexOf(':');
                    if (colon > 0)
                        headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
                }

                var asked   = new HostRequest(request[0],
                                              request[1],
                                              headers.TryGetValue("Host", out var host) ? host : null,
                                              headers,
                                              (IPEndPoint) Client.Client.LocalEndPoint!,
                                              (IPEndPoint) Client.Client.RemoteEndPoint!,
                                              DateTimeOffset.UtcNow);

                Requests.Enqueue(asked);

                var answer  = (routes.TryGetValue(asked.Path, out var route) ? route : Fallback)(asked);

                if (answer.Hang)
                {
                    await Task.Delay(Timeout.Infinite, stop.Token);
                    return;
                }

                if (answer.Delay > TimeSpan.Zero)
                    await Task.Delay(answer.Delay, stop.Token);

                if (answer.Raw is not null)
                {
                    await stream.WriteAsync(answer.Raw, stop.Token);
                    return;
                }

                var body    = answer.Body ?? [];
                var text    = new StringBuilder();

                text.Append($"HTTP/1.1 {answer.Status} {ReasonOf(answer.Status)}\r\n");
                text.Append($"Content-Length: {body.Length}\r\n");
                text.Append("Connection: close\r\n");

                foreach (var (name, value) in answer.Headers ?? [])
                    text.Append($"{name}: {value}\r\n");

                text.Append("\r\n");

                await stream.WriteAsync(Encoding.ASCII.GetBytes(text.ToString()), stop.Token);

                if (asked.Method != "HEAD")
                    await stream.WriteAsync(body, stop.Token);

            }
            catch (OperationCanceledException) { }
            catch (IOException)                { }
            catch (SocketException)            { }
        }

    }

    private async Task<String?> ReadHeadAsync(NetworkStream Stream)
    {

        var buffer = new Byte[MaxHead];
        var length = 0;

        while (length < buffer.Length)
        {

            var read = await Stream.ReadAsync(buffer.AsMemory(length), stop.Token);

            if (read == 0)
                return null;

            length += read;

            var text = Encoding.ASCII.GetString(buffer, 0, length);
            var end  = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);

            if (end >= 0)
                return text[..end];

        }

        return null;

    }

    private static String ReasonOf(Int32 Status)

        => Status switch {
               200 => "OK",
               204 => "No Content",
               301 => "Moved Permanently",
               302 => "Found",
               303 => "See Other",
               307 => "Temporary Redirect",
               308 => "Permanent Redirect",
               403 => "Forbidden",
               404 => "Not Found",
               500 => "Internal Server Error",
               _   => "Status"
           };

    #endregion


    #region DisposeAsync()

    public async ValueTask DisposeAsync()
    {

        await stop.CancelAsync();

        foreach (var listener in listeners)
            listener.Stop();

        try
        {
            await Task.WhenAll(loops).WaitAsync(TimeSpan.FromSeconds(2));
        }
        catch { /* a loop stuck in accept goes with the process */ }

        stop.Dispose();

    }

    #endregion

}
