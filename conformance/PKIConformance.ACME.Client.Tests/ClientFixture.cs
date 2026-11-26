using System.Collections.Concurrent;
using System.Reflection;

using Microsoft.Extensions.Logging;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.ACME;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// The bench of a test of Hermod's ACME client: <see cref="ScriptedACMEServer"/>,
/// the client's "port 80" - a Hermod HTTP server with Hermod's own http-01
/// responder, the server's http-01 port pointed at it - and Hermod's dns-01
/// responder, writing into the server's zone.
/// </summary>
/// <remarks>
/// The client is Hermod's, and so are its responders; everything that judges
/// them is not: the server checks every request with RawACME, validates with
/// RawACME's key authorization, and issues with .NET.
/// </remarks>
public abstract class ClientFixture
{

    #region Data

    /// <summary>A name of the bench: every name is on the loopback.</summary>
    protected const String Name = "www.acme.test";

    private readonly List<IDisposable> clients = [];

    #endregion

    #region Properties

    /// <summary>The ACME server.</summary>
    protected ScriptedACMEServer          Server       { get; private set; } = null!;

    /// <summary>The client's web server on "port 80".</summary>
    protected HTTPServer                  Port80       { get; private set; } = null!;

    /// <summary>Hermod's http-01 responder, at <see cref="Port80"/>.</summary>
    protected HTTP01ChallengeResponder    HTTP01       { get; private set; } = null!;

    /// <summary>Hermod's dns-01 responder, writing into the server's zone.</summary>
    protected DNS01ChallengeResponder     DNS01        { get; private set; } = null!;

    /// <summary>Every change of the zone the dns-01 responder made: "publish" or "withdraw", name, value.</summary>
    protected ConcurrentQueue<(String What, String Name, String Value)> ZoneChanges { get; } = new();

    /// <summary>Both responders.</summary>
    protected IACMEChallengeResponder[]   Responders
        => [ HTTP01, DNS01 ];

    /// <summary>Every request so far, as evidence.</summary>
    protected String                      Log
        => String.Join("\n", Server.Requests.Select(request => request.ToString()));

    #endregion


    #region Setup / Teardown

    [SetUp]
    public void StartBench()
    {

        ZoneChanges.Clear();

        Port80  = new HTTPServer(IPAddress: IPv4Address.Localhost,
                                 TCPPort:   IPPort.Zero,
                                 AutoStart: true);

        HTTP01  = new HTTP01ChallengeResponder();
        HTTP01.RegisterAt(Port80);

        DNS01   = new DNS01ChallengeResponder(
                      Publish:   (name, value, ct) => {
                                     ZoneChanges.Enqueue(("publish", name, value));
                                     Server.Zone.GetOrAdd(name, _ => new ())[value] = 0;
                                     return Task.CompletedTask;
                                 },
                      Withdraw:  (name, value, ct) => {
                                     ZoneChanges.Enqueue(("withdraw", name, value));
                                     if (Server.Zone.TryGetValue(name, out var values))
                                         values.TryRemove(value, out _);
                                     return Task.CompletedTask;
                                 }
                  );

        UseServer(ScriptedACMEServer.Start());

    }

    [TearDown]
    public async Task StopBench()
    {

        foreach (var client in clients)
            client.Dispose();

        clients.Clear();

        await Port80.DisposeAsync();
        await Server.DisposeAsync();

        // NUnit keeps the fixture for the next test: no server of this one there.
        Server = null!;

    }

    /// <summary>
    /// Have the bench use another server - one with a chain of another
    /// length, say. The one before is stopped.
    /// </summary>
    protected void UseServer(ScriptedACMEServer NewServer)
    {

        var before = Server;

        Server            = NewServer;
        Server.HTTP01Port = Port80.TCPPort.ToUInt16();

        if (before is not null)
            before.DisposeAsync().AsTask().GetAwaiter().GetResult();

    }

    #endregion


    #region Clients

    /// <summary>
    /// A client of the server, with a new account key unless one is given,
    /// polling every tenth of a second.
    /// </summary>
    protected ACMEClient NewClient(ACMEAccountKey?  Key           = null,
                                   TimeProvider?    Clock         = null,
                                   TimeSpan?        PollTimeout   = null,
                                   TimeSpan?        PollInterval  = null)
    {

        var client = new ACMEClient(new Uri(Server.DirectoryURL),
                                    Key ?? ACMEAccountKey.Generate(),
                                    PollInterval: PollInterval ?? TimeSpan.FromMilliseconds(100),
                                    PollTimeout:  PollTimeout  ?? TimeSpan.FromSeconds(20),
                                    TimeProvider: Clock);

        clients.Add(client);

        return client;

    }

    /// <summary>
    /// A client with an account: opened with a contact, the terms agreed.
    /// </summary>
    protected async Task<ACMEClient> ClientWithAccountAsync(ACMEAccountKey?  Key    = null,
                                                            TimeProvider?    Clock  = null,
                                                            TimeSpan?        PollTimeout = null)
    {

        var client = NewClient(Key, Clock, PollTimeout);
        await client.CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);
        return client;

    }

    /// <summary>
    /// A certificate for the names - <see cref="Name"/> by default - by both
    /// responders.
    /// </summary>
    protected Task<ACMECertificate> ObtainAsync(ACMEClient       Client,
                                                params String[]  Names)

        => Client.ObtainCertificateAsync(Names.Length > 0 ? Names : [ Name ], Responders);

    /// <summary>
    /// Have the server take an http-01 answer as Hermod's responder holds it,
    /// without asking over the network - for an address the bench's port 80
    /// does not listen on, as ::1 - and a dns-01 answer from the zone.
    /// </summary>
    protected void ValidateByTheResponder()

        => Server.Validate = (challenge, keyAuthorization) =>
               Task.FromResult(challenge.Type switch {
                                   "http-01" => HTTP01.TryGetKeyAuthorization(challenge.Token, out var served) && served == keyAuthorization,
                                   "dns-01"  => Server.Zone.TryGetValue(RawChallenge.DNS01Name(challenge.Authorization.Identifier.Value), out var values) &&
                                                values.ContainsKey(RawChallenge.DNS01Value(keyAuthorization)),
                                   _         => false
                               }
                                   ? (true,  "the responder holds the answer")
                                   : (false, "the responder holds something else"));

    #endregion

}


/// <summary>
/// What a test tracking a ToDo (PLAN.md, section 2.4) needs: the method or
/// type of a feature, found by its likely names - until it is there, the
/// tracker says which ToDo it waits for.
/// </summary>
internal static class Trackers
{

    /// <summary>A public method of the type by one of the names, or null.</summary>
    public static MethodInfo? Method(Type Type, params String[] Names)

        => Type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static).
                FirstOrDefault(method => Names.Contains(method.Name, StringComparer.Ordinal));

    /// <summary>A public property of the type by one of the names, or null.</summary>
    public static PropertyInfo? Property(Type Type, params String[] Names)

        => Type.GetProperties(BindingFlags.Public | BindingFlags.Instance).
                FirstOrDefault(property => Names.Contains(property.Name, StringComparer.Ordinal));

    /// <summary>A public type of Hermod by one of the names, or null.</summary>
    public static Type? HermodType(params String[] Names)

        => typeof(ACMEClient).Assembly.GetExportedTypes().
                FirstOrDefault(type => Names.Contains(type.Name, StringComparer.Ordinal));

    /// <summary>
    /// Call a method with what its parameters ask for: the given values by
    /// their type, the defaults of the rest - and await it, if it is async.
    /// </summary>
    public static async Task<Object?> InvokeAsync(MethodInfo  Method,
                                                  Object?     Target,
                                                  params Object[] Values)
    {

        var arguments = Method.GetParameters().
                               Select(parameter => Values.FirstOrDefault(value => parameter.ParameterType.IsInstanceOfType(value))
                                                   ?? (parameter.HasDefaultValue ? parameter.DefaultValue : null)).
                               ToArray();

        var result = Method.Invoke(Target, arguments);

        if (result is Task task)
        {
            await task;
            return task.GetType().GetProperty("Result")?.GetValue(task);
        }

        return result;

    }

}


/// <summary>
/// A logger that keeps what it is told - to see what an operator is told.
/// </summary>
internal sealed class ListLogger : ILogger
{

    public ConcurrentQueue<String> Messages { get; } = new();

    public IDisposable? BeginScope<TState>(TState State) where TState : notnull
        => null;

    public Boolean IsEnabled(LogLevel Level)
        => true;

    public void Log<TState>(LogLevel                          Level,
                            EventId                           Event,
                            TState                            State,
                            Exception?                        Exception,
                            Func<TState, Exception?, String>  Formatter)

        => Messages.Enqueue(Formatter(State, Exception));

}
