using NUnit.Framework;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// What every test of a server under test stands on: the server, started
/// once for the fixture with its http-01 pointed at a host of the bench, and
/// the suite's raw client talking to it.
/// </summary>
/// <remarks>
/// <para>
/// Names are proven as addresses of RFC 8738 - 127.0.0.1 and ::1 - by http-01
/// at <see cref="Host"/>: an address needs no resolution, so nothing here
/// depends on a name server, and the host is the only web server ever asked.
/// </para>
/// <para>
/// A server holds on to an authorization once proven, for its account (RFC
/// 8555, section 7.1.3). A test that needs one pending opens an account of
/// its own.
/// </para>
/// </remarks>
public abstract class ACMEServerFixture(String ServerName)
{

    #region Data

    /// <summary>127.0.0.1, an identifier of RFC 8738.</summary>
    protected static readonly (String Type, String Value) Loopback4 = ("ip", "127.0.0.1");

    /// <summary>::1, an identifier of RFC 8738.</summary>
    protected static readonly (String Type, String Value) Loopback6 = ("ip", "::1");

    #endregion

    #region Properties

    /// <summary>The server under test.</summary>
    protected IACMEServerUnderTest   Server  { get; private set; } = null!;

    /// <summary>The suite's client of it.</summary>
    protected RawACMEClient          Client  { get; private set; } = null!;

    /// <summary>The web server http-01 asks.</summary>
    protected ScriptedChallengeHost  Host    { get; private set; } = null!;

    #endregion


    #region Options(HTTP01Port)

    /// <summary>
    /// How the fixture's server is started - with http-01 at the host.
    /// </summary>
    protected virtual ACMEServerOptions Options(UInt16 HTTP01Port)
        => new (HTTP01Port: HTTP01Port);

    #endregion

    #region StartServer() / StopServer()

    [OneTimeSetUp]
    public async Task StartServer()
    {

        Host    = ScriptedChallengeHost.Start();
        Server  = await ServersUnderTest.StartAsync(ServerName, Options(Host.Port));
        Client  = await RawACMEClient.ConnectAsync(Server);

    }

    [OneTimeTearDown]
    public async Task StopServer()
    {

        Client?.Dispose();

        if (Server is not null)
            await Server.DisposeAsync();

        if (Host is not null)
            await Host.DisposeAsync();

    }

    #endregion


    #region Assertions

    /// <summary>
    /// The answer is a problem document (RFC 7807) of the status and of one of
    /// the error types of RFC 8555, section 6.7 - with the answer as evidence.
    /// </summary>
    /// <param name="Response">The answer.</param>
    /// <param name="Status">The status code; any of 4xx where null.</param>
    /// <param name="Types">The error types, without "urn:ietf:params:acme:error:"; any where none.</param>
    protected static void AssertProblem(RawACMEResponse  Response,
                                        Int32?           Status,
                                        params String[]  Types)
    {
        Assert.Multiple(() => {

            if (Status is Int32 status)
                Assert.That(Response.Status, Is.EqualTo(status),                       $"the status: {Response}");
            else
                Assert.That(Response.Status, Is.InRange(400, 499),                     $"the status: {Response}");

            Assert.That(Response.MediaType,  Is.EqualTo("application/problem+json"),   $"the media type: {Response}");

            if (Types.Length > 0)
                Assert.That(Response.ErrorType, Is.AnyOf(Types),                       $"the error type: {Response}");
            else
                Assert.That(Response.ErrorType, Is.Not.Null,                           $"an error type of ACME: {Response}");

        });
    }

    /// <summary>
    /// The request was refused - with a status of 4xx, whichever.
    /// </summary>
    protected static void AssertRefused(RawACMEResponse Response)
        => Assert.That(Response.Status, Is.InRange(400, 499), $"refused: {Response}");

    /// <summary>
    /// The answer has the status.
    /// </summary>
    protected static void AssertStatus(RawACMEResponse  Response,
                                       Int32            Status)

        => Assert.That(Response.Status, Is.EqualTo(Status), Response.ToString());

    #endregion

    #region Helpers

    /// <summary>
    /// A new account, of a new ES256 key.
    /// </summary>
    protected Task<RawACMEAccount> NewAccountAsync(RawKey? Key = null)
        => Client.AccountAsync(Key);

    /// <summary>
    /// A new account with an order of 127.0.0.1 whose authorization is pending.
    /// </summary>
    protected async Task<(RawACMEAccount Account, RawACMEOrder Order)> PendingOrderAsync()
    {
        var account = await NewAccountAsync();
        return (account, await Client.OrderAsync(account, Loopback4));
    }

    /// <summary>
    /// A new account with an order of 127.0.0.1, proven: ready to finalize.
    /// </summary>
    protected async Task<(RawACMEAccount Account, RawACMEOrder Order)> ReadyOrderAsync(params (String Type, String Value)[] Identifiers)
    {
        var account = await NewAccountAsync();
        var order   = await Client.ReadyOrderAsync(account, Host, Identifiers.Length > 0 ? Identifiers : [ Loopback4 ]);
        Assert.That(order.Status, Is.EqualTo("ready"), $"the order of the arrangement: {order.JSON.ToJsonString()}");
        return (account, order);
    }

    #endregion

}
