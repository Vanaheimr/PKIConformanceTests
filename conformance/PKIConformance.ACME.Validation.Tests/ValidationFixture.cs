using NUnit.Framework;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Validation.Tests;

/// <summary>
/// The server under test with both of its far ends on the bench: http-01
/// asks <see cref="Host"/>, every name is resolved by <see cref="DNS"/>
/// (PLAN.md, section 0.3) - and both answer what a test scripted.
/// </summary>
/// <remarks>
/// Every test opens an account of its own, so that nothing it proves is an
/// authorization another test reuses.
/// </remarks>
public abstract class ValidationFixture(String ServerName)
{

    #region Properties

    protected IACMEServerUnderTest   Server  { get; private set; } = null!;
    protected RawACMEClient          Client  { get; private set; } = null!;
    protected ScriptedChallengeHost  Host    { get; private set; } = null!;
    protected ScriptedDNSServer      DNS     { get; private set; } = null!;

    #endregion

    #region StartServer() / StopServer()

    [OneTimeSetUp]
    public async Task StartServer()
    {

        Host    = ScriptedChallengeHost.Start();
        DNS     = new ScriptedDNSServer();
        Server  = await ServersUnderTest.StartAsync(ServerName, new ACMEServerOptions(HTTP01Port: Host.Port, DNSClient: DNS.NewDNSClient()));
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

        if (DNS is not null)
            await DNS.DisposeAsync();

    }

    #endregion


    #region ValidateAsync(Identifier, ChallengeType, Arrange)

    /// <summary>
    /// What a validation came to: the authorization as it ended, the
    /// challenge's token and key authorization, and the challenge object.
    /// </summary>
    protected sealed record Validation(RawACMEResponse  Authorization,
                                       String           Token,
                                       String           KeyAuthorization,
                                       String           ChallengeURL)
    {

        public String  Status
            => Authorization.StringOf("status") ?? "";

        /// <summary>The challenge object as it ended.</summary>
        public System.Text.Json.Nodes.JsonObject? Challenge
            => (Authorization.Object?["challenges"] as System.Text.Json.Nodes.JsonArray ?? []).
                   OfType<System.Text.Json.Nodes.JsonObject>().
                   FirstOrDefault(challenge => challenge["url"]?.GetValue<String>() == ChallengeURL);

        /// <summary>The error type of the challenge, without its prefix.</summary>
        public String? ErrorType
            => Challenge?["error"]?["type"]?.GetValue<String>() is String type && type.StartsWith(RawACMEResponse.ErrorPrefix, StringComparison.Ordinal)
                   ? type[RawACMEResponse.ErrorPrefix.Length..]
                   : null;

        public override String ToString()
            => Authorization.ToString();

    }

    /// <summary>
    /// Order the identifier with a new account, have the test arrange the
    /// answer to the challenge of the type - from its token and key
    /// authorization - answer it, and wait until the server has looked.
    /// </summary>
    protected async Task<Validation> ValidateAsync((String Type, String Value)      Identifier,
                                                   String                           ChallengeType,
                                                   Action<String, String>           Arrange)
    {

        var account        = await Client.AccountAsync();
        var order          = await Client.OrderAsync(account, Identifier);
        var authorization  = await Client.PostAsGetAsync(account, order.Authorizations[0]);
        var challenge      = RawACMEClient.ChallengeOf(authorization, ChallengeType)
                                 ?? throw new InvalidOperationException($"The authorization offers no {ChallengeType}: {authorization}");

        var keyAuthorization = RawChallenge.KeyAuthorization(challenge.Token, account.Key.JWK);

        Arrange(challenge.Token, keyAuthorization);

        var answer         = await Client.PostAsync(account, challenge.URL, "{}");

        if (answer.Status != 200)
            throw new InvalidOperationException($"The challenge was not taken: {answer}");

        var final          = await Client.PollWhileAsync(account, order.Authorizations[0], "pending");

        return new Validation(final, challenge.Token, keyAuthorization, challenge.URL);

    }

    #endregion

}
