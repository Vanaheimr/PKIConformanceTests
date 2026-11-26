using System.Globalization;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// Waiting for the server: RFC 8555, section 7.5.1, <i>"the client will need
/// to poll the authorization resource to see when it is finalized"</i> and
/// <i>"the server ... MAY include a Retry-After header field to suggest a
/// polling interval"</i>; section 7.4, an order "processing" after it was
/// finalized - <i>"the server SHOULD include a Retry-After header field"</i>.
/// </summary>
/// <remarks>
/// The client waits on a <see cref="BenchClock"/>: every wait it asks for is
/// written down, and none takes any time.
/// </remarks>
[TestFixture]
[Property("RFC", "8555 §7.5.1, §7.4")]
public class PollingTests : ClientFixture
{

    /// <summary>
    /// A Retry-After on the polls of an authorization being validated is
    /// waited, not the client's own interval.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task The_Retry_After_Of_An_Authorization_Is_Waited()
    {

        var clock  = new BenchClock();
        var client = await ClientWithAccountAsync(Clock: clock);

        Server.AuthorizationProcessingPolls = 3;
        Server.PollRetryAfter               = "7";

        await ObtainAsync(client);

        Assert.That(clock.Delays.Count(delay => delay == TimeSpan.FromSeconds(7)), Is.GreaterThanOrEqualTo(Server.AuthorizationProcessingPolls - 1), $"waited: {String.Join(", ", clock.Delays)}");

    }

    /// <summary>
    /// A Retry-After on the polls of an order "processing" after its
    /// finalization is waited.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task The_Retry_After_Of_A_Processing_Order_Is_Waited()
    {

        var clock  = new BenchClock();
        var client = await ClientWithAccountAsync(Clock: clock, PollTimeout: TimeSpan.FromMinutes(10));

        Server.OrderProcessingPolls = 3;
        Server.PollRetryAfter       = "11";

        await ObtainAsync(client);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Server.Certificates,                                              Has.Count.EqualTo(1), Log);
            Assert.That(clock.Delays.Count(delay => delay == TimeSpan.FromSeconds(11)),   Is.GreaterThanOrEqualTo(2), $"waited: {String.Join(", ", clock.Delays)}");
        }

    }

    /// <summary>
    /// A Retry-After as an HTTP date (RFC 9110, section 10.2.3) is waited
    /// until that date.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.1; 9110 §10.2.3")]
    [Property("Level", "SHOULD")]
    public async Task A_Retry_After_Date_Is_Waited_Until()
    {

        var clock  = new BenchClock();
        var client = await ClientWithAccountAsync(Clock: clock, PollTimeout: TimeSpan.FromMinutes(10));

        Server.AuthorizationProcessingPolls = 2;
        Server.After = (request, answer) => request.Resource == "authz" && answer.Header("Retry-After") is null && answer.JSON?["status"]?.GetValue<String>() == "pending" &&
                                            Server.Authorizations.Any(authz => authz.Challenges.Any(challenge => challenge.RespondedAt is not null))
                                                ? answer.With("Retry-After", (DateTimeOffset.UtcNow + TimeSpan.FromSeconds(30)).ToString("R", CultureInfo.InvariantCulture))
                                                : answer;

        await ObtainAsync(client);

        Assert.That(clock.Delays.Where(delay => delay > TimeSpan.FromSeconds(25) && delay <= TimeSpan.FromSeconds(31)), Is.Not.Empty, $"waited: {String.Join(", ", clock.Delays)}");

    }

    /// <summary>
    /// The same date read by a client whose clock is not the system's - the
    /// one its TimeProvider says: the wait is until the date by the clock the
    /// client waits by, not by another.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.1; 9110 §10.2.3")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-9")]
    public async Task A_Retry_After_Date_Is_Read_By_The_Client_s_Clock()
    {

        var clock  = new BenchClock(DateTimeOffset.UtcNow.AddDays(-400));
        var client = await ClientWithAccountAsync(Clock: clock, PollTimeout: TimeSpan.FromMinutes(10));

        Server.AuthorizationProcessingPolls = 2;
        Server.After = (request, answer) => request.Resource == "authz" && answer.JSON?["status"]?.GetValue<String>() == "pending" &&
                                            Server.Authorizations.Any(authz => authz.Challenges.Any(challenge => challenge.RespondedAt is not null))
                                                ? answer.Replace("Retry-After", (clock.GetUtcNow() + TimeSpan.FromSeconds(30)).ToString("R", CultureInfo.InvariantCulture))
                                                : answer;

        await ObtainAsync(client);

        Assert.That(clock.Delays.Where(delay => delay > TimeSpan.FromSeconds(25) && delay <= TimeSpan.FromSeconds(31)), Is.Not.Empty, $"waited: {String.Join(", ", clock.Delays)}");

    }

    /// <summary>
    /// An order "processing" for a while after its finalization is looked at
    /// until it is valid, and its certificate fetched then.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Order_Processing_After_Its_Finalization_Is_Waited_For()
    {

        var client = await ClientWithAccountAsync();
        Server.OrderProcessingPolls = 4;

        var certificate = await ObtainAsync(client);
        var finalize    = Server.RequestsOf("finalize").Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(certificate.Certificate.RawData,                                                 Is.EqualTo(Server.Certificates.Single().DER));
            Assert.That(Server.RequestsOf("order").Count(request => request.Number > finalize.Number),   Is.GreaterThanOrEqualTo(4), Log);
        }

    }

    /// <summary>
    /// An authorization that never comes out of validation: the client gives
    /// up after its poll timeout - three minutes of its clock - and stops
    /// asking.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task An_Authorization_That_Never_Ends_Is_Given_Up_After_The_Timeout()
    {

        var clock  = new BenchClock();
        var client = await ClientWithAccountAsync(Clock: clock, PollTimeout: TimeSpan.FromMinutes(3));

        Server.AuthorizationProcessingPolls = Int32.MaxValue;
        Server.PollRetryAfter               = "10";

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));
        var polls   = Server.RequestsOf("authz").Count;

        await Task.Delay(300);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Message,                     Does.Contain("Waited").Or.Contain("in vain"), refused.Message);
            Assert.That(clock.Delays.Aggregate(TimeSpan.Zero, (sum, delay) => sum + delay), Is.InRange(TimeSpan.FromMinutes(2.9), TimeSpan.FromMinutes(4)), "the client's three minutes");
            Assert.That(Server.RequestsOf("authz").Count,     Is.EqualTo(polls), "no polls after giving up");
        }

    }

    /// <summary>
    /// Section 7.5.1: <i>"For challenges where the client can tell when the
    /// server has validated the challenge (e.g., by seeing an HTTP or DNS
    /// request from the server), the client SHOULD NOT begin polling until it
    /// has seen the validation request from the server."</i> - Hermod's
    /// http-01 responder serves the request, and can tell.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-8")]
    public async Task Polling_Begins_After_The_Validation_Request()
    {

        var client = await ClientWithAccountAsync();
        Server.ValidationDelay = TimeSpan.FromSeconds(1.5);

        await client.ObtainCertificateAsync([ Name ], [ HTTP01 ]);

        var validation = Server.Validations.Single();
        var response   = Server.RequestsOf("challenge").First(request => !request.PostAsGet);
        var firstPoll  = Server.RequestsOf("authz").First(request => request.Number > response.Number);

        Assert.That(firstPoll.At, Is.GreaterThanOrEqualTo(validation.At), $"first poll {firstPoll.At:HH:mm:ss.fff}, validation {validation.At:HH:mm:ss.fff}");

    }

}
