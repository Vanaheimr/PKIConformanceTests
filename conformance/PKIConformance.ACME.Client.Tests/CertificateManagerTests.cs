using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// Hermod's <see cref="ACMECertificateManager"/>: a certificate kept in files
/// and renewed - by RFC 9773, <i>"Clients MUST attempt renewal at a time of
/// their choosing based on the suggested renewal window"</i> (section 4.2),
/// and the schedule of section 4.3 on which the window is asked for again.
/// </summary>
/// <remarks>
/// On a <see cref="BenchClock"/>, which the server's certificates and windows
/// follow as well: six hours of the manager's pass in no time.
/// </remarks>
[TestFixture]
[Property("RFC", "9773 §4")]
public class CertificateManagerTests : ClientFixture
{

    private String directory = null!;

    [SetUp]
    public void MakeDirectory()
        => directory = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "pkiconformance-" + Guid.NewGuid().ToString("N")[..12])).FullName;

    [TearDown]
    public void RemoveDirectory()
    {
        try { System.IO.Directory.Delete(directory, recursive: true); } catch (IOException) { }
    }

    private BenchClock Clock()
    {
        var clock  = new BenchClock();
        Server.Now = clock.GetUtcNow;
        return clock;
    }

    private static DateTimeOffset Second(DateTimeOffset Time)
        => DateTimeOffset.FromUnixTimeSeconds(Time.ToUnixTimeSeconds());

    private ACMECertificateManager Manager(ACMEClient         Client,
                                           TimeProvider?      Clock   = null,
                                           String[]?          Names   = null,
                                           ListLogger?        Logger  = null)

        => new (Client, Names ?? [ Name ], Responders, Directory: directory, TimeProvider: Clock, Logger: Logger);

    private async Task Until(Func<Boolean> Condition, String What)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!Condition())
        {
            if (DateTime.UtcNow > deadline)
                Assert.Fail($"Waited in vain for {What}. The last requests:\n" +
                            String.Join("\n", Log.Split('\n').TakeLast(25).Select(line => line.Length > 300 ? line[..300] : line)));
            await Task.Delay(20);
        }
    }


    #region Files

    /// <summary>
    /// A manager without a certificate fetches one and keeps it where certbot
    /// keeps its own: fullchain.pem and privkey.pem, the key the certificate's.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Manager_Without_A_Certificate_Fetches_One_And_Writes_It()
    {

        var client         = await ClientWithAccountAsync();
        await using var m  = Manager(client);

        var started        = await m.StartAsync();
        using var written  = X509Certificate2.CreateFromPemFile(m.FullChainPath!, m.PrivateKeyPath!);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(started,                Is.True);
            Assert.That(written.RawData,        Is.EqualTo(Server.Certificates.Single().DER));
            Assert.That(written.HasPrivateKey,  Is.True);
        }

    }

    /// <summary>
    /// A manager that finds a good certificate in its directory asks the CA
    /// for none.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Manager_That_Finds_A_Good_Certificate_Orders_None()
    {

        var client = await ClientWithAccountAsync();

        await using (var first = Manager(client))
            await first.StartAsync();

        await using var second = Manager(client);
        await second.StartAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Server.RequestsOf("newOrder"),       Has.Count.EqualTo(1), Log);
            Assert.That(second.Certificate?.Certificate.RawData, Is.EqualTo(Server.Certificates.Single().DER));
        }

    }

    /// <summary>
    /// A certificate kept for fewer names than the manager is for is renewed
    /// now.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Certificate_For_Other_Names_Is_Due_Now()
    {

        var client = await ClientWithAccountAsync();

        await using (var first = Manager(client))
            await first.RenewAsync();

        await using var second = Manager(client, Names: [ Name, "more.acme.test" ]);

        Assert.That(await second.WhenDueAsync(), Is.LessThanOrEqualTo(DateTimeOffset.UtcNow));

    }

    /// <summary>
    /// The key of the certificate is its owner's alone (RFC 8555, section
    /// 11.3: <i>"protect private keys"</i>) - 0600, where files have modes.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §11")]
    [Property("Level", "SHOULD")]
    public async Task The_Key_File_Is_Its_Owner_s_Alone()
    {

        if (OperatingSystem.IsWindows())
            Assert.Ignore("File modes are POSIX; on Windows the ACL of the directory rules.");

        var client         = await ClientWithAccountAsync();
        await using var m  = Manager(client);
        await m.RenewAsync();

        Assert.That(File.GetUnixFileMode(m.PrivateKeyPath!), Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite));

    }

    #endregion

    #region When (RFC 9773, section 4.2)

    /// <summary>
    /// Section 4.2: <i>"Clients MUST attempt renewal at a time of their
    /// choosing based on the suggested renewal window. The following
    /// algorithm is RECOMMENDED ... Select a uniform random time within the
    /// suggested window."</i>
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.2")]
    [Property("Level", "MUST")]
    public async Task The_Renewal_Is_Due_Within_The_Suggested_Window()
    {

        var clock  = Clock();
        var start  = Second(clock.GetUtcNow().AddDays(40));
        var end    = start.AddDays(2);

        Server.RenewalWindow = _ => (start, end);

        var client          = await ClientWithAccountAsync(Clock: clock);
        await using var m   = Manager(client, clock);
        await m.RenewAsync();

        Assert.That(await m.WhenDueAsync(), Is.InRange(start, end));

    }

    /// <summary>
    /// Section 4.2: <i>"If the selected time is in the past, attempt renewal
    /// immediately."</i> - a window moved into the past, as before a mass
    /// revocation, and the certificate is renewed now.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.2")]
    [Property("Level", "SHOULD")]
    public async Task A_Window_In_The_Past_Is_A_Renewal_Now()
    {

        var clock = Clock();
        var client          = await ClientWithAccountAsync(Clock: clock);
        await using var m   = Manager(client, clock);
        await m.RenewAsync();

        Server.RenewalWindow = _ => (clock.GetUtcNow().AddDays(-2), clock.GetUtcNow().AddDays(-1));

        var renewed = await m.RenewIfDueAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(renewed,              Is.Not.Null, m.LastError);
            Assert.That(Server.Certificates,  Has.Count.EqualTo(2));
        }

    }

    /// <summary>
    /// Section 4.2: <i>"A RenewalInfo object in which the end timestamp equals
    /// or precedes the start timestamp is invalid ... clients MUST treat one
    /// as though they failed to receive any response from the server (e.g.,
    /// retry at an appropriate interval, renew on a fallback schedule,
    /// etc.)."</i> - a window of no length is no window: the manager's own
    /// schedule holds, a third of the lifetime before its end.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.2")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-6")]
    public async Task A_Window_Of_No_Length_Leaves_The_Manager_s_Own_Schedule()
    {

        var clock  = Clock();
        var start  = Second(clock.GetUtcNow().AddDays(5));

        Server.RenewalWindow = _ => (start, start);

        var client          = await ClientWithAccountAsync(Clock: clock);
        await using var m   = Manager(client, clock);
        var certificate     = await m.RenewAsync();
        var fallback        = certificate.NotAfter - (certificate.NotAfter - certificate.NotBefore) / 3;

        Assert.That(await m.WhenDueAsync(), Is.EqualTo(fallback).Within(TimeSpan.FromSeconds(1)), $"the window [{start:u}, {start:u}] taken");

    }

    /// <summary>
    /// RFC 9773, section 5: <i>"Clients SHOULD include this field in newOrder
    /// requests if there is a clear predecessor certificate, as is the case
    /// for most certificate renewals."</i> - the manager's renewals are.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD")]
    public async Task A_Renewal_Replaces_The_Certificate_Before()
    {

        var client          = await ClientWithAccountAsync();
        await using var m   = Manager(client);

        var first           = await m.RenewAsync();
        await m.RenewAsync();

        Assert.That(Server.RequestsOf("newOrder").Last().PayloadObject?["replaces"]?.GetValue<String>(),
                    Is.EqualTo(ACMEClient.CertificateIdentifier(first.Certificate)), Log);

    }

    /// <summary>
    /// A renewal that fails leaves the certificate there is, and says why.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Failed_Renewal_Keeps_The_Certificate_And_Says_Why()
    {

        var client          = await ClientWithAccountAsync();
        await using var m   = Manager(client);
        var first           = await m.RenewAsync();
        var said            = new List<String>();

        m.OnRenewalFailed          += said.Add;
        Server.ReuseAuthorizations  = false;
        Server.Validate             = (_, _) => Task.FromResult((false, "The bench says no this time."));

        await Assert.ThrowsAsync<ACMEException>(() => m.RenewAsync());

        using (Assert.EnterMultipleScope())
        {
            Assert.That(m.Certificate?.Certificate.RawData,  Is.EqualTo(first.Certificate.RawData));
            Assert.That(m.LastError,                         Does.Contain("The bench says no this time."));
            Assert.That(said,                                Has.Count.EqualTo(1));
        }

    }

    #endregion

    #region How often (RFC 9773, section 4.3)

    /// <summary>
    /// Section 4.3: <i>"Clients MUST NOT check a certificate's RenewalInfo
    /// after the certificate has expired."</i>
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.3")]
    [Property("Level", "MUST NOT")]
    public async Task An_Expired_Certificate_s_Window_Is_Not_Asked_For()
    {

        var clock           = Clock();
        var client          = await ClientWithAccountAsync(Clock: clock);
        await using var m   = Manager(client, clock);
        var certificate     = await m.RenewAsync();
        var asked           = Server.RequestsOf("renewalInfo").Count;

        clock.Set(certificate.NotAfter.AddDays(1));

        await m.WhenDueAsync();

        Assert.That(Server.RequestsOf("renewalInfo").Count, Is.EqualTo(asked), Log);

    }

    /// <summary>
    /// Section 4.3.2: <i>"After an initial fetch of a certificate's
    /// RenewalInfo, clients MUST fetch it again as soon as possible after the
    /// time indicated in the Retry-After header"</i> - an hour, here; the
    /// manager's own six hours between two looks are too long.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.3.2")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "M-1")]
    public async Task The_Window_Is_Asked_For_Again_After_Its_Retry_After()
    {

        var clock  = Clock();
        Server.RenewalRetryAfter = "3600";

        var client          = await ClientWithAccountAsync(Clock: clock);
        var m               = Manager(client, clock);

        try
        {
            await m.RenewAsync();
            await m.StartAsync();
            await Until(() => Server.RequestsOf("renewalInfo").Count >= 4, "four looks at the window");
        }
        finally
        {
            await m.DisposeAsync();
        }

        var times = Server.RequestsOf("renewalInfo").Select(request => request.ServerTime).ToArray();
        var gaps  = times.Zip(times.Skip(1), (before, after) => after - before).Where(gap => gap > TimeSpan.Zero).ToArray();

        Assert.That(gaps.Max(), Is.LessThanOrEqualTo(TimeSpan.FromHours(1) + TimeSpan.FromMinutes(5)),
                    $"the looks, by the manager's clock: {String.Join(", ", times.Select(time => time.ToString("u")))}");

    }

    /// <summary>
    /// Section 4.3: <i>"Clients SHOULD fetch a certificate's RenewalInfo
    /// immediately after issuance."</i> - after a renewal by the manager's
    /// own schedule, the window of the new certificate is asked for at once.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.3")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "M-2")]
    public async Task The_Window_Of_A_New_Certificate_Is_Asked_For_At_Once()
    {

        var clock  = Clock();
        var client = await ClientWithAccountAsync(Clock: clock);

        var m               = Manager(client, clock);

        try
        {

            var first       = await m.RenewAsync();
            var firstId     = ACMEClient.CertificateIdentifier(first.Certificate);
            var due         = Second(clock.GetUtcNow().AddDays(1));

            // The first certificate due in a day, the next ones by the server's default window.
            Server.RenewalWindow = certificate => certificate.ARIId == firstId
                                                      ? (due, due.AddMinutes(10))
                                                      : (new DateTimeOffset(certificate.Leaf.NotAfter.ToUniversalTime()).AddDays(-30),
                                                         new DateTimeOffset(certificate.Leaf.NotAfter.ToUniversalTime()).AddDays(-15));

            await m.StartAsync();

            await Until(() => Server.Certificates.Count >= 2 &&
                              Server.RequestsOf("renewalInfo").Any(request => request.Target.EndsWith(Server.Certificates[1].ARIId, StringComparison.Ordinal)),
                        "the window of the renewed certificate");

        }
        finally
        {
            await m.DisposeAsync();
        }

        var issued  = Server.RequestsOf("finalize").Last().ServerTime;
        var asked   = Server.RequestsOf("renewalInfo").First(request => request.Target.EndsWith(Server.Certificates[1].ARIId, StringComparison.Ordinal)).ServerTime;

        Assert.That(asked - issued, Is.LessThanOrEqualTo(TimeSpan.FromMinutes(5)), $"issued {issued:u}, its window first asked for {asked:u}");

    }

    /// <summary>
    /// Section 4.2: <i>"explanationURL (string, optional): A URL pointing to a
    /// page that may explain why the suggested renewal window has its current
    /// value ... Clients SHOULD provide this URL to their operator, if
    /// present."</i> - through the manager's logger, or anything of it an
    /// operator can read.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.2")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "M-3")]
    public async Task The_explanationURL_Reaches_The_Operator()
    {

        const String why = "https://pkiconformance.test/incidents/2026-11-26";

        Server.RenewalExplanationURL = why;

        var logger          = new ListLogger();
        var client          = await ClientWithAccountAsync();
        await using var m   = Manager(client, Logger: logger);

        await m.RenewAsync();
        await m.WhenDueAsync();

        var readable = logger.Messages.
                              Concat(typeof(ACMECertificateManager).GetProperties().Select(property => property.GetValue(m)?.ToString() ?? "")).
                              ToArray();

        Assert.That(readable.Any(text => text.Contains(why)), Is.True, $"what an operator can read: {String.Join(" | ", readable.Where(text => text.Length > 0))}");

    }

    #endregion

}
