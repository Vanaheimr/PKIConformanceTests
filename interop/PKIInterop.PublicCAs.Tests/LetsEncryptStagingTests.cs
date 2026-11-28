using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Peers;

namespace PKIInterop.PublicCAs.Tests;

/// <summary>
/// Hermod's ACME client against Let's Encrypt's staging environment - the
/// one CA of the world it is written for - over the internet: the directory,
/// an account opened, found again by its key, and none for a new key; every
/// request judged on the wire by RawACME (<see cref="WireForm"/>).
/// </summary>
/// <remarks>
/// <para>
/// Opt-in, as every test of the category Online: no CI runs it, and a run
/// opens accounts at Let's Encrypt - two, of keys made for it, with no
/// contact - well inside staging's rate limits (50 new accounts an address
/// in three hours).
/// </para>
/// <para>
/// Not here: orders, and so authorizations, certificates, revocation and
/// ARI. An order is of a name, and a name the suite may prove needs a public
/// one with a DNS API whose credentials a CI could hold (PLAN.md, section
/// 10). Not here either: a key change and a deactivated account, which
/// Hermod's client does not have yet (T-C3, T-C2).
/// </para>
/// </remarks>
[Category(TestCategories.Online)]
[Property("RFC", "8555 §7.1.1, §7.3")]
public sealed class LetsEncryptStagingTests
{

    #region Bench

    /// <summary>Let's Encrypt's staging environment.</summary>
    public static readonly Uri Directory = new ("https://acme-staging-v02.api.letsencrypt.org/directory");

    /// <summary>The column of the interop matrix.</summary>
    public const String Name = "Let's Encrypt staging";

    private RecordingHandler         wire    = null!;
    private readonly List<ACMEClient> clients = [];

    private String Evidence
        => $"{Name}\n{wire.Log}";

    [SetUp]
    public void StartWire()
    {
        InteropMatrix.Declare(InteropCells.Servers, Name, Revisions.Hermod);
        wire = new RecordingHandler();
    }

    [TearDown]
    public void StopWire()
    {

        if (TestContext.CurrentContext.Result.Outcome.Status != NUnit.Framework.Interfaces.TestStatus.Passed)
            TestContext.Out.WriteLine(Evidence);

        foreach (var client in clients)
            client.Dispose();

        clients.Clear();
        wire.Dispose();

    }

    private ACMEClient NewClient(ACMEAccountKey? Key = null)
    {
        var client = new ACMEClient(Directory, Key ?? ACMEAccountKey.Generate(), HTTPHandler: wire);
        clients.Add(client);
        return client;
    }

    private void AssertWire()
    {
        var wrong = WireForm.Judge(wire.Exchanges);
        Assert.That(wrong, Is.Empty, $"what Hermod sent {Name}:\n{String.Join("\n", wrong)}\n{Evidence}");
    }

    #endregion


    /// <summary>
    /// Section 7.1.1: the directory, as Hermod reads it - the resources it
    /// uses, of RFC 8555 and RFC 9773, and the terms of service.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.1, 9773 §4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.HermodDirectory)]
    public async Task Hermod_Reads_The_Directory()
    {

        var directory = await NewClient().GetDirectoryAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(directory.NewNonce,       Is.Not.Null, Evidence);
            Assert.That(directory.NewAccount,     Is.Not.Null, Evidence);
            Assert.That(directory.NewOrder,       Is.Not.Null, Evidence);
            Assert.That(directory.RevokeCertificate, Is.Not.Null, Evidence);
            Assert.That(directory.RenewalInfo,    Is.Not.Null, Evidence);
            Assert.That(directory.TermsOfService, Is.Not.Null, Evidence);
        }

    }

    /// <summary>
    /// Section 7.3: an account opened, the terms agreed to - no contact, which
    /// Let's Encrypt asks for no more.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.HermodAccount)]
    public async Task An_Account_Is_Opened_With_The_Terms()
    {

        var client  = NewClient();
        var account = await client.CreateAccountAsync(null, TermsOfServiceAgreed: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(account.Created,         Is.True,                                  Evidence);
            Assert.That(account.Status,          Is.EqualTo("valid"),                      Evidence);
            Assert.That(account.URL.Host,        Is.EqualTo(Directory.Host),               Evidence);
            Assert.That(client.AccountURL,       Is.EqualTo(account.URL),                  Evidence);
        }

        AssertWire();

    }

    /// <summary>
    /// Section 7.3.1: the key of an account finds the account - asked for
    /// with onlyReturnExisting, and asked to open one again.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.1")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.HermodAccountFound)]
    public async Task The_Key_Of_An_Account_Finds_It()
    {

        var key    = ACMEAccountKey.Generate();
        var opened = await NewClient(key).CreateAccountAsync(null, TermsOfServiceAgreed: true);
        var found  = await NewClient(key).FindAccountAsync();
        var again  = await NewClient(key).CreateAccountAsync(null, TermsOfServiceAgreed: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found?.URL,     Is.EqualTo(opened.URL), $"onlyReturnExisting: {Evidence}");
            Assert.That(again.Created,  Is.False,               $"no second account: {Evidence}");
            Assert.That(again.URL,      Is.EqualTo(opened.URL), Evidence);
        }

        AssertWire();

    }

    /// <summary>
    /// Section 7.3.1: a key of no account finds none - and opens none.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.1")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.HermodAccountNone)]
    public async Task A_New_Key_Finds_No_Account()
    {

        Assert.That(await NewClient().FindAccountAsync(), Is.Null, Evidence);

        AssertWire();

    }

}
