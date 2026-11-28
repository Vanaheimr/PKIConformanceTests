using System.Globalization;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 9773, ACME Renewal Information: when a certificate should be renewed
/// - <i>"the client sends an unauthenticated GET request to a path under the
/// server's renewalInfo URL"</i> - and the order that renews it, which says
/// so in "replaces".
/// </summary>
/// <remarks>
/// ARI is how a CA tells its clients to renew before a mass revocation: a
/// window a client cannot read, or a "replaces" the server does not keep,
/// leaves the client renewing on its own schedule - too late.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "9773")]
public class RenewalInfoTests(String ServerName) : ACMEServerFixture(ServerName)
{

    private String RenewalInfoURL
        => Client.Resource("renewalInfo");

    private async Task<(RawACMEAccount Account, RawACMEIssued Issued, String Id)> IssuedAsync(params (String Type, String Value)[] Identifiers)
    {
        var account = await NewAccountAsync();
        var issued  = await Client.IssueAsync(account, Host, Identifiers.Length > 0 ? Identifiers : [ Loopback4 ]);
        return (account, issued, RawARI.CertificateId(issued.LeafDER) ?? throw new InvalidOperationException("The certificate has no Authority Key Identifier."));
    }

    private Task<RawACMEResponse> RenewalInfoAsync(String Id)
        => Client.SendAsync(HttpMethod.Get, $"{RenewalInfoURL}/{Id}", ContentType: null);

    private static DateTimeOffset? Timestamp(String? Text)

        => Text is not null && DateTimeOffset.TryParse(Text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at)
               ? at
               : null;

    private Task<RawACMEResponse> OrderReplacingAsync(RawACMEAccount Account, String Id, params (String Type, String Value)[] Identifiers)

        => Client.PostAsync(Account, Client.Resource("newOrder"),
                            RawJson.Object(("identifiers", RawACMEClient.IdentifiersJSON(Identifiers.Length > 0 ? Identifiers : [ Loopback4 ])),
                                           ("replaces",    RawJson.Quote(Id))));


    #region RenewalInfo

    /// <summary>
    /// Section 4.2: <i>"suggestedWindow (object, required): A JSON object with
    /// two keys, "start" and "end", whose values are timestamps, encoded in the
    /// format specified in [RFC3339]"</i> - and <i>"A RenewalInfo object in
    /// which the end timestamp equals or precedes the start timestamp is
    /// invalid. Servers MUST NOT serve such a response"</i>.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.1, §4.2")]
    [Property("Level", "MUST")]
    public async Task The_RenewalInfo_Of_A_Certificate_Is_A_Window_That_Ends_After_It_Starts()
    {

        var (_, issued, id) = await IssuedAsync();
        var answer          = await RenewalInfoAsync(id);
        var start           = Timestamp(answer.Object?["suggestedWindow"]?["start"]?.GetValue<String>());
        var end             = Timestamp(answer.Object?["suggestedWindow"]?["end"]?.GetValue<String>());

        using var leaf      = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(issued.LeafDER);

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(start, Is.Not.Null,                      answer.ToString());
            Assert.That(end,   Is.Not.Null,                      answer.ToString());
            Assert.That(end,   Is.GreaterThan(start ?? DateTimeOffset.MaxValue), $"the end after the start: {answer}");
            Assert.That(end,   Is.LessThanOrEqualTo(new DateTimeOffset(leaf.NotAfter.ToUniversalTime())), $"before the certificate expires: {answer}");
        });

    }

    /// <summary>
    /// Section 4.3.3: a RenewalInfo whose <i>"Retry-After is invalid or not
    /// present"</i> is a long-term error to a client - so a server sends one.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.3")]
    [Property("Level", "SHOULD")]
    public async Task The_RenewalInfo_Says_When_To_Ask_Again()
    {

        var (_, _, id) = await IssuedAsync();
        var answer     = await RenewalInfoAsync(id);

        Assert.That(Int32.TryParse(answer.Header("Retry-After"), out var seconds) && seconds > 0, Is.True, answer.ToString());

    }

    /// <summary>
    /// A revoked certificate is to be renewed now: section 4.3.1, the window
    /// is how a server <i>"needs to revoke certificates"</i> and has clients
    /// renew - a window that has begun.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.2, §4.3.1")]
    [Property("Level", "SHOULD")]
    public async Task The_Window_Of_A_Revoked_Certificate_Has_Begun()
    {

        var (account, issued, id) = await IssuedAsync();
        await Client.PostAsync(account, Client.Resource("revokeCert"), RawJson.Object(("certificate", RawJson.Quote(RawBase64Url.Encode(issued.LeafDER))), ("reason", "1")));

        var answer = await RenewalInfoAsync(id);
        var start  = Timestamp(answer.Object?["suggestedWindow"]?["start"]?.GetValue<String>());

        Assert.That(start, Is.LessThanOrEqualTo(DateTimeOffset.UtcNow), answer.ToString());

    }

    /// <summary>
    /// The identifier of a certificate the server did not issue: not found -
    /// as RFC 9110 has it for a resource that is not there.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.1")]
    [Property("Level", "SHOULD")]
    public async Task The_RenewalInfo_Of_An_Unknown_Certificate_Is_404()

        => AssertStatus(await RenewalInfoAsync("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"), 404);

    /// <summary>
    /// Section 4.1: a certificate is named by the keyIdentifier of its
    /// Authority Key Identifier and its serial - both. The serial of a
    /// certificate of the server, under another keyIdentifier, names a
    /// certificate of another CA: not found. (The mutation sweep found that no
    /// test sent one: a server that looked at the serial alone passed.)
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.1")]
    [Property("Level", "SHOULD")]
    public async Task The_Serial_Of_A_Certificate_Under_Another_keyIdentifier_Is_404()
    {

        var (_, _, id) = await IssuedAsync();
        var parts      = id.Split('.');
        var other      = RawBase64Url.Decode(parts[0]);
        other[0]      ^= 0xFF;

        AssertStatus(await RenewalInfoAsync($"{RawBase64Url.Encode(other)}.{parts[1]}"), 404);

    }

    /// <summary>
    /// What is no identifier of section 4.1 at all: refused.
    /// </summary>
    [TestCase("not-an-identifier")]
    [TestCase("aYhba4dGQEHhs3uEe6CuLN4ByNQ")]
    [TestCase("a.b.c")]
    [Property("RFC", "9773 §4.1")]
    [Property("Level", "MUST")]
    public async Task What_Is_No_Identifier_Is_Refused(String Id)
        => AssertRefused(await RenewalInfoAsync(Id));

    #endregion

    #region replaces (section 5)

    /// <summary>
    /// Section 5: <i>"If the server accepts a newOrder request with a "replaces"
    /// field, it MUST reflect that field in the response and in subsequent
    /// requests for the corresponding Order object."</i>
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-10")]
    public async Task An_Order_That_Replaces_Says_So()
    {

        var (account, _, id) = await IssuedAsync();
        var answer           = await OrderReplacingAsync(account, id);

        Assert.That(answer.Status, Is.EqualTo(201), answer.ToString());

        var later            = await Client.PostAsGetAsync(account, answer.Location!);

        Assert.Multiple(() => {
            Assert.That(answer.StringOf("replaces"), Is.EqualTo(id), $"in the response: {answer}");
            Assert.That(later.StringOf("replaces"),  Is.EqualTo(id), $"in subsequent requests: {later}");
        });

    }

    /// <summary>
    /// Section 5: <i>"If the server rejects the request because the identified
    /// certificate has already been marked as replaced, it MUST return an HTTP
    /// 409 (Conflict) with a problem document of type "alreadyReplaced"."</i> -
    /// a certificate replaced by an order that was finalized.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "MUST")]
    public async Task A_Certificate_Replaced_Already_Is_alreadyReplaced()
    {

        var (account, _, id) = await IssuedAsync();
        var first            = await OrderReplacingAsync(account, id);
        var order            = new RawACMEOrder(first.Location!, first.Object!);

        foreach (var authorization in order.Authorizations)
            await Client.ProveHTTP01Async(account, authorization, Host);

        using var key        = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var finalized        = await Client.FinalizeAsync(account, await Client.RefreshAsync(account, order), RawCSR.CreateBase64Url(key, [ Loopback4 ]));

        Assert.That(finalized.Status, Is.EqualTo(200), finalized.ToString());

        var second           = await OrderReplacingAsync(account, id);

        if (second.Status == 201)
            Assert.Fail($"A certificate replaced already was replaced again - RFC 9773 SHOULD reject it, with 409 alreadyReplaced: {second}");

        AssertProblem(second, 409, "alreadyReplaced");

    }

    /// <summary>
    /// Section 5: <i>"Servers SHOULD check that the identified certificate and
    /// the newOrder request correspond to the same ACME Account"</i> [...] <i>"If
    /// any of these checks fail, the server SHOULD reject the newOrder
    /// request."</i>
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD")]
    public async Task An_Order_Of_Another_Account_Does_Not_Replace()
    {

        var (_, _, id) = await IssuedAsync();
        var mallory    = await NewAccountAsync();

        AssertRefused(await OrderReplacingAsync(mallory, id));

    }

    /// <summary>
    /// Section 5: <i>"Servers SHOULD check [...] that they share at least one
    /// identifier"</i> - a certificate of 127.0.0.1 replaced by an order of ::1.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-11")]
    public async Task An_Order_Of_None_Of_Its_Names_Does_Not_Replace()
    {

        var (account, _, id) = await IssuedAsync();

        AssertRefused(await OrderReplacingAsync(account, id, Loopback6));

    }

    /// <summary>
    /// Section 5: <i>"has not already been marked as replaced by a different
    /// Order that is not "invalid""</i> - a second order replacing the same
    /// certificate while the first one is pending.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-11")]
    public async Task A_Second_Order_Replacing_The_Same_Certificate_Is_Refused()
    {

        var (account, _, id) = await IssuedAsync();
        var first            = await OrderReplacingAsync(account, id);
        var second           = await OrderReplacingAsync(account, id);

        Assert.Multiple(() => {
            AssertStatus(first, 201);
            AssertProblem(second, 409, "alreadyReplaced");
        });

    }

    #endregion

}
