using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// Where a new account and a new order are: RFC 8555, section 7.3, <i>"The
/// server returns this account object in a 201 (Created) response, with the
/// account URL in a Location header field"</i>, and section 7.4, the order's
/// URL likewise - a URI reference of RFC 9110, section 10.2.2, which may be
/// relative: <i>"If the field value is a relative reference, the final value
/// is computed by resolving it against the target URI"</i>.
/// </summary>
[TestFixture]
[Property("RFC", "8555 §7.3, §7.4; 9110 §10.2.2")]
public class LocationTests : ClientFixture
{

    private void LocationOf(String Resource, Func<String, String?> Change)

        => Server.After = (request, answer) => request.Resource == Resource && answer.Header("Location") is String location
                                                   ? (Change(location) is String changed ? answer.Replace("Location", changed) : answer.Without("Location"))
                                                   : answer;

    private static String PathOf(String URL)
        => new Uri(URL).PathAndQuery;


    /// <summary>
    /// A relative Location of a new account is resolved against the URL of
    /// newAccount - and then is the "kid", which section 6.2 wants to be
    /// <i>"the account URL received by POSTing to the newAccount resource"</i>.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Relative_Location_Of_An_Account_Is_Resolved()
    {

        LocationOf("newAccount", PathOf);

        var client  = await ClientWithAccountAsync();
        var account = Server.Accounts.Single();

        await ObtainAsync(client);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(client.AccountURL?.ToString(), Is.EqualTo(account.URL), Log);
            Assert.That(Server.SignedRequests.Where(request => request.Kid is not null).Select(request => request.Kid), Has.All.EqualTo(account.URL), Log);
        }

    }

    /// <summary>
    /// A relative Location of a new order is resolved against the URL of
    /// newOrder, and the order is looked at there.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Relative_Location_Of_An_Order_Is_Resolved()
    {

        LocationOf("newOrder", PathOf);

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);

        Assert.That(Server.RequestsOf("order").Select(request => request.HeaderURL), Has.All.EqualTo(Server.Orders.Single().URL), Log);

    }

    /// <summary>
    /// A new account without a Location is a server's mistake the client
    /// says in words - not a NullReferenceException.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Account_Without_A_Location_Is_A_Clear_Error()
    {

        LocationOf("newAccount", _ => null);

        var client  = NewClient();
        var refused = await Assert.ThrowsAsync<ACMEException>(() => client.CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true));

        Assert.That(refused!.Message, Does.Contain("Location").Or.Contain("where"), refused.Message);

    }

    /// <summary>
    /// A new order without a Location: as clear an error.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Order_Without_A_Location_Is_A_Clear_Error()
    {

        LocationOf("newOrder", _ => null);

        var client  = await ClientWithAccountAsync();
        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        Assert.That(refused!.Message, Does.Contain("Location").Or.Contain("where"), refused.Message);

    }

    /// <summary>
    /// An account URL of another host name than the directory's - a CA that
    /// keeps its accounts behind another front end - is taken as it is, and
    /// is the "kid" letter for letter.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §6.2")]
    [Property("Level", "MUST")]
    public async Task An_Account_URL_Of_Another_Host_Name_Is_The_kid_As_Given()
    {

        Server.URLFor = (kind, id) => kind == "account"
                                          ? $"http://localhost:{Server.Port}/accounts/{id}"
                                          : Server.DefaultURLFor(kind, id);

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);

        Assert.That(Server.SignedRequests.Where(request => request.Kid is not null).Select(request => request.Kid),
                    Has.All.EqualTo(Server.Accounts.Single().URL), Log);

    }

}
