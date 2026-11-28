using System.Text.Json.Nodes;

using NUnit.Framework;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.3: an account - opened, found by its key, changed,
/// deactivated - and section 7.1.2: what an account object is.
/// </summary>
/// <remarks>
/// An account is the key that may order certificates for whatever it
/// proved: a server that hands out the account of one key to another, or
/// that lets a deactivated key go on, hands out certificates.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.3")]
public class AccountTests(String ServerName) : ACMEServerFixture(ServerName)
{

    #region New account

    /// <summary>
    /// <i>"The server returns this account object in a 201 (Created) response,
    /// with the account URL in a Location header field."</i> - and the object
    /// of section 7.1.2: <i>"status (required, string)"</i>, <i>"orders
    /// (required, string)"</i>.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_New_Account_Is_201_With_Its_URL_And_Its_Object()
    {

        var (account, answer) = await Client.NewAccountAsync(PayloadJSON: """{"termsOfServiceAgreed":true,"contact":["mailto:admin@example.org"]}""");

        Assert.Multiple(() => {
            AssertStatus(answer, 201);
            Assert.That(account,                                   Is.Not.Null,                       answer.ToString());
            Assert.That(Uri.IsWellFormedUriString(answer.Location, UriKind.Absolute), Is.True,        $"an absolute URL: {answer}");
            Assert.That(answer.StringOf("status"),                 Is.EqualTo("valid"),               answer.ToString());
            Assert.That(answer.StringOf("orders"),                 Is.Not.Null,                       $"\"orders\" is required (section 7.1.2): {answer}");
            Assert.That(answer.StringsOf("contact"),               Is.EqualTo(new[] { "mailto:admin@example.org" }), answer.ToString());
        });

    }

    /// <summary>
    /// Section 11.1: <i>"the server MUST not allow account key pair reuse
    /// across multiple accounts"</i> - two keys, two accounts, two URLs.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3, §11.1")]
    [Property("Level", "MUST")]
    public async Task Two_Keys_Are_Two_Accounts()
    {

        var one = await NewAccountAsync();
        var two = await NewAccountAsync();

        Assert.That(two.URL, Is.Not.EqualTo(one.URL));

    }

    /// <summary>
    /// <i>"The server MUST NOT reflect the "onlyReturnExisting" field or any
    /// unrecognized fields in the resulting account object."</i>, and it
    /// <i>"MUST ignore any values provided in the "orders" fields in account
    /// objects sent by the client"</i>.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Unknown_Fields_And_orders_Of_A_New_Account_Are_Ignored()
    {

        var (account, answer) = await Client.NewAccountAsync(PayloadJSON: """{"termsOfServiceAgreed":true,"orders":"https://example.org/mine","onlyReturnExisting":false,"x-never-heard-of":42}""");

        Assert.Multiple(() => {
            AssertStatus(answer, 201);
            Assert.That(answer.StringOf("orders"),                Is.Not.EqualTo("https://example.org/mine"), answer.ToString());
            Assert.That(answer.Object?.ContainsKey("onlyReturnExisting"), Is.False, answer.ToString());
            Assert.That(answer.Object?.ContainsKey("x-never-heard-of"),   Is.False, answer.ToString());
        });

    }

    #endregion

    #region Finding an account by its key (7.3.1)

    /// <summary>
    /// Section 7.3.1: <i>"If the server receives a newAccount request signed
    /// with a key for which it already has an account registered with the
    /// provided account key, then it MUST return a response with status code
    /// 200 (OK) and provide the URL of that account in the Location header
    /// field. The body of this response represents the account object as it
    /// existed on the server before this request; any fields in the request
    /// object MUST be ignored."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.1")]
    [Property("Level", "MUST")]
    public async Task The_Same_Key_Finds_The_Same_Account_And_Changes_Nothing()
    {

        using var key  = RawKey.Generate("ES256");
        var (first, _) = await Client.NewAccountAsync(key, """{"termsOfServiceAgreed":true,"contact":["mailto:first@example.org"]}""");
        var (_, again) = await Client.NewAccountAsync(key, """{"termsOfServiceAgreed":true,"contact":["mailto:second@example.org"]}""");
        var now        = await Client.PostAsGetAsync(first!, first!.URL);

        Assert.Multiple(() => {
            AssertStatus(again, 200);
            Assert.That(again.Location,             Is.EqualTo(first.URL),                                 again.ToString());
            Assert.That(again.StringsOf("contact"), Is.EqualTo(new[] { "mailto:first@example.org" }),      again.ToString());
            Assert.That(now.StringsOf("contact"),   Is.EqualTo(new[] { "mailto:first@example.org" }),      now.ToString());
        });

    }

    /// <summary>
    /// The same key of RSA - whose JWK has more ways to be written than one of
    /// EC - finds the same account: the key is what counts, by its thumbprint.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.1")]
    [Property("Level", "MUST")]
    public async Task The_Same_RSA_Key_Finds_The_Same_Account()
    {

        using var key  = RawKey.Generate("RS256");
        var (first, _) = await Client.NewAccountAsync(key);
        var (_, again) = await Client.NewAccountAsync(key, Header: header => header.Set("jwk", RawJson.Object(("n",   RawJson.Quote(key.JWK.N!)),
                                                                                                             ("kty", RawJson.Quote("RSA")),
                                                                                                             ("e",   RawJson.Quote(key.JWK.E!)))));

        Assert.Multiple(() => {
            AssertStatus(again, 200);
            Assert.That(again.Location, Is.EqualTo(first!.URL), again.ToString());
        });

    }

    /// <summary>
    /// Section 7.3.1: <i>"If a client sends such a request and an account does
    /// not exist, then the server MUST return an error response with status
    /// code 400 (Bad Request) and type
    /// "urn:ietf:params:acme:error:accountDoesNotExist"."</i> - and makes none.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.1")]
    [Property("Level", "MUST")]
    public async Task onlyReturnExisting_Of_A_New_Key_Is_accountDoesNotExist_And_Opens_None()
    {

        using var key  = RawKey.Generate("ES256");
        var (_, look)  = await Client.NewAccountAsync(key, """{"onlyReturnExisting":true}""");
        var (_, again) = await Client.NewAccountAsync(key, """{"onlyReturnExisting":true}""");

        Assert.Multiple(() => {
            AssertProblem(look,  400, "accountDoesNotExist");
            AssertProblem(again, 400, "accountDoesNotExist");
        });

    }

    /// <summary>
    /// Section 7.3.1: onlyReturnExisting of a key that has an account: 200 and
    /// its URL.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.1")]
    [Property("Level", "MUST")]
    public async Task onlyReturnExisting_Of_A_Known_Key_Finds_Its_Account()
    {

        var account   = await NewAccountAsync();
        var (_, look) = await Client.NewAccountAsync(account.Key, """{"onlyReturnExisting":true}""");

        Assert.Multiple(() => {
            AssertStatus(look, 200);
            Assert.That(look.Location, Is.EqualTo(account.URL), look.ToString());
        });

    }

    #endregion

    #region Contacts

    /// <summary>
    /// <i>"If the server rejects a contact URL for using an unsupported scheme,
    /// it MUST return an error of type "unsupportedContact""</i> - and
    /// <i>"If the server validates contact URLs, it MUST support the "mailto"
    /// scheme."</i>
    /// </summary>
    [TestCase("tel:+49-30-1234567")]
    [TestCase("https://example.org/contact")]
    [Property("Level", "MUST")]
    public async Task A_Contact_Of_A_Scheme_It_Refuses_Is_unsupportedContact(String Contact)
    {

        var (_, answer) = await Client.NewAccountAsync(PayloadJSON: $$"""{"termsOfServiceAgreed":true,"contact":[{{RawJson.Quote(Contact)}}]}""");

        if (answer.Status is 200 or 201)
            Assert.Pass($"{Contact} was taken - a scheme the server supports.");

        AssertProblem(answer, 400, "unsupportedContact");

    }

    /// <summary>
    /// <i>"Clients MUST NOT provide a "mailto" URL in the "contact" field that
    /// contains "hfields" [RFC6068] or more than one "addr-spec" in the "to"
    /// component. If a server encounters a "mailto" contact URL that does not
    /// meet these criteria, then it SHOULD reject it as invalid."</i> - of type
    /// invalidContact, which <i>"If the server rejects a contact URL for using
    /// a supported scheme but an invalid value, then the server MUST
    /// return"</i>.
    /// </summary>
    [TestCase("mailto:admin@example.org?subject=certificates", Description = "hfields")]
    [TestCase("mailto:admin@example.org,other@example.org",    Description = "two addr-specs")]
    [TestCase("mailto:",                                       Description = "no address")]
    [TestCase("mailto:nobody",                                 Description = "no domain")]
    [TestCase("mailto:@example.org",                           Description = "no local part")]
    [TestCase("mailto:admin@",                                 Description = "nothing after the @")]
    [TestCase("mailto:admin@example.org,",                     Description = "a comma and no second address")]
    [Property("Level", "SHOULD")]
    public async Task A_mailto_That_Is_No_Single_Address_Is_invalidContact(String Contact)
    {

        var (_, answer) = await Client.NewAccountAsync(PayloadJSON: $$"""{"termsOfServiceAgreed":true,"contact":[{{RawJson.Quote(Contact)}}]}""");

        AssertProblem(answer, 400, "invalidContact");

    }

    #endregion

    #region Update (7.3.2)

    /// <summary>
    /// Section 7.3.2: <i>"If the server accepts the update, it MUST return a
    /// response with a 200 (OK) status code and the resulting account
    /// object."</i> - new contacts, two of them.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    public async Task An_Update_Of_The_Contacts_Answers_The_Resulting_Account()
    {

        var account = await NewAccountAsync();
        var answer  = await Client.PostAsync(account, account.URL, """{"contact":["mailto:certificates@example.org","mailto:admin@example.org"]}""");
        var now     = await Client.PostAsGetAsync(account, account.URL);

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(answer.StringsOf("contact"), Is.EqualTo(new[] { "mailto:certificates@example.org", "mailto:admin@example.org" }), answer.ToString());
            Assert.That(now.StringsOf("contact"),    Is.EqualTo(new[] { "mailto:certificates@example.org", "mailto:admin@example.org" }), now.ToString());
        });

    }

    /// <summary>
    /// Section 7.3.2: <i>"The server MUST ignore any updates to the "orders"
    /// field, "termsOfServiceAgreed" field (see Section 7.3.3), the "status"
    /// field (except as allowed by Section 7.3.6), or any other fields it does
    /// not recognize."</i> - an update of "orders" and of a field nobody knows
    /// changes nothing and is not refused.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    public async Task An_Update_Of_orders_And_Of_Unknown_Fields_Is_Ignored()
    {

        var account = await NewAccountAsync();
        var before  = await Client.PostAsGetAsync(account, account.URL);
        var answer  = await Client.PostAsync(account, account.URL, """{"orders":"https://example.org/mine","x-never-heard-of":true}""");

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(answer.StringOf("orders"),                       Is.EqualTo(before.StringOf("orders")), answer.ToString());
            Assert.That(answer.Object?.ContainsKey("x-never-heard-of"),  Is.False,                              answer.ToString());
        });

    }

    /// <summary>
    /// Section 7.3.2: the "status" of an update other than "deactivated" is
    /// to be ignored - so the account stays valid. Whether the server says so
    /// with 200 or refuses the update as malformed (as Boulder does) is a
    /// reading of "ignore"; that the status does not change is not.
    /// </summary>
    [TestCase("revoked")]
    [TestCase("valid")]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    public async Task An_Update_Of_status_Other_Than_deactivated_Does_Not_Change_It(String Status)
    {

        var account = await NewAccountAsync();
        var answer  = await Client.PostAsync(account, account.URL, $$"""{"status":"{{Status}}"}""");
        var now     = await Client.PostAsGetAsync(account, account.URL);

        Assert.Multiple(() => {
            Assert.That(answer.Status,          Is.EqualTo(200).Or.EqualTo(400), answer.ToString());
            Assert.That(now.StringOf("status"), Is.EqualTo("valid"),             now.ToString());
        });

    }

    #endregion

    #region Deactivation (7.3.6)

    /// <summary>
    /// Section 7.3.6: <i>"If the server accepts the deactivation request, it
    /// replies with a 200 (OK) status code and the current contents of the
    /// account object."</i> [...] <i>"If a server receives a POST or
    /// POST-as-GET from a deactivated account, it MUST return an error response
    /// with status code 401 (Unauthorized) and type
    /// "urn:ietf:params:acme:error:unauthorized"."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.6")]
    [Property("Level", "MUST")]
    public async Task A_Deactivated_Account_Is_unauthorized_From_Then_On()
    {

        var account  = await NewAccountAsync();
        var answer   = await Client.PostAsync(account, account.URL, """{"status":"deactivated"}""");
        var get      = await Client.PostAsGetAsync(account, account.URL);
        var order    = await Client.NewOrderAsync(account, Loopback4);
        var update   = await Client.PostAsync(account, account.URL, """{"contact":["mailto:back@example.org"]}""");

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(answer.StringOf("status"), Is.EqualTo("deactivated"), answer.ToString());
            AssertProblem(get,    401, "unauthorized");
            AssertProblem(order,  401, "unauthorized");
            AssertProblem(update, 401, "unauthorized");
        });

    }

    /// <summary>
    /// Section 7.3.6: <i>"Once an account is deactivated, the server MUST NOT
    /// accept further requests authorized by that account's key."</i> and
    /// <i>"ACME does not provide a way to reactivate a deactivated
    /// account."</i> - newAccount with the key opens no account again.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.6")]
    [Property("Level", "MUST")]
    public async Task The_Key_Of_A_Deactivated_Account_Opens_No_Account()
    {

        var account     = await NewAccountAsync();
        await Client.PostAsync(account, account.URL, """{"status":"deactivated"}""");

        var (again, answer) = await Client.NewAccountAsync(account.Key);

        Assert.Multiple(() => {
            AssertRefused(answer);
            Assert.That(again, Is.Null, answer.ToString());
        });

    }

    /// <summary>
    /// Section 7.3.6: <i>"The server SHOULD cancel any pending operations
    /// authorized by the account's key, such as certificate orders."</i> - and
    /// a deactivated account cannot <i>"access resources related to the
    /// account, such as orders or authorizations"</i> in any case.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.6")]
    [Property("Level", "MUST")]
    public async Task The_Orders_Of_A_Deactivated_Account_Are_Out_Of_Reach()
    {

        var (account, order) = await PendingOrderAsync();
        await Client.PostAsync(account, account.URL, """{"status":"deactivated"}""");

        AssertProblem(await Client.PostAsGetAsync(account, order.URL), 401, "unauthorized");

    }

    #endregion

    #region Orders list (7.1.2.1)

    /// <summary>
    /// Section 7.1.2.1: <i>"Each account object includes an "orders" URL from
    /// which a list of orders created by the account can be fetched via
    /// POST-as-GET request. The result of the request MUST be a JSON object
    /// whose "orders" field is an array of URLs, each identifying an order
    /// belonging to the account."</i> - and <i>"The server SHOULD include
    /// pending orders"</i>.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.2.1")]
    [Property("Level", "MUST")]
    public async Task The_Orders_Of_An_Account_Are_Listed()
    {

        var (account, order) = await PendingOrderAsync();
        var object_          = await Client.PostAsGetAsync(account, account.URL);
        var list             = await Client.PostAsGetAsync(account, object_.StringOf("orders")!);

        Assert.Multiple(() => {
            AssertStatus(list, 200);
            Assert.That(list.Object?["orders"], Is.InstanceOf<JsonArray>(), list.ToString());
            Assert.That(list.StringsOf("orders"), Does.Contain(order.URL), list.ToString());
        });

    }

    /// <summary>
    /// The orders of an account are its own: another account may not list them.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.2.1, §10.1")]
    [Property("Level", "MUST")]
    public async Task The_Orders_Of_An_Account_Are_Not_Listed_To_Another()
    {

        var (account, _) = await PendingOrderAsync();
        var mallory      = await NewAccountAsync();
        var object_      = await Client.PostAsGetAsync(account, account.URL);

        AssertRefused(await Client.PostAsGetAsync(mallory, object_.StringOf("orders")!));

    }

    /// <summary>
    /// An account is asked about by its own key alone: a POST-as-GET of
    /// another account's URL is refused.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3, §10.1")]
    [Property("Level", "MUST")]
    public async Task An_Account_Is_Not_Shown_To_Another()
    {

        var account = await NewAccountAsync();
        var mallory = await NewAccountAsync();

        var read        = await Client.PostAsGetAsync(mallory, account.URL);
        var deactivate  = await Client.PostAsync(mallory, account.URL, """{"status":"deactivated"}""");
        var still       = await Client.PostAsGetAsync(account, account.URL);

        Assert.Multiple(() => {
            AssertRefused(read);
            AssertRefused(deactivate);
            AssertStatus(still, 200);
            Assert.That(still.StringOf("status"), Is.EqualTo("valid"), still.ToString());
        });

    }

    #endregion

}
