using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// RFC 8555, section 7.3: an account - opened, found again by its key, its
/// contacts, the terms of service, and the external account binding of
/// section 7.3.4 - as the client asks for it.
/// </summary>
[TestFixture]
[Property("RFC", "8555 §7.3")]
public class AccountTests : ClientFixture
{

    /// <summary>
    /// Section 7.3: <i>"The server returns this account object in a 201
    /// (Created) response, with the account URL in a Location header
    /// field."</i> - and the client knows it from then on.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_New_Account_Is_Created_And_Its_URL_Known()
    {

        var client  = NewClient();
        var account = await client.CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(account.Created,               Is.True);
            Assert.That(account.URL.ToString(),        Is.EqualTo(Server.Accounts.Single().URL));
            Assert.That(client.AccountURL?.ToString(), Is.EqualTo(Server.Accounts.Single().URL));
            Assert.That(account.Status,                Is.EqualTo("valid"));
        }

    }

    /// <summary>
    /// Section 7.3.1: <i>"If the server already has an account registered
    /// with the provided account key, then it MUST return a response with
    /// status code 200 (OK) and provide the URL of that account in the
    /// Location header field."</i> - the same key, a new client of it, the
    /// same account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.1")]
    [Property("Level", "MUST")]
    public async Task The_Same_Key_Finds_The_Same_Account()
    {

        using var key   = ACMEAccountKey.Generate();
        var first       = await NewClient(key).CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);
        var again       = await NewClient(ACMEAccountKey.FromPem(key.ToPem())).CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);
        var found       = await NewClient(ACMEAccountKey.FromPem(key.ToPem())).FindAccountAsync();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(again.Created,  Is.False);
            Assert.That(again.URL,      Is.EqualTo(first.URL));
            Assert.That(found?.URL,     Is.EqualTo(first.URL));
            Assert.That(Server.Accounts, Has.Count.EqualTo(1));
        }

    }

    /// <summary>
    /// Section 7.3.1: <i>"If this field [onlyReturnExisting] is present with
    /// the value "true", then the server MUST NOT create a new account"</i> -
    /// a look for the account of a key is that field and no other, and an
    /// accountDoesNotExist is "none", not a failure.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.1")]
    [Property("Level", "MUST")]
    public async Task A_Look_For_An_Account_Asks_onlyReturnExisting_And_Nothing_Else()
    {

        var found = await NewClient().FindAccountAsync();
        var look  = Server.RequestsOf("newAccount").Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(found,                   Is.Null);
            Assert.That(look.PayloadJSON,        Is.EqualTo("{\"onlyReturnExisting\":true}"), look.ToString());
            Assert.That(Server.Accounts,         Is.Empty);
        }

    }

    /// <summary>
    /// Section 7.1.2: <i>"contact (optional, array of string): An array of
    /// URLs that the server can use to contact the client"</i> - an address
    /// without a scheme is a mailto: URL, one with it stays as it is.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.2")]
    [Property("Level", "MUST")]
    public async Task Contacts_Are_mailto_URLs()
    {

        await NewClient().CreateAccountAsync([ "admin@acme.test", "mailto:ops@acme.test" ], TermsOfServiceAgreed: true);

        Assert.That(Server.Accounts.Single().Contacts, Is.EqualTo(new[] { "mailto:admin@acme.test", "mailto:ops@acme.test" }));

    }

    /// <summary>
    /// Section 7.3: <i>"Clients MUST NOT provide a "mailto" URL in the
    /// "contact" field that contains "hfields" [RFC6068] or more than one
    /// "addr-spec" in the "to" component."</i> - such a contact is refused by
    /// the client, before it is sent.
    /// </summary>
    [TestCase("admin@acme.test?subject=renewal")]
    [TestCase("mailto:admin@acme.test?cc=boss@acme.test")]
    [TestCase("admin@acme.test,boss@acme.test")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-5")]
    public async Task A_mailto_With_hfields_Or_Two_Addresses_Is_Not_Sent(String Contact)
    {

        var client = NewClient();

        await Assert.CatchAsync(() => client.CreateAccountAsync([ Contact ], TermsOfServiceAgreed: true));

        Assert.That(Server.RequestsOf("newAccount").Select(request => request.PayloadJSON), Has.None.Contains("acme.test?").And.None.Contains("acme.test,"), Log);

    }

    /// <summary>
    /// Section 7.3: <i>"Clients SHOULD NOT automatically agree to terms by
    /// default. Rather, they SHOULD require some user interaction for
    /// agreement to terms."</i> - unless told, no agreement is sent.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task The_Terms_Are_Not_Agreed_To_Unless_Told()
    {

        var client  = NewClient();
        var refused = await Assert.ThrowsAsync<ACMEException>(() => client.CreateAccountAsync([ "admin@acme.test" ]));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Server.RequestsOf("newAccount").Single().PayloadObject?.ContainsKey("termsOfServiceAgreed"), Is.False, Log);
            Assert.That(refused!.Problem?.ShortType, Is.EqualTo("userActionRequired"), refused.Message);
        }

    }

    /// <summary>
    /// Section 7.3: <i>"termsOfServiceAgreed (optional, boolean): Including
    /// this field in a newAccount request, with a value of true, indicates
    /// the client's agreement with the terms of service."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Terms_Agreed_To_Are_Sent_As_true()
    {

        await NewClient().CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);

        Assert.That(Server.RequestsOf("newAccount").Single().PayloadObject?["termsOfServiceAgreed"]?.GetValue<Boolean>(), Is.True);

    }


    #region External account binding (section 7.3.4)

    private (String KeyId, Byte[] MAC) ExternalAccount()
    {

        var keyId = "kid-" + Guid.NewGuid().ToString("N")[..8];
        var mac   = RandomNumberGenerator.GetBytes(32);

        Server.ExternalAccountRequired = true;
        Server.ExternalAccountKeys[keyId] = mac;

        return (keyId, mac);

    }

    /// <summary>
    /// Section 7.3.4: <i>"The payload of this JWS is the ACME account key being
    /// registered, in JWK form. The protected header of the JWS MUST meet the
    /// following criteria: The "alg" field MUST indicate a MAC-based algorithm;
    /// The "kid" field MUST contain the key identifier provided by the CA; The
    /// "nonce" field MUST NOT be present; The "url" field MUST be set to the
    /// same value as the outer JWS"</i> - every criterion, and the MAC checked
    /// by RawACME with the key the CA gave.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "MUST")]
    public async Task The_External_Account_Binding_Is_As_Section_7_3_4_Has_It()
    {

        var (keyId, mac) = ExternalAccount();

        await NewClient().CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true, EABKeyId: keyId, EABHMACKey: RawBase64Url.Encode(mac));

        var request = Server.RequestsOf("newAccount").Single();
        var eab     = request.PayloadObject!["externalAccountBinding"]!.AsObject();
        var jws     = new RawJWS(eab["protected"]!.GetValue<String>(), eab["payload"]!.GetValue<String>(), eab["signature"]!.GetValue<String>());
        var header  = JsonNode.Parse(jws.ProtectedJSON)!.AsObject();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(header["alg"]?.GetValue<String>(),                                Is.EqualTo("HS256"),                   jws.ProtectedJSON);
            Assert.That(header["kid"]?.GetValue<String>(),                                Is.EqualTo(keyId),                     jws.ProtectedJSON);
            Assert.That(header.ContainsKey("nonce"),                                      Is.False,                              jws.ProtectedJSON);
            Assert.That(header["url"]?.GetValue<String>(),                                Is.EqualTo(request.HeaderURL),         jws.ProtectedJSON);
            Assert.That(RawJWK.Parse(jws.PayloadJSON).Thumbprint,                         Is.EqualTo(RawJWK.Parse(request.JWK!.ToJsonString()).Thumbprint), "the payload is the outer jwk");
            Assert.That(RawBase64Url.Encode(HMACSHA256.HashData(mac, jws.SigningInput)),  Is.EqualTo(jws.Signature),             "the MAC, by RawACME");
            Assert.That(Server.Accounts.Single().ExternalAccountKeyId,                    Is.EqualTo(keyId));
        }

    }

    /// <summary>
    /// Section 7.3.4: <i>"The MAC key SHOULD be provided in base64url-encoded
    /// form"</i> - which some CAs hand out with its padding; it is the same key.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "MAY")]
    public async Task A_MAC_Key_With_Its_Padding_Is_The_Same_Key()
    {

        var (keyId, mac) = ExternalAccount();
        var padded       = Convert.ToBase64String(mac).Replace('+', '-').Replace('/', '_');

        Assume.That(padded, Does.EndWith("="));

        var account = await NewClient().CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true, EABKeyId: keyId, EABHMACKey: padded);

        Assert.That(account.Created, Is.True, Log);

    }

    /// <summary>
    /// Section 7.3.4: <i>"If such a CA requires that newAccount requests
    /// contain an "externalAccountBinding" field, then it MUST provide the
    /// value "true" in the "externalAccountRequired" subfield"</i> - which a
    /// client reads, and says what is missing before it asks.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "SHOULD")]
    public async Task An_External_Account_Required_And_Not_Given_Is_Said_Before_Asking()
    {

        ExternalAccount();

        var refused = await Assert.ThrowsAsync<ACMEException>(() => NewClient().CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Message,                Does.Contain("external account binding"), refused.Message);
            Assert.That(Server.RequestsOf("newAccount"), Is.Empty, Log);
        }

    }

    #endregion

    #region ToDos

    /// <summary>
    /// ToDo T-C1: section 7.3.2, <i>"the client sends a POST request to the
    /// account URL ... with the updated fields"</i> - new contacts.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C1")]
    public async Task The_Contacts_Of_An_Account_Are_Updated()
    {

        var client = await ClientWithAccountAsync();
        var update = Trackers.Method(typeof(ACMEClient), "UpdateAccountAsync", "UpdateContactsAsync", "UpdateAccountContactsAsync");

        if (update is null)
            Assert.Fail("T-C1: the client cannot update an account's contacts (RFC 8555, section 7.3.2) yet.");

        await Trackers.InvokeAsync(update!, client, (IEnumerable<String>) [ "mailto:new@acme.test" ]);

        Assert.That(Server.Accounts.Single().Contacts, Is.EqualTo(new[] { "mailto:new@acme.test" }), Log);

    }

    /// <summary>
    /// ToDo T-C2: section 7.3.6, <i>"A client can deactivate an account by
    /// posting a signed update to the account URL with a status field of
    /// "deactivated"."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.6")]
    [Property("Level", "MUST")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C2")]
    public async Task An_Account_Is_Deactivated()
    {

        var client     = await ClientWithAccountAsync();
        var deactivate = Trackers.Method(typeof(ACMEClient), "DeactivateAccountAsync", "DeactivateAsync");

        if (deactivate is null)
            Assert.Fail("T-C2: the client cannot deactivate its account (RFC 8555, section 7.3.6) yet.");

        await Trackers.InvokeAsync(deactivate!, client);

        Assert.That(Server.Accounts.Single().Status, Is.EqualTo("deactivated"), Log);

    }

    /// <summary>
    /// ToDo T-C3: section 7.3.5, <i>"To change the key associated with an
    /// account, the client sends a request to the server containing
    /// signatures by both the old and new keys."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.5")]
    [Property("Level", "MUST")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C3")]
    public async Task The_Key_Of_An_Account_Is_Changed()
    {

        var client    = await ClientWithAccountAsync();
        var change    = Trackers.Method(typeof(ACMEClient), "ChangeKeyAsync", "ChangeAccountKeyAsync", "RolloverKeyAsync", "KeyChangeAsync");

        if (change is null)
            Assert.Fail("T-C3: the client cannot roll its account key over (RFC 8555, section 7.3.5) yet.");

        using var newKey = ACMEAccountKey.Generate();
        var before       = Server.Accounts.Single().Key.Thumbprint;

        await Trackers.InvokeAsync(change!, client, newKey);

        Assert.That(Server.Accounts.Single().Key.Thumbprint, Is.EqualTo(newKey.Thumbprint).And.Not.EqualTo(before), Log);

    }

    /// <summary>
    /// ToDo T-C12: section 7.1.2.1, <i>"Each account object includes an
    /// "orders" URL from which a list of orders created by the account can be
    /// fetched via POST-as-GET request."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.2.1")]
    [Property("Level", "MAY")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C12")]
    public async Task The_Orders_Of_An_Account_Are_Listed()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);

        var list   = Trackers.Method(typeof(ACMEClient), "GetOrdersAsync", "ListOrdersAsync", "OrdersAsync");

        if (list is null)
            Assert.Fail("T-C12: the client cannot list the orders of its account (RFC 8555, section 7.1.2.1) yet.");

        await Trackers.InvokeAsync(list!, client);

        Assert.That(Server.RequestsOf("orders"), Is.Not.Empty, Log);

    }

    #endregion

}
