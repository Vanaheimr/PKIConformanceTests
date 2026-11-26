using NUnit.Framework;

using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.3.5: a new key for an account - an inner JWS signed by
/// the new key, of the account URL and the old key, inside an outer one
/// signed by the old key. <i>"On receiving a keyChange request, the server
/// MUST perform the following steps in addition to the typical JWS
/// validation"</i> - nine of them - and <i>"If all of these checks pass, then
/// the server updates the corresponding account by replacing the old account
/// key with the new public key and returns status code 200 (OK)."</i>
/// </summary>
/// <remarks>
/// A key change is the one request that hands an account over: a server
/// that misses one of the nine checks hands it to a key that never agreed,
/// or to one that did not hold the account.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.3.5")]
public class KeyChangeTests(String ServerName) : ACMEServerFixture(ServerName)
{

    private String KeyChangeURL
        => Client.Resource("keyChange");

    /// <summary>
    /// The key change of the account to the new key, the inner JWS built as
    /// the test says.
    /// </summary>
    private Task<RawACMEResponse> KeyChangeAsync(RawACMEAccount   Account,
                                                 RawJWS           Inner)

        => Client.PostAsync(Account, KeyChangeURL, Inner.ToFlattenedJSON());

    /// <summary>
    /// The inner JWS of a key change, with its header and payload changed as
    /// the test says, signed by the given key.
    /// </summary>
    private RawJWS Inner(RawKey               NewKey,
                         RawACMEAccount       Account,
                         Action<JWSHeader>?   Header   = null,
                         String?              Payload  = null,
                         RawKey?              SignWith = null)
    {

        var header = new JWSHeader().SetString("alg", NewKey.Algorithm).Set("jwk", NewKey.JWK.ToJSON()).SetString("url", KeyChangeURL);
        Header?.Invoke(header);

        return RawJWS.Sign(SignWith ?? NewKey,
                           header.ToJSON(),
                           Payload ?? RawJson.Object(("account", RawJson.Quote(Account.URL)), ("oldKey", Account.Key.JWK.ToJSON())));

    }


    /// <summary>
    /// The change itself: 200, and from then on the new key is the account's
    /// and the old one is not.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_New_Key_Is_The_Account_s_And_The_Old_One_Is_Not()
    {

        var account     = await NewAccountAsync();
        using var key   = RawKey.Generate("ES384");

        var answer      = await KeyChangeAsync(account, RawAccountJWS.KeyChange(key, account.URL, account.Key.JWK, KeyChangeURL));
        var withNew     = await Client.PostAsGetAsync(account with { Key = key }, account.URL);
        var withOld     = await Client.PostAsGetAsync(account, account.URL);
        var (_, found)  = await Client.NewAccountAsync(key, """{"onlyReturnExisting":true}""");

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            AssertStatus(withNew, 200);
            AssertRefused(withOld);
            AssertStatus(found, 200);
            Assert.That(found.Location, Is.EqualTo(account.URL), $"section 7.3.1 finds the account by its new key: {found}");
        });

    }

    /// <summary>
    /// Section 7.3.5: <i>"the server MUST NOT invalidate pending orders or
    /// authorization transactions based on a change of account key."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Pending_Orders_Survive_The_Change()
    {

        var (account, order) = await PendingOrderAsync();
        using var key         = RawKey.Generate("ES256");

        var answer            = await KeyChangeAsync(account, RawAccountJWS.KeyChange(key, account.URL, account.Key.JWK, KeyChangeURL));
        var after             = await Client.PostAsGetAsync(account with { Key = key }, order.URL);

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            AssertStatus(after, 200);
            Assert.That(after.StringOf("status"), Is.EqualTo("pending"), after.ToString());
        });

    }

    /// <summary>
    /// Step 4: <i>"Check that the inner JWS verifies using the key in its
    /// "jwk" field."</i> - an inner JWS signed by the old key: the new key
    /// never agreed.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Inner_JWS_Not_Signed_By_The_New_Key_Is_Refused()
    {

        var account    = await NewAccountAsync();
        using var key  = RawKey.Generate("ES256");

        await AssertRefusedAndUnchangedAsync(account, await KeyChangeAsync(account, Inner(key, account, SignWith: account.Key)));

    }

    /// <summary>
    /// Step 3: <i>"Check that the JWS protected header of the inner JWS has a
    /// "jwk" field."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Inner_JWS_Without_jwk_Is_Refused()
    {

        var account    = await NewAccountAsync();
        using var key  = RawKey.Generate("ES256");

        await AssertRefusedAndUnchangedAsync(account, await KeyChangeAsync(account, Inner(key, account, Header: header => header.Remove("jwk").SetString("kid", account.URL))));

    }

    /// <summary>
    /// Step 6: <i>"Check that the "url" parameters of the inner and outer JWSs
    /// are the same."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Inner_JWS_For_Another_URL_Is_Refused()
    {

        var account    = await NewAccountAsync();
        using var key  = RawKey.Generate("ES256");

        await AssertRefusedAndUnchangedAsync(account, await KeyChangeAsync(account, Inner(key, account, Header: header => header.SetString("url", account.URL))));

    }

    /// <summary>
    /// <i>"The inner JWS MUST omit the "nonce" header parameter."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Inner_JWS_With_A_Nonce_Is_Refused()
    {

        var account    = await NewAccountAsync();
        using var key  = RawKey.Generate("ES256");
        var nonce      = await Client.FreshNonceAsync();

        await AssertRefusedAndUnchangedAsync(account, await KeyChangeAsync(account, Inner(key, account, Header: header => header.SetString("nonce", nonce))));

    }

    /// <summary>
    /// Step 7: <i>"Check that the "account" field of the keyChange object
    /// contains the URL for the account matching the old key"</i> - another
    /// account's URL.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Inner_JWS_Of_Another_Account_Is_Refused()
    {

        var account    = await NewAccountAsync();
        var other      = await NewAccountAsync();
        using var key  = RawKey.Generate("ES256");

        var payload    = RawJson.Object(("account", RawJson.Quote(other.URL)), ("oldKey", account.Key.JWK.ToJSON()));

        await AssertRefusedAndUnchangedAsync(account, await KeyChangeAsync(account, Inner(key, account, Payload: payload)));
        AssertStatus(await Client.PostAsGetAsync(other, other.URL), 200);

    }

    /// <summary>
    /// Step 8: <i>"Check that the "oldKey" field of the keyChange object is the
    /// same as the account key for the account in question."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Inner_JWS_Of_Another_Old_Key_Is_Refused()
    {

        var account     = await NewAccountAsync();
        using var key   = RawKey.Generate("ES256");
        using var wrong = RawKey.Generate("ES256");

        var payload     = RawJson.Object(("account", RawJson.Quote(account.URL)), ("oldKey", wrong.JWK.ToJSON()));

        await AssertRefusedAndUnchangedAsync(account, await KeyChangeAsync(account, Inner(key, account, Payload: payload)));

    }

    /// <summary>
    /// Step 9: <i>"Check that no account exists whose account key is the same
    /// as the key in the "jwk" header parameter of the inner JWS."</i> -
    /// <i>"If there is an existing account with the new key provided, then the
    /// server SHOULD use status code 409 (Conflict) and provide the URL of that
    /// account in the Location header field."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Key_Of_Another_Account_Is_A_Conflict_With_Its_Location()
    {

        var account  = await NewAccountAsync();
        var other    = await NewAccountAsync();

        var answer   = await KeyChangeAsync(account, Inner(other.Key, account));

        Assert.Multiple(() => {
            Assert.That(answer.Status,   Is.EqualTo(409),         $"SHOULD 409: {answer}");
            Assert.That(answer.Location, Is.EqualTo(other.URL),   $"SHOULD give the other account's URL: {answer}");
        });

        await AssertRefusedAndUnchangedAsync(account, answer);

    }

    /// <summary>
    /// Step 5: <i>"Check that the payload of the inner JWS is a well-formed
    /// keyChange object"</i> - an inner JWS of a POST-as-GET.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Inner_JWS_Without_A_keyChange_Object_Is_Refused()
    {

        var account    = await NewAccountAsync();
        using var key  = RawKey.Generate("ES256");

        var header     = new JWSHeader().SetString("alg", "ES256").Set("jwk", key.JWK.ToJSON()).SetString("url", KeyChangeURL);
        var inner      = RawJWS.Sign(key, header.ToJSON(), null);

        await AssertRefusedAndUnchangedAsync(account, await KeyChangeAsync(account, inner));

    }

    /// <summary>
    /// The new key is checked as any account key (section 6.2): one of RSA of
    /// 1024 bits is no key of an account.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.5, §6.2")]
    [Property("Level", "MUST")]
    public async Task A_New_Key_It_Would_Not_Open_An_Account_With_Is_Refused()
    {

        var account    = await NewAccountAsync();
        using var key  = RawKey.Generate("RS256", RSABits: 1024);

        await AssertRefusedAndUnchangedAsync(account, await KeyChangeAsync(account, RawAccountJWS.KeyChange(key, account.URL, account.Key.JWK, KeyChangeURL)));

    }

    /// <summary>
    /// Refused - and the old key is the account's still.
    /// </summary>
    private async Task AssertRefusedAndUnchangedAsync(RawACMEAccount   Account,
                                                      RawACMEResponse  Answer)
    {

        var still = await Client.PostAsGetAsync(Account, Account.URL);

        Assert.Multiple(() => {
            AssertRefused(Answer);
            AssertStatus(still, 200);
        });

    }

}
