using System.Text.Json.Nodes;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.3.4: an account opened with an external account
/// binding - a JWS of the account key, MACed with a key the CA handed out of
/// band. <i>"To verify the account binding, the CA MUST take the following
/// steps: 1. Verify that the value of the field is a well-formed JWS 2.
/// Verify that the JWS protected field meets the above criteria 3. Retrieve
/// the MAC key corresponding to the key identifier in the "kid" field 4.
/// Verify that the MAC on the JWS verifies using that MAC key 5. Verify that
/// the payload of the JWS represents the same key as was used to verify the
/// outer JWS (i.e., the "jwk" field of the outer JWS)"</i> [...] <i>"If any of
/// these checks fail, then the CA MUST reject the newAccount request."</i>
/// </summary>
/// <remarks>
/// A server that requires a binding lets in only who it gave a key: a binding
/// it does not check lets in everybody, and one whose payload it does not
/// compare with the outer key lets a key it gave out bind any account key.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.3.4")]
public class ExternalAccountBindingTests(String ServerName) : ACMEServerFixture(ServerName)
{

    protected override ACMEServerOptions Options(UInt16 HTTP01Port)
        => new (HTTP01Port: HTTP01Port, ExternalAccountRequired: true);

    private String NewAccountURL
        => Client.Resource("newAccount");

    /// <summary>
    /// The payload of a newAccount request with the binding.
    /// </summary>
    private static String WithBinding(String BindingJSON)
        => $$"""{"termsOfServiceAgreed":true,"externalAccountBinding":{{BindingJSON}}}""";

    /// <summary>
    /// A binding of the key, by a key of the server, changed as the test says.
    /// </summary>
    private async Task<String> BindingAsync(RawKey                   AccountKey,
                                            String                   Algorithm   = "HS256",
                                            Func<String, String>?    KeyId       = null,
                                            Byte[]?                  MACKey      = null,
                                            String?                  URL         = null,
                                            String?                  Nonce       = null,
                                            RawJWK?                  Bound       = null)
    {

        var (kid, mac) = await Server.NewExternalAccountKeyAsync();

        var header     = new Core.Scripted.JWSHeader().SetString("alg", Algorithm).SetString("kid", KeyId?.Invoke(kid) ?? kid);

        if (Nonce is not null)
            header.SetString("nonce", Nonce);

        header.SetString("url", URL ?? NewAccountURL);

        var key        = MACKey ?? mac;

        return RawJWS.Sign(data => Algorithm switch {
                                       "HS384" => System.Security.Cryptography.HMACSHA384.HashData(key, data),
                                       "HS512" => System.Security.Cryptography.HMACSHA512.HashData(key, data),
                                       _       => System.Security.Cryptography.HMACSHA256.HashData(key, data)
                                   },
                           header.ToJSON(),
                           (Bound ?? AccountKey.JWK).ToJSON()).ToFlattenedJSON();

    }


    [Test]
    [Property("RFC", "8555 §7.1.1, §7.3.4")]
    [Property("Level", "MUST")]
    public void The_Directory_Says_A_Binding_Is_Required()
        => Assert.That(Client.Directory["meta"]?["externalAccountRequired"]?.GetValue<Boolean>(), Is.True, Client.Directory.ToJsonString());

    /// <summary>
    /// <i>"If the CA receives a newAccount request without an
    /// "externalAccountBinding" field, then it SHOULD reply with an error of
    /// type "externalAccountRequired"."</i>
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task A_New_Account_Without_A_Binding_Is_externalAccountRequired()
    {

        var (account, answer) = await Client.NewAccountAsync();

        Assert.Multiple(() => {
            AssertProblem(answer, null, "externalAccountRequired");
            Assert.That(account, Is.Null);
        });

    }

    /// <summary>
    /// A binding that holds, of each MAC of RFC 7518 a binding is made with:
    /// the account is opened.
    /// </summary>
    [TestCase("HS256")]
    [TestCase("HS384")]
    [TestCase("HS512")]
    [Property("Level", "MUST")]
    public async Task A_Binding_That_Holds_Opens_The_Account(String Algorithm)
    {

        using var key         = RawKey.Generate("ES256");
        var (account, answer) = await Client.NewAccountAsync(key, WithBinding(await BindingAsync(key, Algorithm)));

        Assert.Multiple(() => {
            AssertStatus(answer, 201);
            Assert.That(account, Is.Not.Null, answer.ToString());
        });

    }

    /// <summary>
    /// <i>"If all of these checks pass and the CA creates a new account, then
    /// the CA may consider the new account associated with the external
    /// account corresponding to the MAC key. The account object the CA returns
    /// MUST include an "externalAccountBinding" field with the same value as
    /// the field in the request."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-6")]
    public async Task The_New_Account_Object_Has_The_Binding_As_It_Was_Sent()
    {

        using var key  = RawKey.Generate("ES256");
        var binding    = await BindingAsync(key);
        var (_, answer) = await Client.NewAccountAsync(key, WithBinding(binding));

        Assert.Multiple(() => {
            AssertStatus(answer, 201);
            Assert.That(answer.Object?["externalAccountBinding"]?.ToJsonString(), Is.EqualTo(JsonNode.Parse(binding)!.ToJsonString()), answer.ToString());
        });

    }

    /// <summary>
    /// Step 4: the MAC of another key does not verify.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Binding_MACed_With_Another_Key_Is_Refused()
    {

        using var key  = RawKey.Generate("ES256");
        var binding    = await BindingAsync(key, MACKey: System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));

        var (account, answer) = await Client.NewAccountAsync(key, WithBinding(binding));

        Assert.Multiple(() => {
            AssertProblem(answer, null);
            Assert.That(account, Is.Null);
        });

    }

    /// <summary>
    /// Step 3: a "kid" the CA never gave has no MAC key.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Binding_Of_A_kid_The_CA_Never_Gave_Is_Refused()
    {

        using var key  = RawKey.Generate("ES256");
        var binding    = await BindingAsync(key, KeyId: kid => kid + "-not");

        AssertProblem((await Client.NewAccountAsync(key, WithBinding(binding))).Response, null);

    }

    /// <summary>
    /// Step 2: <i>"The "url" field MUST be set to the same value as the outer
    /// JWS"</i>.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Binding_For_Another_URL_Is_Refused()
    {

        using var key  = RawKey.Generate("ES256");
        var binding    = await BindingAsync(key, URL: Client.Resource("newOrder"));

        AssertProblem((await Client.NewAccountAsync(key, WithBinding(binding))).Response, null);

    }

    /// <summary>
    /// Step 2: <i>"The "nonce" field MUST NOT be present"</i>.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Binding_With_A_Nonce_Is_Refused()
    {

        using var key  = RawKey.Generate("ES256");
        var binding    = await BindingAsync(key, Nonce: await Client.FreshNonceAsync());

        AssertProblem((await Client.NewAccountAsync(key, WithBinding(binding))).Response, null);

    }

    /// <summary>
    /// Step 5: the binding is of another key than the one that signed the
    /// request - a key of the CA lent to bind somebody else's account key.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Binding_Of_Another_Account_Key_Is_Refused()
    {

        using var key    = RawKey.Generate("ES256");
        using var other  = RawKey.Generate("ES256");
        var binding      = await BindingAsync(key, Bound: other.JWK);

        AssertProblem((await Client.NewAccountAsync(key, WithBinding(binding))).Response, null);

    }

    /// <summary>
    /// Step 2: <i>"The "alg" field MUST indicate a MAC-based algorithm"</i> -
    /// a binding signed by the account key itself binds nothing.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Binding_Signed_Instead_Of_MACed_Is_Refused()
    {

        using var key  = RawKey.Generate("ES256");
        var (kid, _)   = await Server.NewExternalAccountKeyAsync();

        var binding    = RawJWS.Sign(key,
                                     RawJson.Object(("alg", RawJson.Quote("ES256")), ("kid", RawJson.Quote(kid)), ("url", RawJson.Quote(NewAccountURL))),
                                     key.JWK.ToJSON()).ToFlattenedJSON();

        AssertProblem((await Client.NewAccountAsync(key, WithBinding(binding))).Response, null);

    }

    /// <summary>
    /// Step 1: <i>"Verify that the value of the field is a well-formed JWS"</i>.
    /// </summary>
    [TestCase("\"a string\"")]
    [TestCase("""{"protected":"e30","payload":"e30"}""")]
    [TestCase("[]")]
    [Property("Level", "MUST")]
    public async Task A_Binding_That_Is_No_JWS_Is_Refused(String Binding)
    {

        using var key = RawKey.Generate("ES256");

        AssertProblem((await Client.NewAccountAsync(key, WithBinding(Binding))).Response, null);

    }

}
