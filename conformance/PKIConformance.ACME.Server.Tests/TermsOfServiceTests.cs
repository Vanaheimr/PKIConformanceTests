using NUnit.Framework;

using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.3: <i>"If the server wishes to require the client to
/// agree to terms under which the ACME service is to be used, it MUST
/// indicate the URL where such terms can be accessed in the "termsOfService"
/// subfield of the "meta" field in the directory object, and the server MUST
/// reject newAccount requests that do not have the "termsOfServiceAgreed"
/// field set to "true"."</i>
/// </summary>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.3")]
public class TermsOfServiceTests(String ServerName) : ACMEServerFixture(ServerName)
{

    private const String Terms = "https://pki.example.org/acme/terms-2026-11.pdf";

    protected override ACMEServerOptions Options(UInt16 HTTP01Port)
        => new (HTTP01Port: HTTP01Port, TermsOfService: Terms);


    [Test]
    [Property("RFC", "8555 §7.1.1, §7.3")]
    [Property("Level", "MUST")]
    public void The_Directory_Names_The_Terms()
        => Assert.That(Client.Directory["meta"]?["termsOfService"]?.GetValue<String>(), Is.EqualTo(Terms), Client.Directory.ToJsonString());

    /// <summary>
    /// Without "termsOfServiceAgreed", with it false, with it "true" as a
    /// string: refused, and no account.
    /// </summary>
    [TestCase("""{}""")]
    [TestCase("""{"termsOfServiceAgreed":false}""")]
    [TestCase("""{"termsOfServiceAgreed":"true"}""")]
    [TestCase("""{"contact":["mailto:admin@example.org"]}""")]
    [Property("Level", "MUST")]
    public async Task A_New_Account_That_Does_Not_Agree_Is_Refused(String Payload)
    {

        var (account, answer) = await Client.NewAccountAsync(PayloadJSON: Payload);

        Assert.Multiple(() => {
            AssertProblem(answer, null);
            Assert.That(account, Is.Null, answer.ToString());
        });

    }

    /// <summary>
    /// The control: agreed, opened - and the account object says so
    /// (section 7.1.2, "termsOfServiceAgreed").
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_New_Account_That_Agrees_Is_Opened()
    {

        var (account, answer) = await Client.NewAccountAsync();

        Assert.Multiple(() => {
            AssertStatus(answer, 201);
            Assert.That(account, Is.Not.Null, answer.ToString());
        });

    }

    /// <summary>
    /// Section 7.3.2: an update's "termsOfServiceAgreed" is ignored - false
    /// does not take the agreement back, nor is the update refused for it.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    public async Task An_Update_Of_termsOfServiceAgreed_Is_Ignored()
    {

        var account = await NewAccountAsync();
        var answer  = await Client.PostAsync(account, account.URL, """{"termsOfServiceAgreed":false}""");
        var after   = await Client.PostAsGetAsync(account, account.URL);

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            AssertStatus(after,  200);
            Assert.That(after.StringOf("status"), Is.EqualTo("valid"), after.ToString());
        });

    }

}
