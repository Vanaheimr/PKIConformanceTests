using System.Text.Json.Nodes;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.4: an order - <i>"If the server is willing to issue
/// the requested certificate, it responds with a 201 (Created) response. The
/// body of this response is an order object reflecting the client's request
/// and any authorizations the client must complete before the certificate
/// will be issued."</i> - with the objects of sections 7.1.3 and 7.1.4, and
/// the identifiers of RFC 8738.
/// </summary>
/// <remarks>
/// What an order says is what a certificate will say: <i>"it MUST NOT issue a
/// certificate with contents other than those requested"</i>. A server that
/// takes a name it should not, or reads an identifier as another one, signs
/// what nobody asked for.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.4")]
public class NewOrderTests(String ServerName) : ACMEServerFixture(ServerName)
{

    private RawACMEAccount account = null!;

    [OneTimeSetUp]
    public async Task Arrange()
        => account = await NewAccountAsync();

    private static String RFC3339(JsonNode? Node)
        => Node?.GetValue<String>() ?? "";

    private static Boolean IsRFC3339(String Text)
        => System.Text.RegularExpressions.Regex.IsMatch(Text, @"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$");


    #region The order object

    /// <summary>
    /// 201, the order URL in Location, and the order object of section 7.1.3:
    /// <i>"status (required, string)"</i>, <i>"expires (optional, string):
    /// [...] This field is REQUIRED for objects with "pending" or "valid" in the
    /// status field."</i>, <i>"identifiers (required, array of object)"</i>,
    /// <i>"authorizations (required, array of string)"</i>, <i>"finalize
    /// (required, string)"</i> - and no <i>"error (optional, object): The
    /// error that occurred while processing the order, if any."</i>, of an
    /// order where none occurred yet.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, §7.1.3")]
    [Property("Level", "MUST")]
    public async Task A_New_Order_Is_201_With_Its_URL_And_Its_Object()
    {

        var other  = await NewAccountAsync();
        var answer = await Client.NewOrderAsync(other, Loopback4, Loopback6);

        Assert.Multiple(() => {
            AssertStatus(answer, 201);
            Assert.That(Uri.IsWellFormedUriString(answer.Location, UriKind.Absolute), Is.True,                 $"Location: {answer}");
            Assert.That(answer.StringOf("status"),                                    Is.EqualTo("pending"),    answer.ToString());
            Assert.That(IsRFC3339(RFC3339(answer.Object?["expires"])),               Is.True,                   $"\"expires\" of RFC 3339: {answer}");
            Assert.That(answer.Object?["identifiers"]?.AsArray().Count,               Is.EqualTo(2),            answer.ToString());
            Assert.That(answer.StringsOf("authorizations"),                           Has.Count.EqualTo(2),     $"one authorization of each name: {answer}");
            Assert.That(answer.StringOf("finalize"),                                  Is.Not.Null,              answer.ToString());
            Assert.That(answer.Object?.ContainsKey("error"),                          Is.False,                 $"no error: {answer}");
        });

    }

    /// <summary>
    /// Section 7.4: <i>"notBefore (optional, string): The requested value of
    /// the notBefore field in the certificate"</i>, the same of notAfter - and
    /// <i>"The server MUST return an error if it cannot fulfill the request as
    /// specified, and it MUST NOT issue a certificate with contents other than
    /// those requested."</i> An order that asks for one of the two alone:
    /// refused, or signed a certificate that says so. (The mutation sweep found
    /// that no test asked for a validity: a server that refused only an order
    /// of both, and signed one of either as if it had not been asked, passed.)
    /// </summary>
    [TestCase("notBefore")]
    [TestCase("notAfter")]
    [Property("Level", "MUST")]
    public async Task An_Order_Of_A_Validity_Is_Refused_Or_Signed_So(String Field)
    {

        var asked   = new DateTimeOffset(DateTimeOffset.UtcNow.Ticks / TimeSpan.TicksPerSecond * TimeSpan.TicksPerSecond, TimeSpan.Zero) +
                      (Field == "notBefore" ? TimeSpan.FromHours(1) : TimeSpan.FromDays(3));
        var answer  = await Client.PostAsync(account, Client.Resource("newOrder"),
                                             RawJson.Object(("identifiers", RawACMEClient.IdentifiersJSON([ Loopback4 ])),
                                                            (Field,         RawJson.Quote(asked.ToString("yyyy-MM-ddTHH:mm:ssZ")))));

        if (answer.Status != 201)
        {
            AssertProblem(answer, null);
            return;
        }

        var ready   = await Client.ReadyAsync(account, Host, new RawACMEOrder(answer.Location!, answer.Object!));
        var issued  = await Client.FinishAsync(account, ready, Loopback4);

        using var leaf = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(issued.LeafDER);

        var got     = new DateTimeOffset((Field == "notBefore" ? leaf.NotBefore : leaf.NotAfter).ToUniversalTime());

        Assert.That(got, Is.EqualTo(asked), $"the certificate's {Field}: {answer}");

    }

    /// <summary>
    /// Section 7.1.3: <i>"The elements of the "authorizations" and
    /// "identifiers" arrays are immutable once set. The server MUST NOT change
    /// the contents of either array after they are created."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.3")]
    [Property("Level", "MUST")]
    public async Task Its_identifiers_And_authorizations_Do_Not_Change()
    {

        var other    = await NewAccountAsync();
        var created  = await Client.NewOrderAsync(other, Loopback4);
        var proven   = await Client.ProveHTTP01Async(other, created.StringsOf("authorizations")[0], Host);
        var after    = await Client.PostAsGetAsync(other, created.Location!);

        Assert.Multiple(() => {
            Assert.That(proven.StringOf("status"),                      Is.EqualTo("valid"),                                  proven.ToString());
            Assert.That(after.StringsOf("authorizations"),              Is.EqualTo(created.StringsOf("authorizations")),       after.ToString());
            Assert.That(after.Object?["identifiers"]?.ToJsonString(),   Is.EqualTo(created.Object?["identifiers"]?.ToJsonString()), after.ToString());
        });

    }

    /// <summary>
    /// Section 7.1.4, the authorization object: <i>"identifier (required,
    /// object)"</i>, <i>"status (required, string)"</i>, <i>"challenges
    /// (required, array of objects)"</i> - and section 8: each challenge has
    /// <i>"type (required, string)"</i>, <i>"url (required, string)"</i>,
    /// <i>"status (required, string)"</i>.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.4, §8")]
    [Property("Level", "MUST")]
    public async Task Its_Authorizations_Are_Authorization_Objects()
    {

        var order  = await Client.OrderAsync(account, Loopback4);
        var authz  = await Client.PostAsGetAsync(account, order.Authorizations[0]);

        Assert.Multiple(() => {
            AssertStatus(authz, 200);
            Assert.That(authz.Object?["identifier"]?["type"]?.GetValue<String>(),  Is.EqualTo("ip"),        authz.ToString());
            Assert.That(authz.Object?["identifier"]?["value"]?.GetValue<String>(), Is.EqualTo("127.0.0.1"), authz.ToString());
            Assert.That(authz.StringOf("status"),                                  Is.AnyOf("pending", "valid"), authz.ToString());
            Assert.That(authz.Object?["challenges"]?.AsArray(),                    Is.Not.Empty,             authz.ToString());

            foreach (var challenge in (authz.Object?["challenges"] as JsonArray ?? []).OfType<JsonObject>())
            {
                Assert.That(challenge["type"]?.GetValue<String>(),   Is.Not.Null.And.Not.Empty, challenge.ToJsonString());
                Assert.That(challenge["url"]?.GetValue<String>(),    Is.Not.Null.And.Not.Empty, challenge.ToJsonString());
                Assert.That(challenge["status"]?.GetValue<String>(), Is.Not.Null.And.Not.Empty, challenge.ToJsonString());
            }
        });

    }

    /// <summary>
    /// Section 8.3 (and 8.4): <i>"token (required, string): A random value that
    /// uniquely identifies the challenge. This value MUST have at least 128
    /// bits of entropy. It MUST NOT contain any characters outside the
    /// base64url alphabet and MUST NOT include base64 padding characters
    /// ("=")."</i> - every token of 20 orders: base64url of 16 octets at
    /// least, and no two alike.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, §8.4")]
    [Property("Level", "MUST")]
    public async Task Every_Token_Is_base64url_Of_128_Bits_At_Least_And_Unique()
    {

        var tokens = new List<String>();

        for (var i = 0; i < 20; i++)
        {
            var other = await NewAccountAsync();
            var order = await Client.OrderAsync(other, Loopback4);
            var authz = await Client.PostAsGetAsync(other, order.Authorizations[0]);
            tokens.AddRange((authz.Object?["challenges"] as JsonArray ?? []).OfType<JsonObject>().Select(challenge => challenge["token"]!.GetValue<String>()));
        }

        using (Assert.EnterMultipleScope())
        {
            Assert.That(tokens.Distinct().Count(), Is.EqualTo(tokens.Count), "unique");
            foreach (var token in tokens)
            {
                Assert.That(RawBase64Url.TryDecode(token, out var octets, out var error), Is.True, $"{token}: {error}");
                Assert.That(octets?.Length ?? 0, Is.GreaterThanOrEqualTo(16), $"{token}: 128 bits at least");
            }
        }

    }

    #endregion

    #region Identifiers

    /// <summary>
    /// Section 7.4: <i>"identifiers (required, array of object)"</i> - none, or
    /// an empty array, is no order.
    /// </summary>
    [TestCase("""{}""")]
    [TestCase("""{"identifiers":[]}""")]
    [TestCase("""{"identifiers":"127.0.0.1"}""")]
    [TestCase("""{"identifiers":[{"type":"ip"}]}""")]
    [Property("Level", "MUST")]
    public async Task An_Order_Without_Identifiers_Is_Refused(String Payload)

        => AssertProblem(await Client.PostAsync(account, Client.Resource("newOrder"), Payload), 400);

    /// <summary>
    /// An identifier of a type the server does not know: section 6.7,
    /// <i>"unsupportedIdentifier: An identifier is of an unsupported type"</i>.
    /// </summary>
    [TestCase("email", "admin@example.org")]
    [TestCase("DNS",   "example.org")]
    [TestCase("",      "example.org")]
    [Property("RFC", "8555 §7.4, §6.7")]
    [Property("Level", "SHOULD")]
    public async Task An_Identifier_Of_An_Unknown_Type_Is_unsupportedIdentifier(String Type, String Value)

        => AssertProblem(await Client.NewOrderAsync(account, (Type, Value)), 400, "unsupportedIdentifier");

    /// <summary>
    /// Section 7.1.3: a wildcard is <i>"a single asterisk character followed by
    /// a single full stop character ("*.") followed by a domain name as defined
    /// for use in the Subject Alternate Name Extension by [RFC5280]"</i> - and
    /// section 7.1.4: <i>"The domain name MUST be encoded in the form in which
    /// it would appear in a certificate."</i>, <i>"Wildcard domain names (with
    /// "*" as the first label) MUST NOT be included in authorization
    /// objects."</i> Names that are none of these are refused.
    /// </summary>
    [TestCase("*.*.example.org",                     Description = "two wildcards")]
    [TestCase("www.*.example.org",                   Description = "a wildcard not in front")]
    [TestCase("*example.org",                        Description = "an asterisk without its full stop")]
    [TestCase("exa mple.org",                        Description = "a space")]
    [TestCase("example..org",                        Description = "an empty label")]
    [TestCase("-example.org",                        Description = "a label that starts with a hyphen")]
    [TestCase("https://example.org",                 Description = "a URL")]
    [TestCase("www.example.org/path",                Description = "a path")]
    [TestCase("exämple.org",                    Description = "a U-label, where a certificate has the A-label")]
    [Property("RFC", "8555 §7.1.3, §7.1.4")]
    [Property("Level", "MUST")]
    public async Task A_dns_Identifier_That_Is_No_Name_Of_A_Certificate_Is_Refused(String Name)

        => AssertProblem(await Client.NewOrderAsync(account, ("dns", Name)), 400, "malformed", "rejectedIdentifier");

    /// <summary>
    /// RFC 1035, section 2.3.4: <i>"labels 63 octets or less"</i>, <i>"names 255
    /// octets or less"</i> - which RFC 5280 takes over for a dNSName.
    /// </summary>
    [TestCase(64,  1, Description = "a label of 64")]
    [TestCase(63,  5, Description = "a name of 320")]
    [Property("RFC", "8555 §7.1.4, 1035 §2.3.4")]
    [Property("Level", "MUST")]
    public async Task A_dns_Identifier_Too_Long_Is_Refused(Int32 LabelLength, Int32 Labels)
    {

        var name = String.Join('.', Enumerable.Repeat(new String('a', LabelLength), Labels)) + ".example.org";

        AssertProblem(await Client.NewOrderAsync(account, ("dns", name)), 400, "malformed", "rejectedIdentifier");

    }

    /// <summary>
    /// Section 7.1.4: <i>"Servers MUST verify any identifier values that begin
    /// with the ASCII-Compatible Encoding prefix "xn--" as defined in [RFC5890]
    /// are properly encoded."</i> - "xn--" followed by nothing, by Punycode
    /// (RFC 3492) of nothing but ASCII, which no U-label is (RFC 5890, section
    /// 2.3.2.1), and by Punycode that overflows (RFC 3492, section 6.4).
    /// </summary>
    [TestCase("xn--.example.org",                Description = "nothing after the prefix")]
    [TestCase("xn--abc-.example.org",            Description = "ASCII alone: no U-label")]
    [TestCase("xn--99999999999999.example.org",  Description = "Punycode that overflows - S-8", Category = TestCategories.KnownIssue)]
    [Property("RFC", "8555 §7.1.4, 5890")]
    [Property("Level", "MUST")]
    public async Task An_xn_Label_That_Is_No_A_Label_Is_Refused(String Name)

        => AssertProblem(await Client.NewOrderAsync(account, ("dns", Name)), 400, "malformed", "rejectedIdentifier");

    /// <summary>
    /// The control of the A-labels: one that is proper - "xn--mnchen-3ya", of
    /// "münchen" - is taken.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.4, 5890")]
    [Property("Level", "MUST")]
    public async Task A_Proper_A_Label_Is_Taken()

        => AssertStatus(await Client.NewOrderAsync(account, ("dns", "xn--mnchen-3ya.example.org")), 201);

    /// <summary>
    /// Section 7.1.3: <i>"An authorization returned by the server for a
    /// wildcard domain name identifier MUST NOT include the asterisk and full
    /// stop ("*.") prefix in the authorization identifier value. The returned
    /// authorization MUST include the optional "wildcard" field, with a value
    /// of true."</i> - and section 7.1.4 of the field: <i>"For other
    /// authorizations, it MUST be absent."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.3, §7.1.4")]
    [Property("Level", "MUST")]
    public async Task The_Authorization_Of_A_Wildcard_Is_Of_The_Base_Name_And_Says_wildcard()
    {

        var order      = await Client.OrderAsync(account, ("dns", "*.wildcard.example.org"), ("dns", "plain.example.org"));
        var answers    = await Task.WhenAll(order.Authorizations.Select(url => Client.PostAsGetAsync(account, url)));

        var wildcard   = answers.Single(answer => answer.Object?["identifier"]?["value"]?.GetValue<String>() is "wildcard.example.org" or "*.wildcard.example.org");
        var plain      = answers.Single(answer => answer.Object?["identifier"]?["value"]?.GetValue<String>() == "plain.example.org");

        Assert.Multiple(() => {
            Assert.That(wildcard.Object?["identifier"]?["value"]?.GetValue<String>(), Is.EqualTo("wildcard.example.org"), wildcard.ToString());
            Assert.That(wildcard.Object?["wildcard"]?.GetValue<Boolean>(),            Is.True,                         wildcard.ToString());
            Assert.That(plain.Object?.ContainsKey("wildcard"),                         Is.False,                        plain.ToString());
        });

    }

    /// <summary>
    /// RFC 8738, section 3: <i>"An identifier for the IPv6 address 2001:db8::1
    /// would be formatted like so: {"type": "ip", "value": "2001:db8::1"}"</i>
    /// - an order of addresses of both families, and its authorizations of
    /// the type "ip".
    /// </summary>
    [Test]
    [Property("RFC", "8738 §3")]
    [Property("Level", "MUST")]
    public async Task An_Order_Of_Addresses_Has_Authorizations_Of_ip()
    {

        var order    = await Client.OrderAsync(account, ("ip", "192.0.2.1"), ("ip", "2001:db8::1"));
        var answers  = await Task.WhenAll(order.Authorizations.Select(url => Client.PostAsGetAsync(account, url)));

        Assert.That(answers.Select(answer => $"{answer.Object?["identifier"]?["type"]} {answer.Object?["identifier"]?["value"]}"),
                    Is.EquivalentTo(new[] { "ip 192.0.2.1", "ip 2001:db8::1" }));

    }

    /// <summary>
    /// RFC 8738, section 7: <i>"The existing "dns-01" challenge MUST NOT be used
    /// to validate IP identifiers."</i> - so no authorization of an address
    /// offers it.
    /// </summary>
    [Test]
    [Property("RFC", "8738 §7")]
    [Property("Level", "MUST")]
    public async Task No_Authorization_Of_An_Address_Offers_dns_01()
    {

        var order    = await Client.OrderAsync(account, ("ip", "192.0.2.2"), ("ip", "2001:db8::2"));
        var answers  = await Task.WhenAll(order.Authorizations.Select(url => Client.PostAsGetAsync(account, url)));

        using (Assert.EnterMultipleScope())
        {
            foreach (var answer in answers)
                Assert.That(RawACMEClient.ChallengeOf(answer, "dns-01"), Is.Null, answer.ToString());
        }

    }

    /// <summary>
    /// RFC 8738, section 3: <i>"The value field MUST contain the textual form of
    /// the address as defined in Section 2.1 of [RFC1123] for IPv4 and in
    /// Section 4 of [RFC5952] for IPv6."</i> - forms that are not: a server
    /// refuses them, or keeps them as the address they say in that form; it
    /// never reads them as another address (an interpretation: section 7.4,
    /// <i>"MUST NOT issue a certificate with contents other than those
    /// requested"</i>).
    /// </summary>
    [TestCase("010.0.0.1",          "10.0.0.1",   Description = "a leading zero, which inet_aton reads as octal: 8.0.0.1 - S-9", Category = TestCategories.KnownIssue)]
    [TestCase("0x7f.0.0.1",         "127.0.0.1",  Description = "hexadecimal")]
    [TestCase("127.1",              "127.0.0.1",  Description = "two parts, which inet_aton reads as 127.0.0.1")]
    [TestCase("3221225985",         "192.0.2.1",  Description = "one number")]
    [Property("RFC", "8738 §3, 8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task An_Address_Not_In_Its_Textual_Form_Is_Refused_Or_Read_As_Written(String Written, String Decimal)
    {

        var answer = await Client.NewOrderAsync(account, ("ip", Written));

        if (answer.Status != 201)
        {
            AssertProblem(answer, 400, "malformed", "rejectedIdentifier", "unsupportedIdentifier");
            return;
        }

        var value = answer.Object?["identifiers"]?[0]?["value"]?.GetValue<String>();

        Assert.That(value, Is.EqualTo(Written).Or.EqualTo(Decimal), $"\"{Written}\" became \"{value}\": {answer}");

    }

    /// <summary>
    /// An address is of the type "ip" (RFC 8738): as a "dns" identifier it is
    /// no domain name, and is refused.
    /// </summary>
    [TestCase("127.0.0.1")]
    [TestCase("::1")]
    [Property("RFC", "8738 §3, 8555 §7.1.4")]
    [Property("Level", "MUST")]
    public async Task An_Address_As_A_dns_Identifier_Is_Refused(String Address)

        => AssertProblem(await Client.NewOrderAsync(account, ("dns", Address)), 400, "malformed", "rejectedIdentifier");

    /// <summary>
    /// RFC 8738: an "ip" identifier is an address, not a network or a name.
    /// </summary>
    [TestCase("10.0.0.0/8")]
    [TestCase("fe80::1%eth0")]
    [TestCase("example.org")]
    [TestCase("256.0.0.1")]
    [Property("RFC", "8738 §3")]
    [Property("Level", "MUST")]
    public async Task An_ip_Identifier_That_Is_No_Address_Is_Refused(String Value)

        => AssertProblem(await Client.NewOrderAsync(account, ("ip", Value)), 400, "malformed", "rejectedIdentifier");

    #endregion

}
