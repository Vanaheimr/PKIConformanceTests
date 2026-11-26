using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Validation.Tests;

/// <summary>
/// RFC 8555, section 8.4, dns-01: <i>"1. Compute the SHA-256 digest
/// [FIPS180-4] of the stored key authorization 2. Query for TXT records for
/// the validation domain name 3. Verify that the contents of one of the TXT
/// records match the digest value"</i> - the validation domain name being
/// <i>"the "_acme-challenge" label to the domain name being validated"</i>.
/// </summary>
/// <remarks>
/// <para>
/// The server under test asks the bench's name server through Hermod's
/// DNSClient (PLAN.md, section 0.3), as if it were its resolver: the zone
/// "acme.test" is the test's, record by record.
/// </para>
/// <para>
/// dns-01 is the proof of a wildcard, and of a name whose web server a CA
/// cannot reach: a validator that takes a record of another name, or no
/// record, issues certificates for whole domains nobody proved.
/// </para>
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §8.4")]
[Category(TestCategories.KnownIssue)]
[Property("Finding", "V-1")]
public class DNS01ValidationTests(String ServerName) : ValidationFixture(ServerName)
{

    private Int32 names;

    /// <summary>
    /// A name of the zone no other test uses.
    /// </summary>
    private String NewName()
        => $"n{Interlocked.Increment(ref names)}-{Guid.NewGuid():N}"[..20] + ".acme.test";

    private static String ValidationName(String Name)
        => $"_acme-challenge.{Name}";

    private Task<Validation> ProvenAsync(String Name, Action<String, String> Arrange)
        => ValidateAsync(("dns", Name), "dns-01", Arrange);

    /// <summary>
    /// No proof - after the validation name was asked for: a validator that
    /// never asks refuses every answer, the wrong ones among them, and proves
    /// nothing by it.
    /// </summary>
    private void AssertNoProof(Validation  Validation,
                               String      Name)
    {
        Assert.Multiple(() => {
            Assert.That(DNS.QuestionsFor(ValidationName(Name)), Is.Not.Empty,          $"the validation name {ValidationName(Name)} was asked for: {Validation}");
            Assert.That(Validation.Status,                       Is.EqualTo("invalid"), Validation.ToString());
        });
    }


    /// <summary>
    /// The digest as a TXT record of the validation domain name: valid - and
    /// the record asked for was that one, of the type TXT.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Digest_At_The_Validation_Name_Is_Taken()
    {

        var name       = NewName();
        var validation = await ProvenAsync(name, (_, keyAuthorization) => DNS.AddTXT(ValidationName(name), RawChallenge.DNS01Value(keyAuthorization)));

        Assert.Multiple(() => {
            Assert.That(validation.Status,                                               Is.EqualTo("valid"), validation.ToString());
            Assert.That(DNS.QuestionsFor(ValidationName(name)).Select(question => question.Type), Does.Contain(ScriptedDNSServer.Types.TXT), "a TXT question of the validation name");
        });

    }

    /// <summary>
    /// <i>"Verify that the contents of one of the TXT records match the digest
    /// value"</i> - one among others: the digest of an earlier attempt, and
    /// text of nobody's.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Digest_Among_Other_Records_Is_Taken()
    {

        var name       = NewName();
        var validation = await ProvenAsync(name, (_, keyAuthorization) => {
                             DNS.AddTXT(ValidationName(name), "v=spf1 -all");
                             DNS.AddTXT(ValidationName(name), RawChallenge.DNS01Value("an.earlier-attempt"));
                             DNS.AddTXT(ValidationName(name), RawChallenge.DNS01Value(keyAuthorization));
                         });

        Assert.That(validation.Status, Is.EqualTo("valid"), validation.ToString());

    }

    /// <summary>
    /// What is not the digest - the key authorization itself, the digest of
    /// another, the digest in base64 with its padding, the digest at the name
    /// instead of its validation name - is no proof.
    /// </summary>
    [TestCase("the key authorization itself")]
    [TestCase("another digest")]
    [TestCase("base64 with padding")]
    [TestCase("at the name itself")]
    [Property("Level", "MUST")]
    public async Task What_Is_Not_The_Digest_At_The_Validation_Name_Is_No_Proof(String What)
    {

        var name       = NewName();
        var validation = await ProvenAsync(name, (_, keyAuthorization) => {

                             var digest = RawChallenge.DNS01Value(keyAuthorization);

                             switch (What)
                             {
                                 case "the key authorization itself": DNS.AddTXT(ValidationName(name), keyAuthorization);                                                     break;
                                 case "another digest":               DNS.AddTXT(ValidationName(name), RawChallenge.DNS01Value(keyAuthorization + "x"));                      break;
                                 case "base64 with padding":          DNS.AddTXT(ValidationName(name), Convert.ToBase64String(RawBase64Url.Decode(digest)));                break;
                                 default:                             DNS.AddTXT(name, digest);                                                                              break;
                             }

                         });

        Assert.Multiple(() => {
            AssertNoProof(validation, name);
            Assert.That(validation.ErrorType, Is.Not.Null,           $"the challenge's \"error\": {validation}");
        });

    }

    /// <summary>
    /// <i>"If no DNS record is found [...] then the validation fails."</i> -
    /// NXDOMAIN, a name without a TXT record, a name server that fails.
    /// </summary>
    [TestCase("NXDOMAIN")]
    [TestCase("no TXT")]
    [TestCase("SERVFAIL")]
    [Property("Level", "MUST")]
    public async Task No_Record_Is_No_Proof(String How)
    {

        var name       = NewName();
        var validation = await ProvenAsync(name, (_, _) => {
                             if (How == "no TXT")
                                 DNS.AddEmpty(ValidationName(name));
                             else if (How == "SERVFAIL")
                                 DNS.ServFail[ValidationName(name)] = true;
                         });

        AssertNoProof(validation, name);

    }

    /// <summary>
    /// A name server that never answers: the validation fails, in its time.
    /// </summary>
    [Test]
    [Category(TestCategories.Slow)]
    [Property("Level", "MUST")]
    public async Task A_Name_Server_That_Never_Answers_Is_No_Proof()
    {

        var name       = NewName();
        var validation = await ProvenAsync(name, (_, _) => DNS.Silent[ValidationName(name)] = true);

        AssertNoProof(validation, name);

    }

    /// <summary>
    /// A wildcard is proven at the validation name of its base name: section
    /// 8.4, <i>"the "_acme-challenge" label to the domain name being
    /// validated"</i>, which for "*.example.org" is "example.org" (section
    /// 7.1.3: <i>"MUST NOT include the asterisk and full stop"</i>).
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.4, §7.1.3")]
    [Property("Level", "MUST")]
    public async Task A_Wildcard_Is_Proven_At_Its_Base_Name()
    {

        var name       = NewName();
        var validation = await ValidateAsync(("dns", "*." + name), "dns-01",
                                             (_, keyAuthorization) => DNS.AddTXT(ValidationName(name), RawChallenge.DNS01Value(keyAuthorization)));

        Assert.That(validation.Status, Is.EqualTo("valid"), validation.ToString());

    }

    /// <summary>
    /// The validation name delegated by a CNAME to a zone of its own - as
    /// operators do so that the ACME client may write there and nowhere else,
    /// and as Let's Encrypt follows it. A resolver answers with the chain;
    /// the record at its end is the one that counts. (RFC 8555 does not say;
    /// an interpretation, with every public CA.)
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.4, 1034 §3.6.2")]
    [Property("Level", "SHOULD")]
    public async Task A_Validation_Name_Delegated_By_CNAME_Is_Followed()
    {

        var name       = NewName();
        var delegated  = "challenges." + NewName();

        var validation = await ProvenAsync(name, (_, keyAuthorization) => {
                             DNS.AddCNAME(ValidationName(name), delegated);
                             DNS.AddTXT(delegated, RawChallenge.DNS01Value(keyAuthorization));
                         });

        Assert.That(validation.Status, Is.EqualTo("valid"), validation.ToString());

    }

    /// <summary>
    /// A TXT record is one or more character-strings (RFC 1035, section
    /// 3.3.14); the digest split into two of them, as some DNS providers
    /// store a value, is the strings joined - as Let's Encrypt reads it. (An
    /// interpretation: RFC 8555 says "the contents of one of the TXT records".)
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.4, 1035 §3.3.14")]
    [Property("Level", "SHOULD")]
    public async Task A_Digest_In_Two_Strings_Of_One_Record_Is_Taken()
    {

        var name       = NewName();
        var validation = await ProvenAsync(name, (_, keyAuthorization) => {
                             var digest = RawChallenge.DNS01Value(keyAuthorization);
                             DNS.AddTXT(ValidationName(name), digest[..20], digest[20..]);
                         });

        Assert.That(validation.Status, Is.EqualTo("valid"), validation.ToString());

    }

    /// <summary>
    /// The digest in two records of the name, half in each: no record has it.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Digest_Split_Over_Two_Records_Is_No_Proof()
    {

        var name       = NewName();
        var validation = await ProvenAsync(name, (_, keyAuthorization) => {
                             var digest = RawChallenge.DNS01Value(keyAuthorization);
                             DNS.AddTXT(ValidationName(name), digest[..20]);
                             DNS.AddTXT(ValidationName(name), digest[20..]);
                         });

        AssertNoProof(validation, name);

    }

}
