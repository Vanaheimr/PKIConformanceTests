using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Validation.Tests;

/// <summary>
/// The bench's name server, asked the way the server under test asks it -
/// through Hermod's DNSClient - for what dns-01 needs: a TXT record of an
/// "_acme-challenge" name, in one string or in two, at the end of a CNAME;
/// and NXDOMAIN for a name it does not know.
/// </summary>
/// <remarks>
/// Not a test of anything under test: the proof that a dns-01 test that
/// fails, fails at the server and not at the bench. The names are given to
/// the client as a <see cref="DNSServiceName"/>, which takes an underscore
/// label - a <see cref="DomainName"/> is a host name and does not.
/// </remarks>
[Property("RFC", "1035")]
public class BenchNameServerTests
{

    private static async Task<IReadOnlyList<String>> TXTAsync(ScriptedDNSServer Server, String Name)
    {

        using var client = Server.NewDNSClient();
        var info         = await client.Query(DNSServiceName.Parse(Name), [ DNSResourceRecordTypes.TXT ], ForceUpdate: true);

        return [.. info.Answers.OfType<TXT>().Select(txt => String.Concat(txt.Strings))];

    }

    [Test]
    public async Task It_Answers_The_TXT_Records_Of_A_Validation_Name()
    {

        await using var server = new ScriptedDNSServer();

        server.AddTXT("_acme-challenge.bench.acme.test", "one");
        server.AddTXT("_acme-challenge.bench.acme.test", "tw", "o");

        Assert.That(await TXTAsync(server, "_acme-challenge.bench.acme.test"), Is.EquivalentTo(new[] { "one", "two" }));

    }

    [Test]
    public async Task It_Answers_With_The_Chain_Of_A_CNAME()
    {

        await using var server = new ScriptedDNSServer();

        server.AddCNAME("_acme-challenge.bench.acme.test", "delegated.bench.acme.test");
        server.AddTXT("delegated.bench.acme.test", "at the end");

        Assert.That(await TXTAsync(server, "_acme-challenge.bench.acme.test"), Is.EqualTo(new[] { "at the end" }));

    }

    [Test]
    public async Task It_Knows_No_Name_It_Was_Not_Given()
    {

        await using var server = new ScriptedDNSServer();

        var records = await TXTAsync(server, "_acme-challenge.nobody.acme.test");

        Assert.Multiple(() => {
            Assert.That(records,                                                   Is.Empty);
            Assert.That(server.QuestionsFor("_acme-challenge.nobody.acme.test"),   Is.Not.Empty);
        });

    }

}
