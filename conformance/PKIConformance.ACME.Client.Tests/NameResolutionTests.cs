using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;
using org.GraphDefined.Vanaheimr.Hermod.DNS;

using PKIConformance.Core;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// PLAN.md, section 0.3: every name is resolved through Hermod's DNSClient,
/// never through the operating system - the ACME client's own connections to
/// its server among them (ToDo T-C11).
/// </summary>
[TestFixture]
[Property("RFC", "PLAN §0.3")]
public class NameResolutionTests : ClientFixture
{

    /// <summary>
    /// ToDo T-C11: the client is given a DNSClient - the bench's name server,
    /// which alone knows "ca.acme.test" - and reaches its directory through it.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    [Category(TestCategories.ToDo)]
    [Property("ToDo", "T-C11")]
    public async Task The_Directory_Is_Reached_Through_Hermod_s_DNSClient()
    {

        await using var dns = new ScriptedDNSServer();
        dns.AddAddress("ca.acme.test", IPAddress.Loopback);

        var constructor = typeof(ACMEClient).GetConstructors().
                                             FirstOrDefault(candidate => candidate.GetParameters().Any(parameter => parameter.ParameterType == typeof(DNSClient)));

        if (constructor is null)
            Assert.Fail("T-C11: the ACME client takes no DNSClient yet; it resolves through the operating system.");

        var arguments = constructor!.GetParameters().
                                     Select(parameter => parameter.ParameterType == typeof(DNSClient)      ? dns.NewDNSClient()
                                                       : parameter.ParameterType == typeof(Uri)            ? new Uri($"http://ca.acme.test:{Server.Port}/directory")
                                                       : parameter.ParameterType == typeof(ACMEAccountKey) ? ACMEAccountKey.Generate()
                                                       : parameter.HasDefaultValue                         ? parameter.DefaultValue
                                                       : null).
                                     ToArray();

        using var client = (ACMEClient) constructor.Invoke(arguments);

        await client.GetDirectoryAsync();

        Assert.That(dns.QuestionsFor("ca.acme.test"), Is.Not.Empty);

    }

}
