using System.Text.Json.Nodes;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// RFC 8555, section 7.4: an order - its identifiers (and RFC 8738's
/// addresses), its profile (draft-ietf-acme-profiles), and what the client
/// does with the order object it gets back: <i>"Clients SHOULD check the
/// "status" field of an order to determine whether they need to take any
/// action"</i> (section 7.1.3), and <i>"Clients MUST NOT make any assumptions
/// about the sort order of "identifiers" or "authorizations" elements"</i>.
/// </summary>
[TestFixture]
[Property("RFC", "8555 §7.4")]
public class OrderTests : ClientFixture
{

    private IReadOnlyList<(String Type, String Value)> IdentifiersOf(ACMERequest NewOrder)

        => [ .. NewOrder.PayloadObject!["identifiers"]!.AsArray().Select(identifier => (identifier!["type"]!.GetValue<String>(), identifier["value"]!.GetValue<String>())) ];


    /// <summary>
    /// Section 7.4: <i>"identifiers (required, array of object): An array of
    /// identifier objects that the client wishes to submit an order for"</i> -
    /// a name as a DNS name in lower case, without its final dot, the wildcard
    /// as "*.", the same name once.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Identifiers_Are_The_Names_Asked_For()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client, "WWW.acme.test.", "acme.test", "*.acme.test", "www.acme.test");

        Assert.That(IdentifiersOf(Server.RequestsOf("newOrder").Single()),
                    Is.EquivalentTo(new[] { ("dns", "www.acme.test"), ("dns", "acme.test"), ("dns", "*.acme.test") }), Log);

    }

    /// <summary>
    /// RFC 8738, section 3: <i>"The value field of the identifier MUST contain
    /// the textual form of the address as defined in Section 2.1 of [RFC1123]
    /// for IPv4 and in Section 4 of [RFC5952] for IPv6."</i>
    /// </summary>
    [TestCase("127.0.0.1",            "127.0.0.1")]
    [TestCase("::1",                  "::1")]
    [TestCase("2001:DB8:0:0:0:0:0:1", "2001:db8::1")]
    [TestCase("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1")]
    [TestCase("::FFFF:192.0.2.1",     "::ffff:192.0.2.1")]
    [Property("RFC", "8738 §3; 5952 §4")]
    [Property("Level", "MUST")]
    public async Task An_Address_Is_In_The_Textual_Form_Of_RFC_1123_Or_RFC_5952(String Given, String OnTheWire)
    {

        var client = await ClientWithAccountAsync();
        ValidateByTheResponder();

        await ObtainAsync(client, Given);

        Assert.That(IdentifiersOf(Server.RequestsOf("newOrder").Single()), Is.EqualTo(new[] { ("ip", OnTheWire) }), Log);

    }

    /// <summary>
    /// draft-ietf-acme-profiles, section 4: <i>"profile (optional, string): The
    /// name of the profile, as advertised in the "profiles" field of the
    /// directory metadata object"</i> - sent when asked for, and echoed in
    /// the order.
    /// </summary>
    [Test]
    [Property("RFC", "draft-ietf-acme-profiles-03 §4")]
    [Property("Level", "MUST")]
    public async Task The_Profile_Asked_For_Is_Sent()
    {

        Server.Profiles = new Dictionary<String, String> { ["classic"] = "90 days", ["shortlived"] = "6 days" };

        var client = await ClientWithAccountAsync();
        await client.ObtainCertificateAsync([ Name ], Responders, Profile: "shortlived");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Server.RequestsOf("newOrder").Single().PayloadObject?["profile"]?.GetValue<String>(), Is.EqualTo("shortlived"), Log);
            Assert.That(Server.Orders.Single().Profile,                                                         Is.EqualTo("shortlived"));
        }

    }

    /// <summary>
    /// draft-ietf-acme-profiles, section 4: <i>"The client SHOULD NOT request a
    /// profile name that is not advertised in the server's Directory metadata
    /// object."</i> - neither one of another name, nor one of a server that
    /// advertises none.
    /// </summary>
    [TestCase("other profiles")]
    [TestCase("no profiles")]
    [Property("RFC", "draft-ietf-acme-profiles-03 §4")]
    [Property("Level", "SHOULD NOT")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "C-7")]
    public async Task A_Profile_The_Server_Does_Not_Advertise_Is_Not_Asked_For(String Advertised)
    {

        Server.Profiles = Advertised == "no profiles" ? null : new Dictionary<String, String> { ["classic"] = "90 days" };

        var client = await ClientWithAccountAsync();

        try
        {
            await client.ObtainCertificateAsync([ Name ], Responders, Profile: "shortlived");
        }
        catch (Exception)
        {
            // Refused, by the client or by the server: what counts is what was sent.
        }

        Assert.That(Server.RequestsOf("newOrder").Select(request => request.PayloadObject?["profile"]?.GetValue<String>()), Has.None.EqualTo("shortlived"), Log);

    }

    /// <summary>
    /// Section 7.4: <i>"Clients MUST NOT make any assumptions about the sort
    /// order of "identifiers" or "authorizations" elements in the returned
    /// order object."</i> - both reversed in every order object, and the
    /// order is fulfilled all the same.
    /// </summary>
    [Test]
    [Property("Level", "MUST NOT")]
    public async Task The_Order_Of_Identifiers_And_Authorizations_Is_Not_Assumed()
    {

        Server.After = (request, answer) => request.Resource is "newOrder" or "order" or "finalize" && answer.JSON?["authorizations"] is not null
                                                ? answer.MapJSON(order => {
                                                      order["authorizations"] = new JsonArray([ .. order["authorizations"]!.AsArray().Reverse().Select(node => node?.DeepClone()) ]);
                                                      order["identifiers"]    = new JsonArray([ .. order["identifiers"]!.AsArray().Reverse().Select(node => node?.DeepClone()) ]);
                                                  })
                                                : answer;

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client, "a.acme.test", "b.acme.test", "c.acme.test");

        Assert.That(certificate.Identifiers.Select(identifier => identifier.Value), Is.EquivalentTo(new[] { "a.acme.test", "b.acme.test", "c.acme.test" }), Log);

    }

    /// <summary>
    /// Section 7.1.3: <i>"Clients SHOULD check the "status" field of an order
    /// to determine whether they need to take any action."</i> - an order
    /// "ready" from the start, its authorizations won before, is finalized
    /// without a single challenge.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.3")]
    [Property("Level", "SHOULD")]
    public async Task An_Order_Ready_From_The_Start_Is_Finalized_Without_Challenges()
    {

        var client = await ClientWithAccountAsync();
        await ObtainAsync(client);

        var before = Server.Requests.Count;
        ZoneChanges.Clear();

        await ObtainAsync(client);

        var after  = Server.Requests.Skip(before).ToArray();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(Server.Orders.Last().Status,                                         Is.EqualTo("valid"));
            Assert.That(after.Where(request => request.Resource == "challenge"),             Is.Empty, Log);
            Assert.That(after.Count(request => request.Resource == "finalize"),              Is.EqualTo(1), Log);
            Assert.That(ZoneChanges,                                                         Is.Empty);
        }

    }

    /// <summary>
    /// An order that fails - its one authorization invalid - is an error that
    /// says why: the challenge's error, as the server put it.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.1.3, §7.5")]
    [Property("Level", "SHOULD")]
    public async Task A_Failed_Order_Is_An_Error_That_Says_Why()
    {

        var client = await ClientWithAccountAsync();
        Server.Validate = (_, _) => Task.FromResult((false, "The bench found the wrong answer at the wrong place."));

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Message,           Does.Contain("The bench found the wrong answer"), refused.Message);
            Assert.That(refused.Problem?.ShortType, Is.EqualTo("incorrectResponse"),                 refused.Message);
        }

    }

    /// <summary>
    /// Section 7.4: <i>"invalid": The certificate will not be issued. Consider
    /// this order process abandoned.</i> - a finalization answered with an
    /// invalid order and its error ends there, with the error.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Order_Invalid_After_Its_Finalization_Is_Abandoned()
    {

        var client = await ClientWithAccountAsync();

        Server.Before = request => {
                            if (request.Resource != "finalize")
                                return null;
                            var order    = Server.Orders.Single(candidate => candidate.Id == request.ResourceId);
                            order.Status = "invalid";
                            order.Error  = new JsonObject { ["type"] = ScriptedAnswer.ErrorPrefix + "badCSR", ["detail"] = "The bench does not like this key.", ["status"] = 400 };
                            return ScriptedAnswer.Json(200, ScriptedACMEServer.OrderJSON(order));
                        };

        var refused = await Assert.ThrowsAsync<ACMEException>(() => ObtainAsync(client));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(refused!.Message,                 Does.Contain("The bench does not like this key."), refused.Message);
            Assert.That(Server.RequestsOf("certificate"), Is.Empty, Log);
        }

    }

}
