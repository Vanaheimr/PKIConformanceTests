using Newtonsoft.Json.Linq;

using NUnit.Framework;

using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.1.1: the directory - the one URL a client is
/// configured with, and from which it learns every other.
/// </summary>
/// <remarks>
/// <para>
/// <i>"In order to help clients configure themselves with the right URLs for
/// each ACME operation, ACME servers provide a directory object. This should
/// be the only URL needed to configure clients."</i>
/// </para>
/// <para>
/// A client that builds a URL itself instead of taking it from here works
/// against one server and no other; the directory is what makes the URLs the
/// server's business. That only holds if every resource a client needs is in
/// it, as an absolute URL it can use as it stands.
/// </para>
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.1.1")]
public class DirectoryTests(String ServerName)
{

    private IACMEServerUnderTest?  server;
    private HttpClient             http = null!;

    [OneTimeSetUp]
    public async Task StartServer()
    {
        server = await ServersUnderTest.StartAsync(ServerName);
        http   = server.TLS.NewHttpClient();
    }

    [OneTimeTearDown]
    public async Task StopServer()
    {
        http?.Dispose();
        if (server is not null)
            await server.DisposeAsync();
    }

    private async Task<JObject> Directory()
    {

        using var response = await http.GetAsync(server!.DirectoryURL);
        var       text     = await response.Content.ReadAsStringAsync();

        Assert.That((Int32) response.StatusCode, Is.EqualTo(200), $"{server.Name}: GET {server.DirectoryURL} answered {(Int32) response.StatusCode}: {text}");

        return JObject.Parse(text);

    }


    /// <summary>
    /// The resources of the table of section 7.1.1 a server has to offer:
    /// "newAuthz" alone is optional (section 7.4.1).
    /// </summary>
    [TestCase("newNonce")]
    [TestCase("newAccount")]
    [TestCase("newOrder")]
    [TestCase("revokeCert")]
    [TestCase("keyChange")]
    [Property("Level", "MUST")]
    public async Task The_Directory_Names_The_Resource_As_An_Absolute_URL(String Resource)
    {

        var directory = await Directory();

        Assert.That(directory[Resource]?.Type, Is.EqualTo(JTokenType.String), $"{server!.Name}: the directory has no \"{Resource}\": {directory}");

        var value = directory.Value<String>(Resource)!;

        Assert.That(Uri.TryCreate(value, UriKind.Absolute, out var url) && url.Scheme is "http" or "https",
                    Is.True,
                    $"{server.Name}: \"{Resource}\" is \"{value}\", not an absolute http(s) URL");

    }

    /// <summary>
    /// <i>"If a server does not wish to support pre-authorization, it MUST omit
    /// the "newAuthz" field of the directory."</i> (section 7.4.1) - and one
    /// that names it has to answer there.
    /// </summary>
    [Test]
    [Property("RFC",   "8555 §7.4.1")]
    [Property("Level", "MUST")]
    public async Task A_NewAuthz_In_The_Directory_Is_A_Resource_That_Exists()
    {

        var directory = await Directory();

        if (directory["newAuthz"] is null)
            Assert.Pass($"{server!.Name} offers no pre-authorization and says so by omitting \"newAuthz\".");

        // A POST without a JWS is refused - but by the resource, not as unknown.
        using var response = await http.PostAsync(directory.Value<String>("newAuthz"), new StringContent(""));

        Assert.That((Int32) response.StatusCode, Is.Not.EqualTo(404), $"{server!.Name} names \"newAuthz\" in its directory, and there is nothing there");

    }

    /// <summary>
    /// The resources are the server's: each a URL of its own, and none of
    /// them the directory itself (<i>"There is no constraint on the URL of the
    /// directory except that it should be different from the other ACME server
    /// resources' URLs"</i>).
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task Every_Resource_Has_A_URL_Of_Its_Own()
    {

        var directory  = await Directory();

        var urls       = directory.Properties().
                                   Where (property => property.Name != "meta" && property.Value.Type == JTokenType.String).
                                   Select(property => property.Value.Value<String>()!).
                                   ToArray();

        Assert.Multiple(() => {
            Assert.That(urls, Is.Unique,                                                    $"{server!.Name}: {directory}");
            Assert.That(urls, Has.None.EqualTo(server!.DirectoryURL.ToString()),            $"{server.Name}: {directory}");
        });

    }

    /// <summary>
    /// <i>"meta (optional, object)"</i> - where it is there, its fields are of
    /// the types the table of section 7.1.1 gives them.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Meta_Object_Has_Fields_Of_The_Types_The_RFC_Gives()
    {

        var directory = await Directory();

        if (directory["meta"] is not JObject meta)
        {
            Assert.That(directory["meta"], Is.Null, $"{server!.Name}: \"meta\" is there, and no object: {directory}");
            return;
        }

        Assert.Multiple(() => {

            foreach (var field in new[] { "termsOfService", "website" })
                if (meta[field] is JToken value)
                    Assert.That(value.Type == JTokenType.String && Uri.IsWellFormedUriString(value.Value<String>(), UriKind.Absolute),
                                Is.True, $"{server!.Name}: meta.{field} is no URL: {value}");

            if (meta["caaIdentities"] is JToken caa)
                Assert.That(caa is JArray array && array.All(identity => identity.Type == JTokenType.String),
                            Is.True, $"{server!.Name}: meta.caaIdentities is no array of strings: {caa}");

            if (meta["externalAccountRequired"] is JToken eab)
                Assert.That(eab.Type, Is.EqualTo(JTokenType.Boolean), $"{server!.Name}: meta.externalAccountRequired is no boolean: {eab}");

        });

    }

}
