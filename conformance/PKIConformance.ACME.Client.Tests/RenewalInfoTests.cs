using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;

namespace PKIConformance.ACME.Client.Tests;

/// <summary>
/// RFC 9773, ACME Renewal Information, from the client's side: <i>"the client
/// sends an unauthenticated GET request to a path under the server's
/// renewalInfo URL"</i> (section 4.1), reads the window (section 4.2), and
/// says in a renewal which certificate it replaces (section 5).
/// </summary>
[TestFixture]
[Property("RFC", "9773")]
public class RenewalInfoTests : ClientFixture
{

    private static DateTimeOffset Second(DateTimeOffset Time)
        => DateTimeOffset.FromUnixTimeSeconds(Time.ToUnixTimeSeconds());


    /// <summary>
    /// Section 4.1: <i>"The path component is a unique identifier for the
    /// certificate ... the base64url-encoded [RFC4648] bytes of a DER-encoded
    /// KeyIdentifier [RFC5280] ... a literal period ... the base64url-encoded
    /// bytes of a DER-encoded CertificateSerialNumber"</i> - by RawACME's
    /// reading of the certificate, a GET, unsigned.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.1")]
    [Property("Level", "MUST")]
    public async Task The_Window_Is_Asked_For_At_The_Identifier_Of_The_Certificate()
    {

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        await client.GetRenewalInfoAsync(certificate.Certificate);

        var request     = Server.RequestsOf("renewalInfo").Single();

        using (Assert.EnterMultipleScope())
        {
            Assert.That(request.Method, Is.EqualTo("GET"));
            Assert.That(request.URL,    Is.EqualTo($"{request.HandedOutURL}/{RawARI.CertificateId(certificate.Certificate.RawData)}"));
            Assert.That(request.Body,   Is.Empty);
        }

    }

    /// <summary>
    /// Section 4.2: <i>"suggestedWindow (object, required): A JSON object with
    /// two keys, "start" and "end""</i>, <i>"explanationURL (string,
    /// optional)"</i>, and section 4.3, the Retry-After - all as the server
    /// said them.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §4.2, §4.3")]
    [Property("Level", "MUST")]
    public async Task The_Window_Its_Explanation_And_Its_Retry_After_Are_Read()
    {

        var start = Second(DateTimeOffset.UtcNow.AddDays(30));
        var end   = start.AddDays(2);

        Server.RenewalWindow          = _ => (start, end);
        Server.RenewalExplanationURL  = "https://pkiconformance.test/ari/why";
        Server.RenewalRetryAfter      = "3600";

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);
        var info        = await client.GetRenewalInfoAsync(certificate.Certificate);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(info?.Start,                     Is.EqualTo(start));
            Assert.That(info?.End,                       Is.EqualTo(end));
            Assert.That(info?.ExplanationURL?.ToString(), Is.EqualTo("https://pkiconformance.test/ari/why"));
            Assert.That(info?.RetryAfter,                Is.EqualTo(TimeSpan.FromHours(1)));
        }

    }

    /// <summary>
    /// A directory without "renewalInfo" has no windows: none is asked for.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §3")]
    [Property("Level", "MUST")]
    public async Task A_Server_Without_renewalInfo_Is_Asked_Nothing()
    {

        Server.RenewalInfo = false;

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(await client.GetRenewalInfoAsync(certificate.Certificate), Is.Null);
            Assert.That(Server.Requests.Where(request => request.Method == "GET" && request.Resource != "directory"), Is.Empty, Log);
        }

    }

    /// <summary>
    /// Section 4.2: <i>"A RenewalInfo object in which the end timestamp equals
    /// or precedes the start timestamp is invalid. Servers MUST NOT serve such
    /// a response, and clients MUST treat one as though they failed to
    /// receive any response from the server"</i> - no window, whether it ends
    /// before it starts or when it starts.
    /// </summary>
    [TestCase(0, Category = TestCategories.KnownIssue)]
    [TestCase(-3600)]
    [Property("RFC", "9773 §4.2")]
    [Property("Level", "MUST")]
    [Property("Finding", "C-6")]
    public async Task A_Window_That_Ends_When_Or_Before_It_Starts_Is_No_Window(Int32 Length)
    {

        var start = Second(DateTimeOffset.UtcNow.AddDays(30));

        Server.RenewalWindow = _ => (start, start.AddSeconds(Length));

        var client      = await ClientWithAccountAsync();
        var certificate = await ObtainAsync(client);

        ACMERenewalInfo? info = null;

        try
        {
            info = await client.GetRenewalInfoAsync(certificate.Certificate);
        }
        catch (ACMEException)
        {
            // As though no response came: as good as null.
        }

        Assert.That(info, Is.Null, $"taken as a window: {info}");

    }

    /// <summary>
    /// Section 5: <i>"Clients SHOULD include this field in newOrder requests
    /// if there is a clear predecessor certificate"</i> - the identifier of the
    /// certificate a renewal replaces.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD")]
    public async Task A_Renewal_Says_Which_Certificate_It_Replaces()
    {

        var client  = await ClientWithAccountAsync();
        var first   = await ObtainAsync(client);

        await client.ObtainCertificateAsync([ Name ], Responders, Replacing: first.Certificate);

        Assert.That(Server.RequestsOf("newOrder").Last().PayloadObject?["replaces"]?.GetValue<String>(),
                    Is.EqualTo(RawARI.CertificateId(first.Certificate.RawData)), Log);

    }

    /// <summary>
    /// Section 5: <i>"Clients SHOULD NOT include this field if the ACME server
    /// has not indicated that it supports this protocol by advertising the
    /// renewalInfo resource in its Directory."</i>
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD NOT")]
    public async Task A_Renewal_At_A_Server_Without_renewalInfo_Says_Nothing_Of_It()
    {

        Server.RenewalInfo = false;

        var client  = await ClientWithAccountAsync();
        var first   = await ObtainAsync(client);

        await client.ObtainCertificateAsync([ Name ], Responders, Replacing: first.Certificate);

        Assert.That(Server.RequestsOf("newOrder").Last().PayloadObject?.ContainsKey("replaces"), Is.False, Log);

    }

    /// <summary>
    /// Section 5: <i>"If the server rejects the request because the identified
    /// certificate has already been marked as replaced, it MUST return an HTTP
    /// 409 (Conflict) with a problem document of type "alreadyReplaced""</i> -
    /// and the client orders the certificate as a new one.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD")]
    public async Task A_Certificate_Replaced_Already_Is_Ordered_Anew()
    {

        var client  = await ClientWithAccountAsync();
        var first   = await ObtainAsync(client);

        Server.Before = request => request.Resource == "newOrder" && request.PayloadObject?.ContainsKey("replaces") == true
                                       ? ScriptedAnswer.Problem(409, "alreadyReplaced", "Replaced by an order before.")
                                       : null;

        var second  = await client.ObtainCertificateAsync([ Name ], Responders, Replacing: first.Certificate);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(second.Certificate.RawData,                                       Is.EqualTo(Server.Certificates.Last().DER));
            Assert.That(Server.RequestsOf("newOrder").Last().PayloadObject?.ContainsKey("replaces"), Is.False, Log);
        }

    }

}
