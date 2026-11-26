using NUnit.Framework;

using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 6.7: errors as problem documents of RFC 7807, of the
/// types of the ACME URN namespace - <i>"Servers MUST NOT use the ACME URN
/// namespace for errors not listed in the appropriate IANA registry"</i> -
/// and RFC 7807, section 3.1: <i>"Generators MUST use the same status code in
/// the actual HTTP response"</i> as in "status".
/// </summary>
/// <remarks>
/// A client acts on the type of an error: it retries badNonce, it says
/// rateLimited, it gives up on unauthorized. A type outside the registry is
/// one no client knows what to do with.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §6.7")]
public class ErrorDocumentTests(String ServerName) : ACMEServerFixture(ServerName)
{

    /// <summary>
    /// The "ACME Error Types" registry: RFC 8555, section 9.7.4, with
    /// alreadyReplaced of RFC 9773 and invalidProfile of
    /// draft-ietf-acme-profiles.
    /// </summary>
    private static readonly String[] Registered = [
        "accountDoesNotExist", "alreadyReplaced", "alreadyRevoked", "badCSR", "badNonce", "badPublicKey",
        "badRevocationReason", "badSignatureAlgorithm", "caa", "compound", "connection", "dns",
        "externalAccountRequired", "incorrectResponse", "invalidContact", "invalidProfile", "malformed",
        "orderNotReady", "rateLimited", "rejectedIdentifier", "serverInternal", "tls", "unauthorized",
        "unsupportedContact", "unsupportedIdentifier", "userActionRequired"
    ];

    /// <summary>
    /// Errors of every kind the suite can provoke without effort: a bad nonce,
    /// a URL that does not match, a body that is no JWS, a "kid" of nobody,
    /// an identifier of no type, an order finalized too early, an order that
    /// is not there, a contact of no scheme.
    /// </summary>
    private async Task<IReadOnlyList<RawACMEResponse>> ProvokeAsync()
    {

        var (account, order) = await PendingOrderAsync();

        return [
            await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("nonce", "bm9uZQ")),
            await Client.PostAsync(account, account.URL, null, Header: header => header.SetString("url", account.URL + "/")),
            await Client.PostAsync(account, account.URL, null, Body: _ => "this is no JWS"),
            await Client.PostAsync(account.Key, account.URL + "0", account.URL, null),
            await Client.NewOrderAsync(account, ("email", "nobody@example.org")),
            await Client.FinalizeAsync(account, order, "MIIB"),
            await Client.PostAsGetAsync(account, order.URL + "0"),
            await Client.PostAsync(account, account.URL, """{"contact":["tel:+4912345"]}""")
        ];

    }

    /// <summary>
    /// Every error is application/problem+json, of a type of the registry,
    /// with the status of the answer as its "status" where it has one.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Every_Error_Is_A_Problem_Document_Of_A_Registered_Type()
    {

        var answers = await ProvokeAsync();

        using (Assert.EnterMultipleScope())
        {
            foreach (var answer in answers)
            {

                Assert.That(answer.Status,       Is.InRange(400, 599),                            answer.ToString());
                Assert.That(answer.MediaType,    Is.EqualTo("application/problem+json"),          answer.ToString());
                Assert.That(answer.ProblemType,  Does.StartWith(RawACMEResponse.ErrorPrefix),     answer.ToString());
                Assert.That(answer.ErrorType,    Is.AnyOf(Registered),                            answer.ToString());

                if (answer.Object?["status"] is not null)
                    Assert.That(answer.Object["status"]!.GetValue<Int32>(), Is.EqualTo(answer.Status), $"RFC 7807, section 3.1: {answer}");

            }
        }

    }

    /// <summary>
    /// <i>"Clients SHOULD display the "detail" field of all errors."</i> - so
    /// there is one, a sentence.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public async Task Every_Error_Says_What_Went_Wrong()
    {

        var answers = await ProvokeAsync();

        using (Assert.EnterMultipleScope())
        {
            foreach (var answer in answers)
                Assert.That(answer.StringOf("detail"), Is.Not.Null.And.Not.Empty, answer.ToString());
        }

    }

}
