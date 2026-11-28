using System.Security.Cryptography;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.6: <i>"Before revoking a certificate, the server MUST
/// verify that the key used to sign the request is authorized to revoke the
/// certificate. The server MUST consider at least the following accounts
/// authorized for a given certificate: the account that issued the
/// certificate. an account that holds authorizations for all of the
/// identifiers in the certificate. The server MUST also consider a revocation
/// request valid if it is signed with the private key corresponding to the
/// public key in the certificate."</i>
/// </summary>
/// <remarks>
/// Revocation is the one way back from a certificate gone wrong: a server
/// that refuses the holder of the certificate key leaves a stolen
/// certificate standing, one that takes anybody takes down anybody's.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.6")]
public class RevocationTests(String ServerName) : ACMEServerFixture(ServerName)
{

    private String RevokeCertURL
        => Client.Resource("revokeCert");

    private static String Payload(Byte[] Certificate, Int32? Reason = null)

        => Reason is Int32 reason
               ? RawJson.Object(("certificate", RawJson.Quote(RawBase64Url.Encode(Certificate))), ("reason", reason.ToString()))
               : RawJson.Object(("certificate", RawJson.Quote(RawBase64Url.Encode(Certificate))));

    private async Task<(RawACMEAccount Account, RawACMEIssued Issued)> IssuedAsync()
    {
        var account = await NewAccountAsync();
        return (account, await Client.IssueAsync(account, Host, Loopback4));
    }


    /// <summary>
    /// By the account it was issued to, with a reason of RFC 5280 a subscriber
    /// gives (keyCompromise): <i>"If the revocation succeeds, the server
    /// responds with status code 200 (OK)."</i> - and a second time: <i>"if the
    /// certificate has already been revoked, the server returns an error
    /// response with status code 400 (Bad Request) and type
    /// "urn:ietf:params:acme:error:alreadyRevoked"."</i>
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Account_Of_A_Certificate_Revokes_It_Once()
    {

        var (account, issued) = await IssuedAsync();

        var first             = await Client.PostAsync(account, RevokeCertURL, Payload(issued.LeafDER, 1));
        var again             = await Client.PostAsync(account, RevokeCertURL, Payload(issued.LeafDER, 1));

        Assert.Multiple(() => {
            AssertStatus(first, 200);
            AssertProblem(again, 400, "alreadyRevoked");
        });

    }

    /// <summary>
    /// <i>"reason (optional, int)"</i> - without one.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Revocation_Without_A_Reason_Is_Taken()
    {

        var (account, issued) = await IssuedAsync();

        AssertStatus(await Client.PostAsync(account, RevokeCertURL, Payload(issued.LeafDER)), 200);

    }

    /// <summary>
    /// <i>"The server MUST also consider a revocation request valid if it is
    /// signed with the private key corresponding to the public key in the
    /// certificate."</i> - with its "jwk" (section 6.2), by nobody's account.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task The_Key_Of_A_Certificate_Revokes_It()
    {

        var (_, issued) = await IssuedAsync();
        using var key   = new RawKey(issued.CertificateKey, "ES256");

        AssertStatus(await Client.PostAsync(key, null, RevokeCertURL, Payload(issued.LeafDER, 1)), 200);

    }

    /// <summary>
    /// <i>"an account that holds authorizations for all of the identifiers in
    /// the certificate"</i> - another account that proved 127.0.0.1 itself.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task An_Account_That_Proved_Every_Name_Revokes_It()
    {

        var (_, issued) = await IssuedAsync();
        var other       = await NewAccountAsync();
        var order       = await Client.ReadyOrderAsync(other, Host, Loopback4);

        Assert.That(order.Status, Is.EqualTo("ready"), "the other account proved 127.0.0.1");

        AssertStatus(await Client.PostAsync(other, RevokeCertURL, Payload(issued.LeafDER, 4)), 200);

    }

    /// <summary>
    /// An account that is none of these - it did not order the certificate
    /// and proved none of its names - is not authorized.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Another_Account_Does_Not_Revoke_It()
    {

        var (account, issued) = await IssuedAsync();
        var mallory           = await NewAccountAsync();

        var answer            = await Client.PostAsync(mallory, RevokeCertURL, Payload(issued.LeafDER, 1));
        var owner             = await Client.PostAsync(account, RevokeCertURL, Payload(issued.LeafDER, 1));

        Assert.Multiple(() => {
            AssertProblem(answer, null, "unauthorized");
            AssertStatus(owner, 200);
        });

    }

    /// <summary>
    /// A "jwk" that is not the certificate's key: nobody's signature it
    /// accepts.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Another_Key_Does_Not_Revoke_It()
    {

        var (_, issued) = await IssuedAsync();
        using var key   = RawKey.Generate("ES256");

        AssertProblem(await Client.PostAsync(key, null, RevokeCertURL, Payload(issued.LeafDER, 1)), null);

    }

    /// <summary>
    /// <i>"reason (optional, int): One of the revocation reasonCodes defined in
    /// Section 5.3.1 of [RFC5280]"</i> - 7 is unused there, 11 and -1 are none:
    /// <i>"If a request contains a disallowed reasonCode, then the server MUST
    /// reject it with the error type
    /// "urn:ietf:params:acme:error:badRevocationReason"."</i>
    /// </summary>
    [TestCase(7)]
    [TestCase(11)]
    [TestCase(-1)]
    [Property("Level", "MUST")]
    public async Task A_Reason_That_Is_No_reasonCode_Is_badRevocationReason(Int32 Reason)
    {

        var (account, issued) = await IssuedAsync();

        AssertProblem(await Client.PostAsync(account, RevokeCertURL, Payload(issued.LeafDER, Reason)), 400, "badRevocationReason");

    }

    /// <summary>
    /// The same of a "reason" beyond 32 bits, and so none of RFC 5280's:
    /// badRevocationReason, not the server's error. (One beyond a double, an
    /// array and an object are refused so.)
    /// </summary>
    [TestCase("4294967296",          Description = "2^32")]
    [TestCase("9223372036854775808", Description = "2^63")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-18")]
    public async Task A_Reason_Beyond_Every_reasonCode_Is_badRevocationReason(String Reason)
    {

        var (account, issued) = await IssuedAsync();

        AssertProblem(await Client.PostAsync(account, RevokeCertURL,
                                             RawJson.Object(("certificate", RawJson.Quote(RawBase64Url.Encode(issued.LeafDER))), ("reason", Reason))),
                      400, "badRevocationReason");

    }

    /// <summary>
    /// <i>"The server MAY disallow a subset of reasonCodes from being used by
    /// the user. If a request contains a disallowed reasonCode, then the server
    /// MUST reject it with the error type
    /// "urn:ietf:params:acme:error:badRevocationReason"."</i> - reasons a CA
    /// gives rather than a subscriber: taken, or refused as badRevocationReason.
    /// </summary>
    [TestCase(2,  Description = "cACompromise")]
    [TestCase(6,  Description = "certificateHold")]
    [TestCase(8,  Description = "removeFromCRL")]
    [TestCase(9,  Description = "privilegeWithdrawn")]
    [TestCase(10, Description = "aACompromise")]
    [Property("Level", "MUST")]
    public async Task A_Reason_It_Does_Not_Allow_Is_badRevocationReason(Int32 Reason)
    {

        var (account, issued) = await IssuedAsync();
        var answer            = await Client.PostAsync(account, RevokeCertURL, Payload(issued.LeafDER, Reason));

        if (answer.Status == 200)
            Assert.Pass($"reason {Reason} is allowed here");

        AssertProblem(answer, 400, "badRevocationReason");

    }

    /// <summary>
    /// <i>"certificate (required, string): The certificate to be revoked, in
    /// the base64url-encoded version of the DER format."</i> - padded, which
    /// section 5 says <i>"MUST be rejected as improperly encoded"</i>.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6, §5")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-1")]
    public async Task A_Certificate_With_Padding_Is_Refused()
    {

        RawACMEAccount account;
        RawACMEIssued  issued;

        do
        {
            (account, issued) = await IssuedAsync();
        }
        while (RawBase64Url.Encode(issued.LeafDER).Length % 4 == 0);

        var encoded = RawBase64Url.Encode(issued.LeafDER);
        var padded  = encoded + new String('=', 4 - encoded.Length % 4);

        var answer  = await Client.PostAsync(account, RevokeCertURL, RawJson.Object(("certificate", RawJson.Quote(padded)), ("reason", "1")));
        var control = await Client.PostAsync(account, RevokeCertURL, Payload(issued.LeafDER, 1));

        Assert.Multiple(() => {
            AssertProblem(answer, 400, "malformed");
            AssertStatus(control, 200);
        });

    }

    /// <summary>
    /// The certificate with a line break in it, as base64 of MIME has them -
    /// which base64url of RFC 7515, section 2, is <i>"without the inclusion of
    /// any line breaks, whitespace, or other additional characters"</i>; and
    /// then as it should be, revoked.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6, 7515 §2")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-14")]
    public async Task A_Certificate_With_Whitespace_Is_Refused()
    {

        var (account, issued) = await IssuedAsync();
        var encoded           = RawBase64Url.Encode(issued.LeafDER);

        var answer            = await Client.PostAsync(account, RevokeCertURL, RawJson.Object(("certificate", RawJson.Quote(encoded[..64] + "\n" + encoded[64..])), ("reason", "1")));
        var control           = await Client.PostAsync(account, RevokeCertURL, Payload(issued.LeafDER, 1));

        Assert.Multiple(() => {
            AssertProblem(answer, 400, "malformed");
            AssertStatus(control, 200);
        });

    }

    /// <summary>
    /// A certificate the server never issued - one of the bench - is none of
    /// its to revoke.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Certificate_Of_Another_CA_Is_Refused()
    {

        var account   = await NewAccountAsync();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request   = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256);
        using var own = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        AssertProblem(await Client.PostAsync(account, RevokeCertURL, Payload(own.RawData, 1)), null);

    }

}
