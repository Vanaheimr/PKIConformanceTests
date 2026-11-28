using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// Python's acme - the library of certbot, at certbot's pin - against the
/// ACME server under test, for what no client of the command line does: an
/// account's key changed (RFC 8555, section 7.3.5), an authorization given
/// up (section 7.5.2), a CSR of other names than the order's (section 7.4),
/// and a certificate revoked by another account that proved its names
/// (section 7.6).
/// </summary>
/// <remarks>
/// <para>
/// The conformance tests of the server ask the same of it with RawACME. Here
/// a client of other hands asks: acme's JWS, JSON, nonces and web server of
/// http-01, driven step by step by a script of the suite's
/// (<see cref="PythonACME"/>), which reports what the server answered. The
/// test judges that, and the server's own state beside it.
/// </para>
/// <para>
/// Everything else acme does, certbot does with it: certbot's columns are
/// its cells. The column of acme has the five above alone - the first a
/// certificate by http-01, which every other starts with.
/// </para>
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555")]
public sealed class PythonACMETests(String ServerName) : InteropFixture(ServerName)
{

    protected override String[] Tools    => [ PythonACME.Python, "openssl" ];

    protected override String   PeerName => PythonACME.Version;

    [OneTimeSetUp]
    public void RequireAcme()
    {
        if (!PythonACME.Version.StartsWith("acme ", StringComparison.Ordinal))
            Assert.Ignore(PythonACME.Version);
        TestEnvironment.RequireBenchNames();
    }

    private PythonACMEReport Run(String Scenario, String Email, params (String Name, Object? Value)[] Arguments)
    {

        var acme      = Keep(new PythonACME(Server.TLS.RootFile));
        var arguments = new Dictionary<String, Object?> {
                            ["names"] = new[] { BenchNames.WWW },
                            ["port"]  = HTTP01Port,
                            ["email"] = Email
                        };

        foreach (var (name, value) in Arguments)
            arguments[name] = value;

        return acme.Run(Scenario, DirectoryURL, arguments);

    }

    private static String? Kind(String? Problem)
        => Problem?.Split(':').LastOrDefault();


    /// <summary>
    /// A certificate by http-01 of acme's own web server - the way every
    /// other scenario starts, judged as every certificate of a peer is.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, §8.3")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.Http01OwnServer)]
    public async Task Python_acme_Gets_A_Certificate_By_http01()
    {

        await StartAsync();

        var report = Run("issue", "acme@acme.test");

        Assert.That(report.Ok("finalize"), Is.True, report.ToString());

        AssertIssued(report.Value("fullchain"), [ BenchNames.WWW ], "EC", 256, report);

    }

    /// <summary>
    /// Section 7.3.5: <i>"If all of these checks pass, then the server updates
    /// the corresponding account by replacing the old account key with the
    /// new public key and returns status code 200 (OK)."</i> - acme's outer
    /// JWS of the old key around an inner one of the new. Then the new key
    /// finds the account, the old one no account, and the server keeps the
    /// new key's thumbprint as josepy computes it.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.5")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountKeyRollover)]
    public async Task Python_acme_Changes_The_Key_Of_Its_Account()
    {

        await StartAsync();

        var report = Run("key-change", "rollover@acme.test");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Ok("keyChange"),                              Is.True,                          $"the key change: {report}");
            Assert.That(report.Value("found by the new key"),                Is.EqualTo(report.Value("account")), $"the new key finds the account: {report}");
            Assert.That(Kind(report.Problem("the account by its old key")),  Is.EqualTo("accountDoesNotExist"), $"the old key finds none: {report}");
            Assert.That(AccountOf("rollover@acme.test")?.Thumbprint,         Is.EqualTo(report.Value("new thumbprint")),
                                                                             $"{Server.Name} keeps the new key: {report}");
        }

    }

    /// <summary>
    /// Section 7.5.2: <i>"The server MUST NOT treat deactivated authorization
    /// objects as sufficient for issuing certificates."</i> - an
    /// authorization of a ready order given up: the order that had it is
    /// <i>"invalid"</i> (section 7.1.6: <i>"The order also moves to the
    /// "invalid" state if ... one of its authorizations enters a final state
    /// other than "valid""</i>) and is not finalized, and a new order of the
    /// name needs a new proof.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.2, §7.1.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AuthorizationDeactivated)]
    public async Task Python_acme_Deactivates_An_Authorization_And_Nothing_Is_Issued_On_It()
    {

        await StartAsync();

        var report      = Run("deactivate-authz", "deactivate@acme.test");
        var account     = AccountOf("deactivate@acme.test");
        var deactivated = report.Value("authorization");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Ok("deactivate the authorization"),       Is.True,                    $"the deactivation: {report}");
            Assert.That(report.Value("status it answered"),               Is.EqualTo("deactivated"),  $"the authorization it answered with: {report}");
            Assert.That(report.Value("status of the authorization after"), Is.EqualTo("deactivated"), $"the authorization, read again: {report}");
            Assert.That(report.Value("status of the order after"),        Is.EqualTo("invalid"),      $"the order of the authorization (section 7.1.6): {report}");
            Assert.That(report.Ok("finalize the order"),                  Is.False,                   $"the order was finalized on a deactivated authorization: {report}");
            Assert.That(Server.Issued().Where(issued => issued.AccountId == account?.Id),
                                                                          Is.Empty,                   $"{Server.Name} issued on a deactivated authorization: {report}");
            Assert.That(report.Values("next authorization statuses"),     Is.Not.Empty.And.All.EqualTo("pending"),
                                                                                                      $"a new order of the name needs a new proof: {report}");
            Assert.That(report.Values("next authorizations"),             Has.No.Member(deactivated), $"a new order of the name has the deactivated authorization: {report}");
        }

    }

    /// <summary>
    /// Section 7.4: <i>"The CSR MUST indicate the exact same set of requested
    /// identifiers as the initial newOrder request."</i> and <i>"the error
    /// document returned by the server SHOULD use error code "badCSR""</i> -
    /// a ready order finalized with a CSR of another name, by acme: refused
    /// as badCSR, nothing issued of it, and the order, still ready, then
    /// finalized with its own.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RefusedOtherNamesCSR)]
    public async Task A_CSR_Of_Other_Names_Is_badCSR_And_The_Order_Is_Finalized_With_Its_Own()
    {

        await StartAsync();

        var report = Run("csr-of-other-names", "csr@acme.test", ("other names", new[] { BenchNames.Numbered[0] }));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Ok("finalize with a CSR of other names"),          Is.False,              $"a certificate of other names than the order's: {report}");
            Assert.That(Kind(report.Problem("finalize with a CSR of other names")), Is.EqualTo("badCSR"), $"the refusal: {report}");
            Assert.That(report.Value("status of the order after"),                Is.EqualTo("ready"),   $"the order after the refusal: {report}");
            Assert.That(report.Ok("finalize with its own CSR"),                   Is.True,               $"the order with its own CSR: {report}");
        }

        AssertIssued(report.Value("fullchain"), [ BenchNames.WWW ], "EC", 256, report);

    }

    /// <summary>
    /// Section 7.6: <i>"The server MUST consider at least the following
    /// accounts authorized for a given certificate: ... an account that holds
    /// authorizations for all of the identifiers in the certificate."</i> -
    /// alice's certificate, revoked not by mallory, who proved none of its
    /// names, but by bob, who proved every one; held revoked for bob's
    /// reason, and in the CRL.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RevokedByProof)]
    public async Task Python_acme_Revokes_A_Certificate_Of_Another_Account_Whose_Names_It_Proved()
    {

        await StartAsync();

        var report = Run("revoke-by-proof", "revoke@acme.test");
        var chain  = report.Value("fullchain");
        var leaf   = AssertIssued(chain, [ BenchNames.WWW ], "EC", 256, report);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(report.Ok("revoked by mallory, who proved nothing"),              Is.False,                 $"revoked by an account that proved nothing: {report}");
            Assert.That(Kind(report.Problem("revoked by mallory, who proved nothing")),   Is.EqualTo("unauthorized"), $"mallory's refusal: {report}");
            Assert.That(report.Ok("revoked by bob, who proved every name"),               Is.True,                  $"bob's revocation: {report}");
        }

        AssertRevoked(leaf, chain!, 4, report);

    }

}
