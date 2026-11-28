using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIConformance.ACME.Server.Tests;

/// <summary>
/// RFC 8555, section 7.4: an order finalized with its CSR - <i>"The CSR MUST
/// indicate the exact same set of requested identifiers as the initial
/// newOrder request."</i> - section 11.1, <i>"ACME clients and servers MUST
/// verify that a CSR submitted in a finalize request does not contain a
/// public key for any known account key pair."</i> - and section 7.4.2, the
/// certificate downloaded as application/pem-certificate-chain (section 9.1).
/// </summary>
/// <remarks>
/// This is where a server signs: what it lets through here is in a
/// certificate. The certificates are judged by .NET's X509 classes and the
/// suite's strict PEM reader - never by the server's view of them.
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.4")]
public partial class FinalizeTests(String ServerName) : ACMEServerFixture(ServerName)
{

    #region Finalize

    /// <summary>
    /// <i>"A request to finalize an order will result in error if the order is
    /// not in the "ready" state. In such cases, the server MUST return a 403
    /// (Forbidden) error with a problem document of type "orderNotReady"."</i>
    /// - an order whose name is not proven yet.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Finalizing_A_pending_Order_Is_orderNotReady()
    {

        var (account, order) = await PendingOrderAsync();
        using var key        = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        AssertProblem(await Client.FinalizeAsync(account, order, RawCSR.CreateBase64Url(key, [ Loopback4 ])), 403, "orderNotReady");

    }

    /// <summary>
    /// The same of an order finalized already, which is "valid": it is not
    /// "ready" any more, and no second certificate comes of it.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task Finalizing_A_valid_Order_Again_Is_orderNotReady()
    {

        var account   = await NewAccountAsync();
        var issued    = await Client.IssueAsync(account, Host, Loopback4);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var again     = await Client.FinalizeAsync(account, issued.Order, RawCSR.CreateBase64Url(key, [ Loopback4 ]));
        var after     = await Client.PostAsGetAsync(account, issued.Order.URL);

        Assert.Multiple(() => {
            AssertProblem(again, 403, "orderNotReady");
            Assert.That(after.StringOf("certificate"), Is.EqualTo(issued.CertificateURL), after.ToString());
        });

    }

    /// <summary>
    /// <i>"If a request to finalize an order is successful, the server will
    /// return a 200 (OK) with an updated order object."</i> - "processing" or
    /// "valid", and once "valid", the certificate's URL (section 7.1.3,
    /// <i>"certificate (optional, string): A URL for the certificate that has
    /// been issued in response to this order."</i>).
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_Finalized_Order_Is_200_And_Becomes_valid_With_Its_Certificate()
    {

        var (account, order) = await ReadyOrderAsync();
        using var key        = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var answer           = await Client.FinalizeAsync(account, order, RawCSR.CreateBase64Url(key, [ Loopback4 ]));
        var done             = await Client.PollWhileAsync(account, order.URL, "processing");

        Assert.Multiple(() => {
            AssertStatus(answer, 200);
            Assert.That(answer.StringOf("status"),   Is.AnyOf("processing", "valid"), answer.ToString());
            Assert.That(done.StringOf("status"),     Is.EqualTo("valid"),             done.ToString());
            Assert.That(done.StringOf("certificate"), Is.Not.Null,                     done.ToString());
        });

    }

    /// <summary>
    /// <i>"The CSR MUST indicate the exact same set of requested identifiers as
    /// the initial newOrder request."</i> - <i>"In such cases, the problem
    /// document returned by the server SHOULD use error code "badCSR""</i> -
    /// <i>"After returning such an error, the server SHOULD leave the order in
    /// the "ready" state"</i>. A CSR of fewer names, of more, of others.
    /// </summary>
    [TestCase("fewer")]
    [TestCase("more")]
    [TestCase("other")]
    [Property("Level", "MUST")]
    public async Task A_CSR_Of_Other_Names_Than_The_Order_Is_badCSR_And_The_Order_Stays_ready(String How)
    {

        var (account, order) = await ReadyOrderAsync(Loopback4, Loopback6);
        using var key        = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        (String, String)[] names = How switch {
                                       "fewer" => [ Loopback4 ],
                                       "more"  => [ Loopback4, Loopback6, ("ip", "192.0.2.1") ],
                                       _       => [ Loopback4, ("ip", "192.0.2.1") ]
                                   };

        var answer = await Client.FinalizeAsync(account, order, RawCSR.CreateBase64Url(key, names));
        var after  = await Client.PostAsGetAsync(account, order.URL);

        Assert.Multiple(() => {
            AssertProblem(answer, 400, "badCSR");
            Assert.That(after.StringOf("status"), Is.EqualTo("ready"), $"SHOULD stay ready: {after}");
        });

    }

    /// <summary>
    /// <i>"Identifiers of type "dns" MUST appear either in the commonName
    /// portion of the requested subject name or in an extensionRequest
    /// attribute [RFC2985] requesting a subjectAltName extension, or both."</i>
    /// - a commonName is a name the CSR asks for, and one the order does not
    /// have makes it a CSR of other names: badCSR. (The mutation sweep found
    /// that no CSR here had a commonName: a server that never read it, and
    /// signed for the subjectAltName alone, passed.)
    /// </summary>
    [TestCase("unordered.example.org")]
    [TestCase("192.0.2.1")]
    [Property("Level", "MUST")]
    public async Task A_CSR_Whose_commonName_Is_Not_Of_The_Order_Is_badCSR(String CommonName)
    {

        var (account, order) = await ReadyOrderAsync();
        using var key        = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        AssertProblem(await Client.FinalizeAsync(account, order, RawCSR.CreateBase64Url(key, [ Loopback4 ], CommonName)), 400, "badCSR");

    }

    /// <summary>
    /// Section 11.1: <i>"In particular, when a server receives a finalize
    /// request, it MUST verify that the public key in a CSR is not the same as
    /// the public key of the account key pair used to authenticate that
    /// request."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §11.1")]
    [Property("Level", "MUST")]
    public async Task A_CSR_Of_The_Account_Key_Is_Refused()
    {

        var (account, order) = await ReadyOrderAsync();

        var answer           = await Client.FinalizeAsync(account, order, RawCSR.CreateBase64Url(account.Key.Key, [ Loopback4 ]));

        AssertProblem(answer, 400, "badCSR");

    }

    /// <summary>
    /// Section 11.1: <i>"ACME clients and servers MUST verify that a CSR
    /// submitted in a finalize request does not contain a public key for any
    /// known account key pair."</i> - the key of another account of the server.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §11.1")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-7")]
    public async Task A_CSR_Of_Another_Account_s_Key_Is_Refused()
    {

        var (account, order) = await ReadyOrderAsync();
        var other            = await NewAccountAsync();

        var answer           = await Client.FinalizeAsync(account, order, RawCSR.CreateBase64Url(other.Key.Key, [ Loopback4 ]));

        AssertProblem(answer, 400, "badCSR");

    }

    /// <summary>
    /// A CSR whose signature does not hold: RFC 2986, section 3, the signature
    /// is the proof of possession of the key - without it, a certificate of
    /// anybody's public key.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, 2986 §3")]
    [Property("Level", "MUST")]
    public async Task A_CSR_Whose_Signature_Does_Not_Hold_Is_badCSR()
    {

        var (account, order) = await ReadyOrderAsync();
        using var key        = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der              = RawCSR.Create(key, [ Loopback4 ]);
        der[^3]             ^= 0x55;

        AssertProblem(await Client.FinalizeAsync(account, order, RawBase64Url.Encode(der)), 400, "badCSR", "malformed");

    }

    /// <summary>
    /// A CSR of a key of RSA, 2048 bits, signed - the kind of key most
    /// certificates of the world still have. (The mutation sweep found that no
    /// test here had one: the server's look at the key of a CSR, whether it
    /// is an account's, was never walked for RSA.)
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_CSR_Of_An_RSA_Key_Is_Signed()
    {

        var (account, order) = await ReadyOrderAsync();
        using var key        = RSA.Create(2048);

        AssertStatus(await Client.FinalizeAsync(account, order, RawCSR.CreateBase64Url(key, [ Loopback4 ])), 200);

    }

    /// <summary>
    /// A CSR of a key on a curve nobody knows (1.2.840.10045.3.1.11 for
    /// P-256's 1.2.840.10045.3.1.7): a CSR the CA is unwilling to sign, and
    /// <i>"In such cases, the problem document returned by the server SHOULD
    /// use error code "badCSR""</i> - the client's error, not the server's.
    /// CertificateRequest.LoadSigningRequest throws a
    /// PlatformNotSupportedException for it on every platform, which the PKI
    /// answers 500 (S-19).
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-19")]
    public Task A_CSR_Of_A_Key_On_A_Curve_Nobody_Knows_Is_badCSR()

        => CSROfAKeyThatIsNoneAsync("curve");

    /// <summary>
    /// The same of a key whose point is off P-256 - where the platform says so
    /// as a CryptographicException (OpenSSL, on Linux): gating. On Windows CNG
    /// throws a PlatformNotSupportedException for it as well (S-19):
    /// <see cref="A_CSR_Of_A_Point_Off_Its_Curve_Is_badCSR_On_Windows"/> is
    /// the test of that leg, and this one skips there.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    public Task A_CSR_Of_A_Point_Off_Its_Curve_Is_badCSR()
    {

        if (OperatingSystem.IsWindows())
            Assert.Ignore("Windows refuses such a key otherwise (S-19) - A_CSR_Of_A_Point_Off_Its_Curve_Is_badCSR_On_Windows is the test of this leg.");

        return CSROfAKeyThatIsNoneAsync("point");

    }

    /// <summary>
    /// <see cref="A_CSR_Of_A_Point_Off_Its_Curve_Is_badCSR"/> on Windows, where
    /// it is a PlatformNotSupportedException, and so a 500 (S-19). Skips
    /// elsewhere.
    /// </summary>
    [Test]
    [Property("Level", "SHOULD")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-19")]
    public Task A_CSR_Of_A_Point_Off_Its_Curve_Is_badCSR_On_Windows()
    {

        if (!OperatingSystem.IsWindows())
            Assert.Ignore("This half of S-19 is of Windows alone - A_CSR_Of_A_Point_Off_Its_Curve_Is_badCSR is the test of this leg, and gates.");

        return CSROfAKeyThatIsNoneAsync("point");

    }

    private async Task CSROfAKeyThatIsNoneAsync(String Spoiled)
    {

        var (account, order) = await ReadyOrderAsync();
        using var key        = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der              = RawCSR.Create(key, [ Loopback4 ]);

        if (Spoiled == "curve")
        {
            // OBJECT IDENTIFIER 1.2.840.10045.3.1.7, its last arc made 11.
            var at = der.AsSpan().IndexOf((ReadOnlySpan<Byte>) [ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 ]);
            Assert.That(at, Is.GreaterThan(0), "the CSR names P-256");
            der[at + 9] = 0x0B;
        }
        else
        {
            // BIT STRING of 66 octets: no unused bits, 04 (uncompressed), x, y - the last octet of y changed.
            var at = der.AsSpan().IndexOf((ReadOnlySpan<Byte>) [ 0x03, 0x42, 0x00, 0x04 ]);
            Assert.That(at, Is.GreaterThan(0), "the CSR has the point of P-256 uncompressed");
            der[at + 4 + 63] ^= 0x01;
        }

        AssertProblem(await Client.FinalizeAsync(account, order, RawBase64Url.Encode(der)), 400, "badCSR", "malformed");

    }

    /// <summary>
    /// <i>"The CSR is sent in the base64url-encoded version of the DER
    /// format."</i> - and section 5, <i>"Encoded values that include trailing
    /// '=' characters MUST be rejected as improperly encoded."</i>: the CSR
    /// padded.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, §5")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-1")]
    public async Task A_CSR_With_Padding_Is_Refused()
    {

        var (account, order) = await ReadyOrderAsync();

        String csr;

        do
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            csr = RawCSR.CreateBase64Url(key, [ Loopback4 ]);
        }
        while (csr.Length % 4 == 0);

        csr += new String('=', 4 - csr.Length % 4);

        AssertProblem(await Client.FinalizeAsync(account, order, csr), 400, "badCSR", "malformed");

    }

    /// <summary>
    /// The CSR with a line break in it, as base64 of MIME has them - which
    /// base64url of RFC 7515, section 2, is <i>"without the inclusion of any
    /// line breaks, whitespace, or other additional characters"</i>.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, 7515 §2")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-14")]
    public async Task A_CSR_With_Whitespace_Is_Refused()
    {

        var (account, order) = await ReadyOrderAsync();
        using var key        = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var csr              = RawCSR.CreateBase64Url(key, [ Loopback4 ]);

        AssertProblem(await Client.FinalizeAsync(account, order, csr[..64] + "\n" + csr[64..]), 400, "badCSR", "malformed");

    }

    /// <summary>
    /// A CSR in PEM, as some clients would send it - which <i>"(Note: Because
    /// this field uses base64url, and does not include headers, it is
    /// different from PEM.)"</i> rules out.
    /// </summary>
    [Test]
    [Property("Level", "MUST")]
    public async Task A_CSR_In_PEM_Is_Refused()
    {

        var (account, order) = await ReadyOrderAsync();
        using var key        = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem              = PemEncoding.WriteString("CERTIFICATE REQUEST", RawCSR.Create(key, [ Loopback4 ]));

        AssertProblem(await Client.FinalizeAsync(account, order, pem), 400, "badCSR", "malformed");

    }

    #endregion

    #region The certificate (7.4.2, 9.1)

    /// <summary>
    /// <i>"[RFC7468] The textual encoding of certificates in this file MUST use
    /// the strict encoding and MUST NOT include explanatory text."</i>
    /// </summary>
    [GeneratedRegex(@"\A(-----BEGIN CERTIFICATE-----(\r\n|\r|\n)([A-Za-z0-9+/]{64}(\r\n|\r|\n))*[A-Za-z0-9+/]{1,63}={0,2}(\r\n|\r|\n)?-----END CERTIFICATE-----)((\r\n|\r|\n)-----BEGIN CERTIFICATE-----(\r\n|\r|\n)([A-Za-z0-9+/]{64}(\r\n|\r|\n))*[A-Za-z0-9+/]{1,63}={0,2}(\r\n|\r|\n)?-----END CERTIFICATE-----)*(\r\n|\r|\n)?\z")]
    private static partial Regex StrictChain();

    /// <summary>
    /// Section 7.4.2: <i>"The default format of the certificate is
    /// application/pem-certificate-chain (see Section 9)."</i> - and section
    /// 9.1: the strict encoding of RFC 7468, nothing else, <i>"In order to
    /// provide easy interoperation with TLS, the first certificate MUST be an
    /// end-entity certificate. Each following certificate SHOULD directly
    /// certify the one preceding it."</i>
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4.2, §9.1")]
    [Property("Level", "MUST")]
    public async Task The_Certificate_Is_A_Strict_PEM_Chain_Leaf_First()
    {

        var account  = await NewAccountAsync();
        var issued   = await Client.IssueAsync(account, Host, Loopback4);
        var answer   = await Client.PostAsGetAsync(account, issued.CertificateURL);
        var chain    = issued.Chain.Select(der => X509CertificateLoader.LoadCertificate(der)).ToList();

        Assert.Multiple(() => {

            AssertStatus(answer, 200);
            Assert.That(answer.MediaType,                    Is.EqualTo("application/pem-certificate-chain"), answer.ToString());
            Assert.That(StrictChain().IsMatch(answer.Text),  Is.True,                                         $"strict PEM of RFC 7468, nothing else: {answer}");
            Assert.That(chain,                               Is.Not.Empty);

            var leaf = chain[0];
            Assert.That(leaf.Extensions.OfType<X509BasicConstraintsExtension>().Any(constraints => constraints.CertificateAuthority), Is.False, "the first is an end entity");

            for (var i = 1; i < chain.Count; i++)
                Assert.That(chain[i - 1].IssuerName.RawData, Is.EqualTo(chain[i].SubjectName.RawData), $"certificate {i} certifies the one before it");

        });

    }

    /// <summary>
    /// Section 7.4: <i>"it MUST NOT issue a certificate with contents other
    /// than those requested"</i> - the names of the order exactly, the key of
    /// the CSR, a chain to the server's root.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    public async Task The_Certificate_Is_Of_The_Names_Of_The_Order_And_The_Key_Of_The_CSR()
    {

        var account  = await NewAccountAsync();
        var issued   = await Client.IssueAsync(account, Host, Loopback4, Loopback6);

        using var leaf  = X509CertificateLoader.LoadCertificate(issued.LeafDER);
        var san         = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>().SingleOrDefault();
        using var root  = X509Certificate2.CreateFromPem(Server.IssuingRootPEM);
        using var chain = new X509Chain();

        chain.ChainPolicy.TrustMode         = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode    = X509RevocationMode.NoCheck;
        chain.ChainPolicy.CustomTrustStore.Add(root);

        foreach (var der in issued.Chain.Skip(1))
            chain.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(der));

        var built       = chain.Build(leaf);

        Assert.Multiple(() => {
            Assert.That(san,                                             Is.Not.Null,                                                "a subjectAltName");
            Assert.That(san?.EnumerateDnsNames(),                        Is.Empty,                                                    "no DNS names");
            Assert.That(san?.EnumerateIPAddresses().Select(ip => ip.ToString()), Is.EquivalentTo(new[] { "127.0.0.1", "::1" }),     "the addresses of the order");
            Assert.That(leaf.PublicKey.ExportSubjectPublicKeyInfo(),     Is.EqualTo(((ECDsa) issued.CertificateKey).ExportSubjectPublicKeyInfo()), "the key of the CSR");
            Assert.That(built,                                           Is.True,                                                    String.Join("; ", chain.ChainStatus.Select(status => status.StatusInformation)));
        });

    }

    /// <summary>
    /// A certificate is downloaded by its own account (section 7.4.2, a
    /// POST-as-GET, which <i>"MUST authenticate the sender and verify any access
    /// control rules"</i>) - not by another one, and not by a GET (section 6.3).
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4.2, §6.3")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "S-4")]
    public async Task The_Certificate_Is_Downloaded_By_A_POST_as_GET()
    {

        var account  = await NewAccountAsync();
        var issued   = await Client.IssueAsync(account, Host, Loopback4);

        var get      = await Client.SendAsync(HttpMethod.Get, issued.CertificateURL);

        AssertProblem(get, 405, "malformed");

    }

    #endregion

}
