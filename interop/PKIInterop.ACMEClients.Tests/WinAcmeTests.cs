using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// win-acme against the ACME server under test, natively on Windows - its
/// column of the matrix of PLAN.md, section 4.5: an account, bound to an
/// external one; certificates by http-01 into a webroot, of every kind of key,
/// of its own CSR, of a profile and of addresses; a renewal forced, one
/// saying what it replaces, and one of its own when the server's window of
/// ARI is due; revocation; and the refusals it is to be told of.
/// </summary>
/// <remarks>
/// <para>
/// Its name is "localhost", the one name every Windows resolves of itself:
/// the bench's names resolve on no Windows that was left as it was.
/// </para>
/// <para>
/// Grey on this leg, and so without a test: a new contact, a deactivated
/// account and a new account key (win-acme 2.4.1 has none of them
/// unattended: the first two in its menu alone, key rollover not at all),
/// kinds of account key (ES256 alone), http-01 of its own web server (an
/// HttpListener on port 80, an administrator's), revocation by the
/// certificate's key, names beyond one, and dns-01.
/// </para>
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.3, §7.4, §7.6, §8.3, 8738, 9773")]
public sealed class WinAcmeTests(String ServerName) : WindowsInteropFixture(ServerName)
{

    #region Bench

    protected override String[] Tools    => [ WinAcme.Installed ];

    protected override String   PeerName => WinAcme.Name;

    private const String Name = "localhost";

    private WinAcme NewWinAcme(Action<JsonObject>? Settings = null)
        => Keep(new WinAcme(DirectoryURL, Settings));

    /// <summary>The key of its certificates: P-256, where the test does not say otherwise.</summary>
    private static Action<JsonObject> P256
        => settings => settings["Csr"]!["Ec"]!["CurveName"] = "secp256r1";

    /// <summary>A certificate of the name by http-01 into the webroot, as the renewal "t1", its PEM files named "cert".</summary>
    private String[] Certificate(WinAcme WinAcme, String Host = Name, params String[] More)
        => [ "--source", "manual", "--host", Host, "--validation", "filesystem", "--webroot", WebrootPath,
             "--store", "pemfiles", "--pemfilespath", WinAcme.PemFiles, "--pemfilesname", "cert",
             "--accepttos", "--emailaddress", "wacs@acme.test", "--id", "t1", .. More ];

    private static String Evidence(Wsl.Result Result, WinAcme WinAcme)
        => $"{Result}\n--- win-acme's log ---\n{WinAcme.Log[^Math.Min(WinAcme.Log.Length, 6000)..]}";

    #endregion


    #region Accounts

    /// <summary>
    /// Section 7.3: a new account, its terms agreed to, a contact given.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.Account)]
    public async Task WinAcme_Registers_An_Account()
    {

        await StartAsync();

        var wacs   = NewWinAcme();
        var result = wacs.Run("--register", "--accepttos", "--emailaddress", "wacs@acme.test");

        Assert.That(AccountOf("wacs@acme.test")?.Status, Is.EqualTo("valid"), $"{Server.Name} keeps the account: {Evidence(result, wacs)}");

    }

    /// <summary>
    /// Section 7.3.4: an account bound to an external account, of a key the
    /// server's operator made.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountEAB)]
    public async Task WinAcme_Registers_An_Account_Bound_To_An_External_Account()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var (keyId, mac) = await ExternalAccountAsync();
        var wacs         = NewWinAcme();
        var result       = wacs.Run("--register", "--accepttos", "--emailaddress", "eab@acme.test", "--eab-key-identifier", keyId, "--eab-key", mac);

        Assert.That(AccountOf("eab@acme.test")?.ExternalAccount, Is.EqualTo(keyId), $"bound to the external account: {Evidence(result, wacs)}");

    }

    #endregion

    #region Certificates

    /// <summary>
    /// Section 8.3: a certificate of the name by http-01, its answer a file
    /// of win-acme's filesystem plugin in the webroot the bench serves.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.Http01Webroot)]
    public async Task WinAcme_Gets_A_Certificate_By_A_Webroot()
    {

        await StartAsync(Webroot: true);

        var wacs   = NewWinAcme(P256);
        var result = wacs.Run(Certificate(wacs, More: [ "--csr", "ec" ]));

        AssertIssued(wacs.Pem("cert", "chain"), [ Name ], "EC", 256, Evidence(result, wacs));

    }

    /// <summary>
    /// RFC 8738: a certificate of an address - which win-acme asks for with a
    /// commonName of the empty string (I-1).
    /// </summary>
    [TestCase("127.0.0.1")]
    [TestCase("::1")]
    [Property("RFC", "8738, 5280 §4.1.2.6")]
    [Property("Level", "MUST")]
    [Category(TestCategories.KnownIssue)]
    [Property("Finding", "I-1")]
    [Cell(InteropCells.IPv4, Argument = "127.0.0.1")]
    [Cell(InteropCells.IPv6, Argument = "::1")]
    public async Task WinAcme_Gets_A_Certificate_Of_An_Address(String Address)
    {

        await StartAsync(Webroot: true);

        var wacs   = NewWinAcme(P256);
        var result = wacs.Run(Certificate(wacs, Address, "--csr", "ec"));

        AssertIssued(wacs.Pem("cert", "chain"), [ Address ], "EC", 256, Evidence(result, wacs));

    }

    /// <summary>
    /// Section 7.4: a certificate of every kind of key win-acme makes - its
    /// curve and its RSA size are settings of its.
    /// </summary>
    [TestCase("ec",  "secp256r1", "EC",  256)]
    [TestCase("ec",  "secp384r1", "EC",  384)]
    [TestCase("rsa", "2048",      "RSA", 2048)]
    [TestCase("rsa", "3072",      "RSA", 3072)]
    [TestCase("rsa", "4096",      "RSA", 4096)]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.CertificateKeys)]
    public async Task WinAcme_Gets_A_Certificate_Of_The_Key_Asked_For(String Csr, String Parameter, String Algorithm, Int32 Size)
    {

        await StartAsync(Webroot: true);

        var wacs   = NewWinAcme(settings => {
                         if (Csr == "ec")
                             settings["Csr"]!["Ec"]!["CurveName"] = Parameter;
                         else
                             settings["Csr"]!["Rsa"]!["KeyBits"]  = Int32.Parse(Parameter);
                     });
        var result = wacs.Run(Certificate(wacs, More: [ "--csr", Csr ]));

        AssertIssued(wacs.Pem("cert", "chain"), [ Name ], Algorithm, Size, Evidence(result, wacs));

    }

    /// <summary>
    /// Section 7.4: a CSR of the client's own - openssl's - and its key.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.OwnCSR)]
    public async Task WinAcme_Gets_A_Certificate_For_Its_Own_CSR()
    {

        await StartAsync(Webroot: true);

        var wacs    = NewWinAcme();
        var key     = Path.Combine(wacs.Directory, "own.key");
        var csr     = Path.Combine(wacs.Directory, "own.csr");
        var openssl = Native.Run(OpenSSL.NativeExecutable!,
                                 [ "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                                   "-keyout", key, "-out", csr, "-subj", $"/CN={Name}", "-addext", $"subjectAltName=DNS:{Name}" ]);

        Assert.That(openssl.Success, Is.True, $"openssl made no CSR: {openssl}");

        var result  = wacs.Run("--source", "csr", "--csrfile", csr, "--pkfile", key, "--validation", "filesystem", "--webroot", WebrootPath,
                               "--store", "pemfiles", "--pemfilespath", wacs.PemFiles, "--pemfilesname", "cert",
                               "--accepttos", "--emailaddress", "wacs@acme.test", "--id", "t1");

        var leaf    = AssertIssued(wacs.Pem("cert", "chain"), [ Name ], "EC", 256, Evidence(result, wacs));

        using var own = ECDsa.Create();
        own.ImportFromPem(File.ReadAllText(key));

        Assert.That(leaf.GetECDsaPublicKey()!.ExportSubjectPublicKeyInfo(), Is.EqualTo(own.ExportSubjectPublicKeyInfo()), "of the CSR's key");

    }

    /// <summary>
    /// draft-ietf-acme-profiles: the profile asked for - "shortlived", of
    /// seven days.
    /// </summary>
    [Test]
    [Property("RFC", "draft-ietf-acme-profiles")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.Profiles)]
    public async Task WinAcme_Gets_A_Certificate_Of_The_Profile_Asked_For()
    {

        await StartAsync(new ACMEServerOptions(Profiles: new Dictionary<String, Int32> { ["classic"] = 90, ["shortlived"] = 7 }), Webroot: true);

        var wacs   = NewWinAcme(P256);
        var result = wacs.Run(Certificate(wacs, More: [ "--csr", "ec", "--profile", "shortlived" ]));
        var leaf   = AssertIssued(wacs.Pem("cert", "chain"), [ Name ], "EC", 256, Evidence(result, wacs));

        Assert.That((leaf.NotAfter - leaf.NotBefore).TotalDays, Is.InRange(6, 8), "the seven days of \"shortlived\"");

    }

    #endregion

    #region Renewals

    /// <summary>
    /// Section 7.4: a renewal win-acme is told to make, unasked by any window.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RenewalForced)]
    public async Task WinAcme_Renews_When_Told_To()
    {

        await StartAsync(Webroot: true);

        var wacs    = NewWinAcme(P256);
        var first   = wacs.Run(Certificate(wacs, More: [ "--csr", "ec" ]));
        var before  = AssertIssued(wacs.Pem("cert", "chain"), [ Name ], "EC", 256, Evidence(first, wacs));
        var renewal = wacs.Run("--renew", "--id", "t1", "--force", "--nocache");
        var after   = AssertIssued(wacs.Pem("cert", "chain"), [ Name ], "EC", 256, Evidence(renewal, wacs));

        Assert.That(after.Thumbprint, Is.Not.EqualTo(before.Thumbprint), $"a new certificate: {Evidence(renewal, wacs)}");

    }

    /// <summary>
    /// RFC 9773, section 5: a renewal says which certificate it replaces, and
    /// the server keeps it so.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD")]
    [Cell(InteropCells.RenewalReplaces)]
    public async Task WinAcme_Renews_Saying_Which_Certificate_It_Replaces()
    {

        await StartAsync(Webroot: true);

        var wacs    = NewWinAcme(P256);
        var first   = wacs.Run(Certificate(wacs, More: [ "--csr", "ec" ]));
        var before  = AssertIssued(wacs.Pem("cert", "chain"), [ Name ], "EC", 256, Evidence(first, wacs));
        var renewal = wacs.Run("--renew", "--id", "t1", "--force", "--nocache");
        var after   = AssertIssued(wacs.Pem("cert", "chain"), [ Name ], "EC", 256, Evidence(renewal, wacs));

        Assert.That(Server.Issued().Single(issued => issued.DER.AsSpan().SequenceEqual(after.RawData)).Replaces,
                    Is.EqualTo(RawARI.CertificateId(before.RawData)), $"replaces the one before: {Evidence(renewal, wacs)}");

    }

    /// <summary>
    /// RFC 9773, section 4.2: win-acme renews unforced when the server's
    /// window is due - the PKI moves the window of a revoked certificate into
    /// the past - having asked for it at the renewal.
    /// </summary>
    /// <remarks>
    /// The certificate is revoked out of band, by its own key, as a CA in an
    /// incident would: the case ARI is for.
    /// </remarks>
    [Test]
    [Property("RFC", "9773 §4.2")]
    [Property("Level", "SHOULD")]
    [Cell(InteropCells.RenewalByARI)]
    public async Task WinAcme_Renews_When_The_Window_Of_ARI_Is_Due()
    {

        await StartAsync(Webroot: true);

        var wacs   = NewWinAcme(P256);
        var first  = wacs.Run(Certificate(wacs, More: [ "--csr", "ec" ]));
        var before = AssertIssued(wacs.Pem("cert", "chain"), [ Name ], "EC", 256, Evidence(first, wacs));

        await RevokeOutOfBandAsync(before, wacs.Pem("cert", "key"));

        var renewal = wacs.Run("--renew", "--id", "t1", "--nocache");
        var after   = AssertIssued(wacs.Pem("cert", "chain"), [ Name ], "EC", 256, Evidence(renewal, wacs));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(after.Thumbprint, Is.Not.EqualTo(before.Thumbprint), $"renewed, unforced: {Evidence(renewal, wacs)}");
            Assert.That(renewal.StdOut,   Does.Contain("/acme/renewal-info/"), "win-acme asked for the window");
        }

    }

    /// <summary>The certificate revoked by its own key, by the suite's raw client - superseded.</summary>
    private async Task RevokeOutOfBandAsync(X509Certificate2 Certificate, String? KeyPEM)
    {

        Assert.That(KeyPEM, Is.Not.Null, "win-acme keeps the certificate's key");

        using var certificateKey = ECDsa.Create();
        certificateKey.ImportFromPem(KeyPEM!);

        using var raw = await RawACMEClient.ConnectAsync(Server);
        using var jwk = new RawKey(certificateKey, "ES256");

        var revoked   = await raw.PostAsync(jwk, null, raw.Resource("revokeCert"),
                                            $"{{\"certificate\":\"{RawBase64Url.Encode(Certificate.RawData)}\",\"reason\":4}}");

        Assert.That(revoked.Status, Is.EqualTo(200), $"revoked by its key: {revoked}");

    }

    #endregion

    #region Revocation

    /// <summary>
    /// Section 7.6: revoked by the account - held so by the server, and in its
    /// CRL. win-acme gives no reason.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RevokedByAccount)]
    public async Task WinAcme_Revokes_A_Certificate_By_Its_Account()
    {

        await StartAsync(Webroot: true);

        var wacs   = NewWinAcme(P256);
        var first  = wacs.Run(Certificate(wacs, More: [ "--csr", "ec" ]));
        var chain  = wacs.Pem("cert", "chain");
        var leaf   = AssertIssued(chain, [ Name ], "EC", 256, Evidence(first, wacs));
        var result = wacs.Run("--revoke", "--id", "t1");

        AssertRevoked(leaf, chain!, null, Evidence(result, wacs));

    }

    #endregion

    #region Refusals

    /// <summary>
    /// A name the server does not sign for: rejectedIdentifier.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4, §6.7")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RefusedName)]
    public async Task WinAcme_Is_Told_Of_A_Name_Not_Signed_For()
    {

        await StartAsync(new ACMEServerOptions(AllowedNames: [ "acme.test", "localhost", "127.0.0.0/8" ]), Webroot: true);

        var wacs   = NewWinAcme();
        var result = wacs.Run(Certificate(wacs, "refused.example"));

        AssertRefused(result, wacs.Log, "rejectedIdentifier");

    }

    /// <summary>
    /// A server that requires an external account binding says so.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "SHOULD")]
    [Cell(InteropCells.RefusedNoEAB)]
    public async Task WinAcme_Is_Told_An_External_Account_Binding_Is_Required()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var wacs   = NewWinAcme();
        var result = wacs.Run("--register", "--accepttos", "--emailaddress", "wacs@acme.test");

        AssertRefused(result, wacs.Log, "externalAccountRequired", "external account");

    }

    /// <summary>
    /// A wrong answer at the token's path: the challenge is invalid, and
    /// win-acme is told why.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, §7.5.1")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RefusedWrongAnswer)]
    public async Task WinAcme_Is_Told_Of_A_Wrong_Answer()
    {

        await StartAsync(Webroot: true);
        Webroot!.Fallback = _ => HostAnswer.Text("not the key authorization");

        var wacs   = NewWinAcme();
        var result = wacs.Run(Certificate(wacs));

        AssertRefused(result, wacs.Log, "incorrectResponse", "unauthorized", "invalid");

    }

    #endregion

}
