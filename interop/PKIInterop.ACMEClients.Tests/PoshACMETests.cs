using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using PKIConformance.Core;
using PKIConformance.Core.Peers;
using PKIConformance.Core.RawACME;
using PKIConformance.Core.Scripted;
using PKIConformance.Core.Servers;

namespace PKIInterop.ACMEClients.Tests;

/// <summary>
/// Posh-ACME against the ACME server under test, natively on Windows - its
/// column of the matrix of PLAN.md, section 4.5: accounts of every kind of
/// key, with a binding, a new contact, deactivated and of a new key;
/// certificates of addresses by http-01 into a webroot, of every kind of
/// key, of its own CSR and of a profile; a renewal forced, one saying what
/// it replaces, and one of its own when the server's window of ARI is due;
/// revocation by the account and by the certificate's key; an authorization
/// given up; and the refusals it is to be told of.
/// </summary>
/// <remarks>
/// Grey on this leg, and so without a test: http-01 of its own web server
/// (its WebSelfHost is an HttpListener, which Windows lets listen on the
/// address alone with an administrator's URL reservation); names beyond
/// "localhost", and so sixteen of them, a wildcard and dns-01 (the bench's
/// names resolve on no Windows left as it was); tls-alpn-01 (Posh-ACME has
/// none).
/// </remarks>
[TestFixtureSource(typeof(ServersUnderTest), nameof(ServersUnderTest.All))]
[Property("RFC", "8555 §7.3, §7.4, §7.6, §8.3, 8738, 9773")]
public sealed class PoshACMETests(String ServerName) : WindowsInteropFixture(ServerName)
{

    #region Bench

    protected override String[] Tools    => [ PoshACME.Module, PoshACME.PowerShell ];

    protected override String   PeerName => PoshACME.Name;

    private PoshACME NewPoshACME()
        => Keep(new PoshACME());

    private static String Q(String Text)
        => PoshACME.Quote(Text);

    /// <summary>
    /// The server, its certificate let through as Posh-ACME lets it - and
    /// without Posh-ACME's telemetry, which would tell poshac.me of every
    /// finalize.
    /// </summary>
    private String Server_
        => $"Set-PAServer -DirectoryUrl {Q(DirectoryURL)} -SkipCertificateCheck -DisableTelemetry; ";

    /// <summary>An account, its terms agreed to.</summary>
    private static String Account(String Email = "posh@acme.test", String KeyLength = "ec-256", String Binding = "")
        => $"New-PAAccount -Contact {Q("mailto:" + Email)} -AcceptTOS -KeyLength {Q(KeyLength)} {Binding} -Force | Out-Null; ";

    /// <summary>A certificate of the address by http-01 into the webroot, as the order "address".</summary>
    private String Certificate(String Address = "127.0.0.1", String Options = "")
        => $"New-PACertificate -Domain {Q(Address)} -Name 'address' -Plugin WebRoot -PluginArgs @{{ WRPath = {Q(WebrootPath)} }} {Options} -Force | Out-Null; ";

    /// <summary>The files of the order's certificate, said.</summary>
    private const String Files
        = "$c = Get-PACertificate -Name 'address'; Write-Output ('FULLCHAIN=' + $c.FullChainFile); Write-Output ('KEY=' + $c.KeyFile); ";

    private static String? FullChain(Wsl.Result Result)
        => PoshACME.Value(Result, "FULLCHAIN") is String path && File.Exists(path) ? File.ReadAllText(path) : null;

    private static String Evidence(Wsl.Result Result)
        => Result.ToString();

    #endregion


    #region Accounts

    /// <summary>
    /// Section 7.3: a new account, its terms agreed to, a contact given - the
    /// server keeps it valid, with the contact.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.Account)]
    public async Task PoshACME_Registers_An_Account()
    {

        await StartAsync();

        var result  = NewPoshACME().Run(Server_ + Account() + "Write-Output ('ACCOUNT=' + (Get-PAAccount).location)");
        var account = AccountOf("posh@acme.test");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(result.Success,                     Is.True,                 Evidence(result));
            Assert.That(account?.Status,                    Is.EqualTo("valid"),     $"{Server.Name} keeps the account: {Evidence(result)}");
            Assert.That(PoshACME.Value(result, "ACCOUNT"),  Does.StartWith(DirectoryURL[..DirectoryURL.IndexOf("/acme/", StringComparison.Ordinal)]),
                                                                                     "the account is at a URL of the server");
        }

    }

    /// <summary>
    /// Section 6.2: every kind of account key Posh-ACME makes - and so every
    /// signature algorithm of them the server is to check.
    /// </summary>
    [TestCase("ec-256", "EC",  "P-256")]
    [TestCase("ec-384", "EC",  "P-384")]
    [TestCase("2048",   "RSA", "2048")]
    [TestCase("4096",   "RSA", "4096")]
    [Property("RFC", "8555 §6.2, §7.3")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountKeys)]
    public async Task PoshACME_Registers_An_Account_Of_The_Key_Asked_For(String KeyLength, String KeyType, String Detail)
    {

        await StartAsync();

        var email   = $"posh-{KeyLength}@acme.test";
        var result  = NewPoshACME().Run(Server_ + Account(email, KeyLength));
        var account = AccountOf(email);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(account?.KeyType,   Is.EqualTo(KeyType), $"the kind of key: {Evidence(result)}");
            Assert.That(account?.KeyDetail, Is.EqualTo(Detail),  $"its curve or size: {Evidence(result)}");
        }

    }

    /// <summary>
    /// Section 7.3.4: an account bound to an external account, of a key the
    /// server's operator made.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountEAB)]
    public async Task PoshACME_Registers_An_Account_Bound_To_An_External_Account()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var (keyId, mac) = await ExternalAccountAsync();
        var result       = NewPoshACME().Run(Server_ + Account("eab@acme.test", Binding: $"-ExtAcctKID {Q(keyId)} -ExtAcctHMACKey {Q(mac)}"));

        Assert.That(AccountOf("eab@acme.test")?.ExternalAccount, Is.EqualTo(keyId), $"bound to the external account: {Evidence(result)}");

    }

    /// <summary>
    /// Section 7.3.2: the contact of the account changed.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.2")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountContact)]
    public async Task PoshACME_Gives_Its_Account_A_New_Contact()
    {

        await StartAsync();

        var result = NewPoshACME().Run(Server_ + Account() + "Set-PAAccount -Contact 'mailto:new-posh@acme.test' -Force | Out-Null");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(AccountOf("new-posh@acme.test"), Is.Not.Null, $"the new contact: {Evidence(result)}");
            Assert.That(AccountOf("posh@acme.test"),     Is.Null,     "the old one gone");
        }

    }

    /// <summary>
    /// Section 7.3.6: the account deactivated.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountDeactivated)]
    public async Task PoshACME_Deactivates_Its_Account()
    {

        await StartAsync();

        var result = NewPoshACME().Run(Server_ + Account() + "Set-PAAccount -Deactivate -Force | Out-Null");

        Assert.That(AccountOf("posh@acme.test")?.Status, Is.EqualTo("deactivated"), Evidence(result));

    }

    /// <summary>
    /// Section 7.3.5: the key of the account changed - from P-256 to P-384.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.5")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AccountKeyRollover)]
    public async Task PoshACME_Changes_The_Key_Of_Its_Account()
    {

        await StartAsync();

        var posh   = NewPoshACME();
        var before = posh.Run(Server_ + Account());
        var key    = AccountOf("posh@acme.test")?.Thumbprint;
        var result = posh.Run(Server_ + "Set-PAAccount -KeyRollover -KeyLength 'ec-384' | Out-Null");
        var after  = AccountOf("posh@acme.test");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(key,               Is.Not.Null,                 $"the account: {Evidence(before)}");
            Assert.That(after?.KeyDetail,  Is.EqualTo("P-384"),         $"the new key: {Evidence(result)}");
            Assert.That(after?.Thumbprint, Is.Not.EqualTo(key),         "another key than before");
        }

    }

    #endregion

    #region Certificates

    /// <summary>
    /// Section 8.3: a certificate of "localhost" by http-01 - the one name
    /// every Windows resolves of itself - its answer a file of the WebRoot
    /// plugin in the webroot the bench serves.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.Http01Webroot)]
    public async Task PoshACME_Gets_A_Certificate_By_A_Webroot()
    {

        await StartAsync(Webroot: true);

        var result = NewPoshACME().Run(Server_ + Account() + Certificate("localhost", "-CertKeyLength 'ec-256'") + Files);

        AssertIssued(FullChain(result), [ "localhost" ], "EC", 256, Evidence(result));

    }

    /// <summary>
    /// RFC 8738: a certificate of an address by http-01, its answer a file of
    /// Posh-ACME's WebRoot plugin in the webroot the bench serves.
    /// </summary>
    [TestCase("127.0.0.1")]
    [TestCase("::1")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.IPv4, Argument = "127.0.0.1")]
    [Cell(InteropCells.IPv6, Argument = "::1")]
    public async Task PoshACME_Gets_A_Certificate_Of_An_Address_By_A_Webroot(String Address)
    {

        await StartAsync(Webroot: true);

        var result = NewPoshACME().Run(Server_ + Account() + Certificate(Address, "-CertKeyLength 'ec-256'") + Files);

        AssertIssued(FullChain(result), [ Address ], "EC", 256, Evidence(result));

    }

    /// <summary>
    /// Section 7.4: a certificate of every kind of key Posh-ACME makes.
    /// </summary>
    [TestCase("ec-256", "EC",  256)]
    [TestCase("ec-384", "EC",  384)]
    [TestCase("2048",   "RSA", 2048)]
    [TestCase("3072",   "RSA", 3072)]
    [TestCase("4096",   "RSA", 4096)]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.CertificateKeys)]
    public async Task PoshACME_Gets_A_Certificate_Of_The_Key_Asked_For(String KeyLength, String Algorithm, Int32 Size)
    {

        await StartAsync(Webroot: true);

        var result = NewPoshACME().Run(Server_ + Account() + Certificate(Options: $"-CertKeyLength {Q(KeyLength)}") + Files, TimeSpan.FromMinutes(4));

        AssertIssued(FullChain(result), [ "127.0.0.1" ], Algorithm, Size, Evidence(result));

    }

    /// <summary>
    /// Section 7.4: a CSR of the client's own - openssl's - signed.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.OwnCSR)]
    public async Task PoshACME_Gets_A_Certificate_For_Its_Own_CSR()
    {

        await StartAsync(Webroot: true);

        var posh    = NewPoshACME();
        var key     = Path.Combine(posh.Home, "own.key");
        var csr     = Path.Combine(posh.Home, "own.csr");
        var openssl = Native.Run(OpenSSL.NativeExecutable!,
                                 [ "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                                   "-keyout", key, "-out", csr, "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1" ]);

        Assert.That(openssl.Success, Is.True, $"openssl made no CSR: {openssl}");

        var result  = posh.Run(Server_ + Account() +
                               $"New-PACertificate -CSRPath {Q(csr)} -Plugin WebRoot -PluginArgs @{{ WRPath = {Q(WebrootPath)} }} -Force | Out-Null; " +
                               "Write-Output ('FULLCHAIN=' + (Get-PACertificate).FullChainFile)");

        var leaf    = AssertIssued(FullChain(result), [ "127.0.0.1" ], "EC", 256, Evidence(result));

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
    public async Task PoshACME_Gets_A_Certificate_Of_The_Profile_Asked_For()
    {

        await StartAsync(new ACMEServerOptions(Profiles: new Dictionary<String, Int32> { ["classic"] = 90, ["shortlived"] = 7 }), Webroot: true);

        var result = NewPoshACME().Run(Server_ + Account() + Certificate(Options: "-CertKeyLength 'ec-256' -Profile 'shortlived'") + Files);
        var leaf   = AssertIssued(FullChain(result), [ "127.0.0.1" ], "EC", 256, Evidence(result));

        Assert.That((leaf.NotAfter - leaf.NotBefore).TotalDays, Is.InRange(6, 8), "the seven days of \"shortlived\"");

    }

    #endregion

    #region Renewals

    /// <summary>
    /// Section 7.4: a renewal Posh-ACME is told to make, unasked by any window.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.4")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RenewalForced)]
    public async Task PoshACME_Renews_When_Told_To()
    {

        await StartAsync(Webroot: true);

        var posh    = NewPoshACME();
        var first   = posh.Run(Server_ + Account() + Certificate(Options: "-CertKeyLength 'ec-256'") + Files);
        var before  = AssertIssued(FullChain(first), [ "127.0.0.1" ], "EC", 256, Evidence(first));
        var renewal = posh.Run(Server_ + "Submit-Renewal -Name 'address' -Force | Out-Null; " + Files);
        var after   = AssertIssued(FullChain(renewal), [ "127.0.0.1" ], "EC", 256, Evidence(renewal));

        Assert.That(after.Thumbprint, Is.Not.EqualTo(before.Thumbprint), $"a new certificate: {Evidence(renewal)}");

    }

    /// <summary>
    /// RFC 9773, section 5: a renewal says which certificate it replaces, and
    /// the server keeps it so.
    /// </summary>
    [Test]
    [Property("RFC", "9773 §5")]
    [Property("Level", "SHOULD")]
    [Cell(InteropCells.RenewalReplaces)]
    public async Task PoshACME_Renews_Saying_Which_Certificate_It_Replaces()
    {

        await StartAsync(Webroot: true);

        var posh    = NewPoshACME();
        var first   = posh.Run(Server_ + Account() + Certificate(Options: "-CertKeyLength 'ec-256'") + Files);
        var before  = AssertIssued(FullChain(first), [ "127.0.0.1" ], "EC", 256, Evidence(first));
        var renewal = posh.Run(Server_ + "Submit-Renewal -Name 'address' -Force | Out-Null; " + Files);
        var after   = AssertIssued(FullChain(renewal), [ "127.0.0.1" ], "EC", 256, Evidence(renewal));

        Assert.That(Server.Issued().Single(issued => issued.DER.AsSpan().SequenceEqual(after.RawData)).Replaces,
                    Is.EqualTo(RawARI.CertificateId(before.RawData)), $"replaces the one before: {Evidence(renewal)}");

    }

    /// <summary>
    /// RFC 9773, section 4.2: Posh-ACME renews unforced when the server's
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
    public async Task PoshACME_Renews_When_The_Window_Of_ARI_Is_Due()
    {

        await StartAsync(Webroot: true);

        var posh   = NewPoshACME();
        var first  = posh.Run(Server_ + Account() + Certificate(Options: "-CertKeyLength 'ec-256'") + Files);
        var before = AssertIssued(FullChain(first), [ "127.0.0.1" ], "EC", 256, Evidence(first));

        await RevokeOutOfBandAsync(before, PoshACME.Value(first, "KEY"));

        var renewal = posh.Run(Server_ + "Submit-Renewal -Name 'address' | Out-Null; " + Files);
        var after   = AssertIssued(FullChain(renewal), [ "127.0.0.1" ], "EC", 256, Evidence(renewal));

        using (Assert.EnterMultipleScope())
        {
            Assert.That(after.Thumbprint, Is.Not.EqualTo(before.Thumbprint), $"renewed, unforced: {Evidence(renewal)}");
            Assert.That(renewal.StdOut,   Does.Contain("AS SOON AS POSSIBLE"), "Posh-ACME read the window");
        }

    }

    /// <summary>The certificate revoked by its own key, by the suite's raw client - superseded.</summary>
    private async Task RevokeOutOfBandAsync(X509Certificate2 Certificate, String? KeyFile)
    {

        Assert.That(KeyFile is not null && File.Exists(KeyFile), Is.True, "Posh-ACME keeps the certificate's key");

        using var certificateKey = ECDsa.Create();
        certificateKey.ImportFromPem(File.ReadAllText(KeyFile!));

        using var raw = await RawACMEClient.ConnectAsync(Server);
        using var jwk = new RawKey(certificateKey, "ES256");

        var revoked   = await raw.PostAsync(jwk, null, raw.Resource("revokeCert"),
                                            $"{{\"certificate\":\"{RawBase64Url.Encode(Certificate.RawData)}\",\"reason\":4}}");

        Assert.That(revoked.Status, Is.EqualTo(200), $"revoked by its key: {revoked}");

    }

    #endregion

    #region Revocation, authorizations

    /// <summary>
    /// Section 7.6: revoked by the account, for keyCompromise - held so by the
    /// server, and in its CRL.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RevokedByAccount)]
    public async Task PoshACME_Revokes_A_Certificate_By_Its_Account()
    {

        await StartAsync(Webroot: true);

        var posh   = NewPoshACME();
        var first  = posh.Run(Server_ + Account() + Certificate(Options: "-CertKeyLength 'ec-256'") + Files);
        var chain  = FullChain(first);
        var leaf   = AssertIssued(chain, [ "127.0.0.1" ], "EC", 256, Evidence(first));
        var result = posh.Run(Server_ + "Revoke-PACertificate -Name 'address' -Reason keyCompromise -Force");

        AssertRevoked(leaf, chain!, 1, Evidence(result));

    }

    /// <summary>
    /// Section 7.6: revoked by the certificate's own key - by a Posh-ACME of
    /// no account at all, given the certificate and its key.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.6")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RevokedByCertificateKey)]
    public async Task PoshACME_Revokes_A_Certificate_By_Its_Key()
    {

        await StartAsync(Webroot: true);

        var first   = NewPoshACME().Run(Server_ + Account() + Certificate(Options: "-CertKeyLength 'ec-256'") + Files +
                                        "Write-Output ('CERT=' + (Get-PACertificate -Name 'address').CertFile)");
        var chain   = FullChain(first);
        var leaf    = AssertIssued(chain, [ "127.0.0.1" ], "EC", 256, Evidence(first));
        var result  = NewPoshACME().Run(Server_ + $"Revoke-PACertificate -CertFile {Q(PoshACME.Value(first, "CERT") ?? "")} -KeyFile {Q(PoshACME.Value(first, "KEY") ?? "")} -Force");

        AssertRevoked(leaf, chain!, null, Evidence(result));

    }

    /// <summary>
    /// Section 7.5.2: the authorization of an order given up - deactivated,
    /// and a new order of the address needs a new proof.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.5.2")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.AuthorizationDeactivated)]
    public async Task PoshACME_Deactivates_An_Authorization()
    {

        await StartAsync(Webroot: true);

        var result = NewPoshACME().Run(Server_ + Account() + Certificate(Options: "-CertKeyLength 'ec-256'") +
                                       "$authz = Get-PAOrder -Name 'address' | Get-PAAuthorization; " +
                                       "Revoke-PAAuthorization -AuthURLs $authz.location -Force; " +
                                       "Write-Output ('DEACTIVATED=' + (Get-PAOrder -Name 'address' | Get-PAAuthorization).status); " +
                                       "New-PAOrder -Domain '127.0.0.1' -Name 'again' -Force | Out-Null; " +
                                       "Write-Output ('NEXT=' + (Get-PAOrder -Name 'again' | Get-PAAuthorization).status)");

        using (Assert.EnterMultipleScope())
        {
            Assert.That(PoshACME.Value(result, "DEACTIVATED"), Is.EqualTo("deactivated"), $"the authorization given up: {Evidence(result)}");
            Assert.That(PoshACME.Value(result, "NEXT"),        Is.EqualTo("pending"),     $"a new order needs a new proof: {Evidence(result)}");
        }

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
    public async Task PoshACME_Is_Told_Of_A_Name_Not_Signed_For()
    {

        await StartAsync(new ACMEServerOptions(AllowedNames: [ "acme.test", "127.0.0.0/8" ]), Webroot: true);

        var result = NewPoshACME().Run(Server_ + Account() + $"New-PACertificate -Domain 'refused.example' -Plugin WebRoot -PluginArgs @{{ WRPath = {Q(WebrootPath)} }} -Force | Out-Null");

        AssertRefused(result, "", "rejectedIdentifier");

    }

    /// <summary>
    /// A server that requires an external account binding says so.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §7.3.4")]
    [Property("Level", "SHOULD")]
    [Cell(InteropCells.RefusedNoEAB)]
    public async Task PoshACME_Is_Told_An_External_Account_Binding_Is_Required()
    {

        await StartAsync(new ACMEServerOptions(ExternalAccountRequired: true));

        var result = NewPoshACME().Run(Server_ + Account());

        AssertRefused(result, "", "externalAccountRequired", "external account");

    }

    /// <summary>
    /// A wrong answer at the token's path: the challenge is invalid, and
    /// Posh-ACME is told why.
    /// </summary>
    [Test]
    [Property("RFC", "8555 §8.3, §7.5.1")]
    [Property("Level", "MUST")]
    [Cell(InteropCells.RefusedWrongAnswer)]
    public async Task PoshACME_Is_Told_Of_A_Wrong_Answer()
    {

        await StartAsync(Webroot: true);
        Webroot!.Fallback = _ => HostAnswer.Text("not the key authorization");

        var result = NewPoshACME().Run(Server_ + Account() + Certificate());

        AssertRefused(result, "", "incorrectResponse", "unauthorized", "invalid");

    }

    #endregion

}
