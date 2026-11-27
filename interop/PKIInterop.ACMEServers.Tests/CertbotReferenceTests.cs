using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.ACME;

using PKIConformance.Core;
using PKIConformance.Core.Peers;

namespace PKIInterop.ACMEServers.Tests;

/// <summary>
/// The files of Hermod's certificate manager against what certbot itself
/// writes: the reference run of PLAN.md, section 4.4 - certbot against
/// Pebble, its live/ directory read as the layout to compare with.
/// </summary>
/// <remarks>
/// <para>
/// The manager says of itself that it writes <i>"fullchain.pem and
/// privkey.pem, the names certbot uses"</i>, that <i>"a
/// ServerCertificateFile of another process reads them as it reads
/// certbot's"</i>, and that <i>"the next start of this one finds them, and
/// asks the certificate authority for nothing while they are good"</i>.
/// Nothing in an RFC says how a certificate is kept in files; certbot's
/// live/ is what servers of the world are configured for, and so it is the
/// reference.
/// </para>
/// <para>
/// What certbot wrote is described in the test's output and in
/// its attachment certbot-live-layout.json, from which
/// fixtures/certbot/live-layout.json is taken - the reference of the offline
/// test of the manager (PKIConformance.ACME.Client.Tests).
/// </para>
/// </remarks>
[Category(TestCategories.Wsl)]
public sealed class CertbotReferenceTests : ServerFixture
{

    #region Bench

    /// <inheritdoc/>
    protected override String[] Tools
        => [ PebbleBuild.Upstream.Binary, PebbleBuild.Upstream.ChallTestSrvBinary, "python3", "openssl", "dig" ];

    private UInt16 certbotPort;

    /// <summary>
    /// A Pebble that validates at certbot's own web server, certbot run
    /// against it for <see cref="ServerFixture.Name"/>: certbot's live/ of it.
    /// </summary>
    private Certbot CertbotRun()
    {

        certbotPort = ChallTestSrv.FreeTcpPort();

        var pebble  = Use(Pebble.Start(PebbleBuild.Upstream, certbotPort));
        var certbot = new Certbot(pebble.TrustedRootFile);
        var result  = certbot.Run($"certonly --server {pebble.DirectoryURL} --agree-tos -m admin@acme.test --no-eff-email " +
                                  $"--standalone --http-01-port {certbotPort} -d {Name} --key-type ecdsa --elliptic-curve secp256r1",
                                  TimeSpan.FromMinutes(3));

        Assert.That(certbot.Live(Name, "fullchain.pem"), Is.Not.Null, $"{Certbot.Version} against {pebble.Name}: {result}\n{Tail(certbot.Log, 30)}");

        return certbot;

    }

    #endregion


    #region The layout

    /// <summary>The files of the manager's two, as certbot has them.</summary>
    private static readonly String[] Kept = [ ACMECertificateManager.FullChainFile, ACMECertificateManager.PrivateKeyFile ];

    /// <summary>
    /// certbot's live/ and the manager's directory, each described by
    /// <see cref="Layout"/>: the reference written down as the test's
    /// attachment.
    /// </summary>
    private async Task<(JsonObject Certbot, JsonObject Hermod)> LayoutsAsync()
    {

        using var certbot = CertbotRun();

        var reference     = Layout(certbot.PathOf($"config/live/{Name}"));

        // The manager's own run: against a Pebble that validates at Hermod's responder.
        using var pebble  = Pebble.Start(PebbleBuild.Upstream, HTTP01Port);
        var directory     = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-manager-{Guid.NewGuid():N}")).FullName;

        try
        {

            using var handler = new RecordingHandler(pebble.TrustedRootFile);
            using var client  = new ACMEClient(pebble.DirectoryURL, ACMEAccountKey.Generate(), handler, PollInterval: TimeSpan.FromMilliseconds(250));
            var       dns01   = new DNS01ChallengeResponder((name, value, ct) => pebble.DNS.SetTXTAsync(name, value, ct),
                                                            (name, value, ct) => pebble.DNS.ClearTXTAsync(name, ct));

            await client.CreateAccountAsync([ "admin@acme.test" ], TermsOfServiceAgreed: true);

            await using (var manager = new ACMECertificateManager(client, [ Name ], [ HTTP01, dns01 ], Directory: directory))
                Assert.That(await manager.StartAsync(), Is.True, $"{manager.LastError}\n{handler.Log}");

            var hermod    = Layout(directory);
            var described = Path.Combine(Path.GetTempPath(), $"certbot-live-layout-{Guid.NewGuid():N}.json");

            File.WriteAllText(described,
                              new JsonObject {
                                  ["certbot"]  = Certbot.Version,
                                  ["server"]   = Server.Name,
                                  ["live"]     = reference
                              }.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));

            TestContext.AddTestAttachment(described, "what certbot wrote");
            TestContext.Out.WriteLine($"certbot:  {reference.ToJsonString()}\nHermod:   {hermod.ToJsonString()}");

            return (reference, hermod);

        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }

    }

    [Test, Property("Level", "—")]
    public async Task The_Managers_Files_Are_Named_Moded_And_Encoded_As_Certbots()
    {

        var (reference, hermod) = await LayoutsAsync();

        using (Assert.EnterMultipleScope())
        {

            foreach (var file in Kept)
            {
                Assert.That(reference[file],                       Is.Not.Null,                                          $"certbot has a {file}");
                Assert.That(hermod[file],                          Is.Not.Null,                                          $"the manager has a {file}");
                Assert.That(hermod[file]?["pem"]?.ToJsonString(),  Is.EqualTo(reference[file]?["pem"]?.ToJsonString()),  $"{file}: the blocks of PEM, as certbot's");
                Assert.That(hermod[file]?["mode"]?.ToString(),     Is.EqualTo(reference[file]?["mode"]?.ToString()),     $"{file}: the mode of the file, as certbot's");
                Assert.That(hermod[file]?["lineEnd"]?.ToString(),  Is.EqualTo(reference[file]?["lineEnd"]?.ToString()),  $"{file}: the line ends, as certbot's");
            }

            Assert.That(hermod[ACMECertificateManager.PrivateKeyFile]?["key"]?.ToString(), Is.EqualTo(reference[ACMECertificateManager.PrivateKeyFile]?["key"]?.ToString()),
                        "the kind of key, as certbot's of its default kind");

        }

    }

    /// <summary>
    /// certbot ends every file with a newline; RFC 7468, section 3 makes the
    /// last one optional - and a file made by <c>cat privkey.pem
    /// fullchain.pem</c>, as HAProxy wants one, then has "-----END PRIVATE
    /// KEY----------BEGIN CERTIFICATE-----" on one line (M-4).
    /// </summary>
    [Test, Property("RFC", "7468 §3"), Property("Level", "—")]
    [Category(TestCategories.KnownIssue), Property("Finding", "M-4")]
    public async Task The_Managers_Files_End_With_A_Newline_As_Certbots()
    {

        var (reference, hermod) = await LayoutsAsync();

        using (Assert.EnterMultipleScope())
        {
            foreach (var file in Kept)
                Assert.That(hermod[file]?["finalNewline"]?.GetValue<Boolean>(), Is.EqualTo(reference[file]?["finalNewline"]?.GetValue<Boolean>()),
                            $"{file}: a newline at the end, as certbot's");
        }

    }

    #endregion


    #region Taking over what certbot keeps

    [Test, Property("Level", "—")]
    public void Hermods_ServerCertificateFile_Reads_Certbots_Live_Files()
    {

        using var certbot = CertbotRun();

        var live          = certbot.PathOf($"config/live/{Name}");
        var file          = new ServerCertificateFile(Path.Combine(live, "fullchain.pem"), Path.Combine(live, "privkey.pem"));
        var leaf          = X509Certificate2.CreateFromPem(certbot.Live(Name, "cert.pem")!);

        Assert.That(file.Current?.Certificate.Thumbprint, Is.EqualTo(leaf.Thumbprint), $"through certbot's symbolic links: {file.LastError}");
    }

    [Test, Property("Level", "—")]
    public async Task The_Manager_Takes_Over_What_Certbot_Keeps_And_Orders_Nothing()
    {

        using var certbot = CertbotRun();

        var live          = certbot.PathOf($"config/live/{Name}");
        var leaf          = X509Certificate2.CreateFromPem(certbot.Live(Name, "cert.pem")!);
        var client        = await ClientWithAccountAsync();

        await using var manager = new ACMECertificateManager(client, [ Name ], Responders, Directory: live);

        Assert.That(manager.Certificate?.Certificate.Thumbprint, Is.EqualTo(leaf.Thumbprint), $"certbot's certificate read at once: {manager.LastError}");

        Assert.That(await manager.StartAsync(), Is.True, manager.LastError);

        using (Assert.EnterMultipleScope())
        {
            Assert.That(manager.Certificate?.Certificate.Thumbprint, Is.EqualTo(leaf.Thumbprint), "and kept");
            Assert.That(Wire.Exchanges.Where(exchange => exchange.Method == "POST" && exchange.Status == 201 && exchange.ResponseBody.Contains("\"identifiers\"", StringComparison.Ordinal)),
                        Is.Empty, $"no order of a certificate that is not due: {Evidence}");
        }

    }

    #endregion


    #region (static) Layout(Directory)

    /// <summary>
    /// What a directory of certificate files is, file by file: where a
    /// symbolic link points, the mode of what it points to, the labels of its
    /// blocks of PEM, its line ends, whether it ends with a newline, and the
    /// kind of a private key.
    /// </summary>
    private static JsonObject Layout(String Directory)
    {

        var layout = new JsonObject();

        foreach (var path in System.IO.Directory.EnumerateFiles(Directory).Order(StringComparer.Ordinal))
        {

            var info    = new FileInfo(path);
            var target  = info.LinkTarget is not null ? info.ResolveLinkTarget(returnFinalTarget: true)?.FullName ?? path : path;
            var text    = File.ReadAllText(path);
            var labels  = text.Split('\n').
                               Where (line => line.StartsWith("-----BEGIN ", StringComparison.Ordinal)).
                               Select(line => line.TrimEnd('\r')["-----BEGIN ".Length..].TrimEnd('-')).
                               ToArray();

            var entry   = new JsonObject {
                              ["mode"]          = OperatingSystem.IsWindows() ? "" : Convert.ToString((Int32) File.GetUnixFileMode(target), 8).PadLeft(4, '0'),
                              ["pem"]           = new JsonArray([ .. labels.Select(label => JsonValue.Create(label)) ]),
                              ["lineEnd"]       = text.Contains("\r\n", StringComparison.Ordinal) ? "CRLF" : "LF",
                              ["finalNewline"]  = text.EndsWith('\n')
                          };

            if (info.LinkTarget is not null)
                entry["link"] = info.LinkTarget;

            if (labels.Any(label => label.Contains("PRIVATE KEY", StringComparison.Ordinal)))
            {
                using var ec  = System.Security.Cryptography.ECDsa.Create();
                using var rsa = System.Security.Cryptography.RSA.Create();
                entry["key"]  = TryImport(ec, text)  ? $"EC {ec.KeySize}"   :
                                TryImport(rsa, text) ? $"RSA {rsa.KeySize}" : "?";
            }

            layout[Path.GetFileName(path)] = entry;

        }

        return layout;

    }

    private static Boolean TryImport(System.Security.Cryptography.AsymmetricAlgorithm Key, String PEM)
    {
        try
        {
            Key.ImportFromPem(PEM);
            return true;
        }
        catch (Exception e) when (e is ArgumentException or System.Security.Cryptography.CryptographicException)
        {
            return false;
        }
    }

    #endregion

}
