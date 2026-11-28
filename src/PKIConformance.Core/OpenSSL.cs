using System.Security.Cryptography.X509Certificates;

namespace PKIConformance.Core;

/// <summary>
/// openssl in WSL as the judge of a certificate a peer was issued: whether
/// its chain verifies to the server's root, and whether a CRL of the server
/// lists it - by the tool everybody's TLS stack is measured against, not by
/// the PKI and not by .NET alone.
/// </summary>
public static class OpenSSL
{

    /// <summary>What <c>openssl version</c> says.</summary>
    public static String Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => Wsl.Run("openssl version", TimeSpan.FromSeconds(15)).StdOut.Trim());

    /// <summary>
    /// The entries of a CRL as <c>openssl crl -text</c> reads it: the serial
    /// number - hexadecimal, upper case, without leading zeros - and its
    /// reason ("Superseded", "Key Compromise", ...), or "" without one.
    /// </summary>
    /// <param name="CRL">The CRL, DER.</param>
    public static IReadOnlyDictionary<String, String> CRLEntries(Byte[] CRL)
    {

        var file = Path.Combine(Path.GetTempPath(), $"pkiconformance-crl-{Guid.NewGuid():N}.der");

        try
        {

            File.WriteAllBytes(file, CRL);

            var lines   = Wsl.Run($"openssl crl -inform DER -in '{Wsl.ToWslPath(file)}' -noout -text", TimeSpan.FromSeconds(15)).
                              StdOut.Split('\n').Select(line => line.Trim()).ToArray();

            var entries = new Dictionary<String, String>(StringComparer.Ordinal);
            var serial  = (String?) null;

            for (var i = 0; i < lines.Length; i++)
            {

                if (lines[i].StartsWith("Serial Number:", StringComparison.Ordinal))
                {
                    serial          = lines[i]["Serial Number:".Length..].Trim().TrimStart('0').ToUpperInvariant();
                    entries[serial] = "";
                }

                else if (serial is not null && lines[i].StartsWith("X509v3 CRL Reason Code:", StringComparison.Ordinal) && i + 1 < lines.Length)
                    entries[serial] = lines[i + 1];

            }

            return entries;

        }
        finally
        {
            File.Delete(file);
        }

    }

    /// <summary>
    /// <c>openssl crl -verify</c>: whether the CRL is signed by its issuer -
    /// "verify OK" - given as PEM.
    /// </summary>
    /// <param name="CRL">The CRL, DER.</param>
    /// <param name="IssuerPEM">The certificate of its issuer.</param>
    public static Wsl.Result VerifyCRL(Byte[]  CRL,
                                       String  IssuerPEM)
    {

        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-openssl-{Guid.NewGuid():N}")).FullName;

        try
        {

            File.WriteAllBytes(Path.Combine(directory, "issuer.crl"), CRL);
            File.WriteAllText (Path.Combine(directory, "issuer.pem"), IssuerPEM);

            var wsl = Wsl.ToWslPath(directory);

            return Wsl.Run($"openssl crl -inform DER -in '{wsl}/issuer.crl' -CAfile '{wsl}/issuer.pem' -noout 2>&1", TimeSpan.FromSeconds(15));

        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
        }

    }

    /// <summary>
    /// <c>openssl verify</c> of a leaf with the intermediates of its chain,
    /// against the root - and, where a CRL is given, with <c>-crl_check</c>.
    /// </summary>
    /// <param name="RootPEM">The root it is to chain to.</param>
    /// <param name="ChainPEM">The leaf and its intermediates, in PEM, the leaf first - as a fullchain.pem.</param>
    /// <param name="CRL">A CRL of the issuer, DER, to check the leaf against.</param>
    public static Wsl.Result Verify(String   RootPEM,
                                    String   ChainPEM,
                                    Byte[]?  CRL = null)
    {

        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-openssl-{Guid.NewGuid():N}")).FullName;

        try
        {

            var certificates = new X509Certificate2Collection();
            certificates.ImportFromPem(ChainPEM);

            if (certificates.Count == 0)
                return new Wsl.Result(-1, "", "no certificate in the chain");

            File.WriteAllText(Path.Combine(directory, "root.pem"),  RootPEM);
            File.WriteAllText(Path.Combine(directory, "leaf.pem"),  certificates[0].ExportCertificatePem() + "\n");

            var untrusted = String.Concat(certificates.Skip(1).Select(certificate => certificate.ExportCertificatePem() + "\n"));

            if (untrusted.Length > 0)
                File.WriteAllText(Path.Combine(directory, "chain.pem"), untrusted);

            var crlOption = "";

            if (CRL is not null)
            {
                File.WriteAllBytes(Path.Combine(directory, "issuer.crl"), CRL);
                Wsl.Run($"openssl crl -inform DER -in '{Wsl.ToWslPath(Path.Combine(directory, "issuer.crl"))}' -out '{Wsl.ToWslPath(Path.Combine(directory, "issuer.crl.pem"))}'", TimeSpan.FromSeconds(15));
                crlOption = $"-crl_check -CRLfile '{Wsl.ToWslPath(Path.Combine(directory, "issuer.crl.pem"))}' ";
            }

            var wsl = Wsl.ToWslPath(directory);

            return Wsl.Run($"openssl verify -purpose sslserver {crlOption}-CAfile '{wsl}/root.pem' " +
                           (untrusted.Length > 0 ? $"-untrusted '{wsl}/chain.pem' " : "") +
                           $"'{wsl}/leaf.pem' 2>&1",
                           TimeSpan.FromSeconds(30));

        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
        }

    }


    #region Native: the host's own openssl, for the Windows leg

    /// <summary>
    /// The host's own openssl - on Windows Git's, or the runner's - which
    /// judges the Windows leg, where there is no WSL; or null.
    /// </summary>
    public static String? NativeExecutable
        => nativeExecutable.Value;

    private static readonly Lazy<String?> nativeExecutable = new (() => Native.Find(OperatingSystem.IsWindows() ? "openssl.exe" : "openssl"));

    /// <summary>What the host's <c>openssl version</c> says.</summary>
    public static String NativeVersion
        => nativeVersion.Value;

    private static readonly Lazy<String> nativeVersion = new (() => NativeExecutable is String openssl
                                                                         ? Native.Run(openssl, [ "version" ], Timeout: TimeSpan.FromSeconds(15)).StdOut.Trim()
                                                                         : "no openssl on the PATH");

    /// <summary>
    /// <see cref="Verify"/> by the host's own openssl: the leaf with the
    /// intermediates of its chain against the root, with <c>-crl_check</c>
    /// where a CRL is given.
    /// </summary>
    public static Wsl.Result VerifyNative(String   RootPEM,
                                          String   ChainPEM,
                                          Byte[]?  CRL = null)
    {

        var openssl   = NativeExecutable ?? throw new InvalidOperationException("No openssl on the PATH.");
        var directory = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-openssl-{Guid.NewGuid():N}")).FullName;

        try
        {

            var certificates = new X509Certificate2Collection();
            certificates.ImportFromPem(ChainPEM);

            if (certificates.Count == 0)
                return new Wsl.Result(-1, "", "no certificate in the chain");

            var root      = Path.Combine(directory, "root.pem");
            var leaf      = Path.Combine(directory, "leaf.pem");
            var chain     = Path.Combine(directory, "chain.pem");
            var untrusted = String.Concat(certificates.Skip(1).Select(certificate => certificate.ExportCertificatePem() + "\n"));

            File.WriteAllText(root, RootPEM);
            File.WriteAllText(leaf, certificates[0].ExportCertificatePem() + "\n");

            List<String> arguments = [ "verify", "-purpose", "sslserver", "-CAfile", root ];

            if (untrusted.Length > 0)
            {
                File.WriteAllText(chain, untrusted);
                arguments.AddRange([ "-untrusted", chain ]);
            }

            if (CRL is not null)
            {
                var der = Path.Combine(directory, "issuer.crl");
                var pem = Path.Combine(directory, "issuer.crl.pem");
                File.WriteAllBytes(der, CRL);
                Native.Run(openssl, [ "crl", "-inform", "DER", "-in", der, "-out", pem ], Timeout: TimeSpan.FromSeconds(15));
                arguments.AddRange([ "-crl_check", "-CRLfile", pem ]);
            }

            arguments.Add(leaf);

            var result = Native.Run(openssl, arguments, Timeout: TimeSpan.FromSeconds(30));

            // As Verify has it: "<file>: OK" - the file by its name alone.
            return result with { StdOut = result.StdOut.Replace(leaf, "leaf.pem") + result.StdErr };

        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
        }

    }

    #endregion

}
