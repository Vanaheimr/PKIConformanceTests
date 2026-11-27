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

}
