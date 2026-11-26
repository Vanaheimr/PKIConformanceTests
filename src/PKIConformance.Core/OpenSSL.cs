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
