namespace PKIConformance.Core.Peers;

/// <summary>
/// uacme (https://github.com/ndilieto/uacme), the ACME client in C, as a
/// peer: Debian's package, its configuration directory the peer's own, its
/// answers to http-01 written by its own hook script into a directory the
/// bench's web server serves.
/// </summary>
/// <remarks>
/// uacme takes no CA file: it trusts what libcurl-gnutls trusts, the system's
/// bundle. The bench lays a bundle with its root over it in the namespace of
/// the run (<see cref="TestEnvironment.TrustSystemWide"/>).
/// </remarks>
public sealed class Uacme(String TrustedRootFile) : Peer("uacme", TrustedRootFile)
{

    /// <summary>The hook Debian ships, which writes the answers of http-01 as files.</summary>
    public const String Hook = "/usr/share/uacme/uacme.sh";

    #region Properties

    /// <summary>What <c>uacme --version</c> says.</summary>
    public static String Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => Wsl.Run("uacme --version 2>&1", TimeSpan.FromSeconds(15)).StdOut.Trim().Split('\n').First().Trim());

    /// <summary>"uacme 1.7.6 (Debian)" - its column of the interop matrix.</summary>
    public static String Name
        => $"uacme {Version.Split(' ')[^1]} (Debian)";

    #endregion


    #region Run(DirectoryURL, Arguments, WellKnown = null, Timeout = null)

    /// <summary>
    /// Run uacme against the directory with the given options and command;
    /// the configuration directory is added, and where the answers of
    /// http-01 go (UACME_CHALLENGE_PATH of its hook).
    /// </summary>
    public Wsl.Result Run(String     DirectoryURL,
                          String     Arguments,
                          String?    WellKnown  = null,
                          TimeSpan?  Timeout    = null)

        => Shell($"{(WellKnown is not null ? $"UACME_CHALLENGE_PATH={Quote(WellKnown)} " : "")}uacme -v -a {Quote(DirectoryURL)} -c {Quote(WslDirectory)} {Arguments}",
                 Timeout ?? TimeSpan.FromSeconds(180));

    #endregion

    #region Certificate(Name) / Key(Name)

    /// <summary>The certificate - leaf and issuers - uacme keeps of the name, or null.</summary>
    public String? Certificate(String Name)
        => Read($"{Name}/cert.pem");

    /// <summary>The private key uacme keeps of the name, or null.</summary>
    public String? Key(String Name)
        => Read($"private/{Name}/key.pem");

    #endregion

}
