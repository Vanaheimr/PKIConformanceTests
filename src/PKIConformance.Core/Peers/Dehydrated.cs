namespace PKIConformance.Core.Peers;

/// <summary>
/// dehydrated (https://github.com/dehydrated-io/dehydrated), the ACME client
/// in bash, as a peer: Debian's package, with a configuration of the peer's
/// own. It has no web server: http-01 answers go as files into a directory a
/// web server of the bench serves.
/// </summary>
public sealed class Dehydrated(String TrustedRootFile) : Peer("dehydrated", TrustedRootFile)
{

    #region Properties

    /// <summary>What dehydrated says it is.</summary>
    public static String Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => Wsl.Run("dpkg-query -W -f='dehydrated ${Version}' dehydrated", TimeSpan.FromSeconds(15)).StdOut.Trim());

    /// <summary>"dehydrated 0.7.2 (Debian)" - its column of the interop matrix.</summary>
    public static String Name
        => $"{Version.Split('-')[0]} (Debian)";

    #endregion


    #region Configure(...)

    /// <summary>
    /// Write the configuration: the CA, the trust of the bench's root, where
    /// the answers to http-01 go, the kind of key.
    /// </summary>
    /// <param name="DirectoryURL">The ACME directory, as the peer reaches it.</param>
    /// <param name="WellKnown">The directory the answers go into, as the peer sees it - /.well-known/acme-challenge/ of the bench's web server.</param>
    /// <param name="KeyAlgorithm">rsa, prime256v1 or secp384r1.</param>
    /// <param name="KeySize">The size of an RSA key.</param>
    /// <param name="Email">The contact of the account.</param>
    /// <param name="More">More lines of configuration.</param>
    public void Configure(String   DirectoryURL,
                          String   WellKnown,
                          String   KeyAlgorithm  = "prime256v1",
                          Int32    KeySize       = 2048,
                          String?  Email         = null,
                          String?  More          = null)

        => Write("config", $"""
                            CA="{DirectoryURL}"
                            CURL_OPTS="--cacert {TrustedRoot}"
                            BASEDIR="{WslDirectory}"
                            WELLKNOWN="{WellKnown}"
                            CHALLENGETYPE="http-01"
                            KEY_ALGO="{KeyAlgorithm}"
                            KEYSIZE="{KeySize}"
                            {(Email is not null ? $"CONTACT_EMAIL=\"{Email}\"" : "")}
                            {More}
                            """);

    #endregion

    #region Run(Arguments, Timeout = null)

    /// <summary>
    /// Run dehydrated with the configuration of <see cref="Configure"/>.
    /// </summary>
    public Wsl.Result Run(String     Arguments,
                          TimeSpan?  Timeout = null)

        => Shell($"dehydrated -f {Quote(WslPathOf("config"))} {Arguments}", Timeout ?? TimeSpan.FromSeconds(180));

    #endregion

    #region Certificate(Name, File)

    /// <summary>
    /// A file dehydrated keeps of the certificate of the name - "cert.pem",
    /// "chain.pem", "fullchain.pem", "privkey.pem" - or null.
    /// </summary>
    public String? Certificate(String Name, String File = "cert.pem")
        => Read($"certs/{Name}/{File}");

    #endregion

}
