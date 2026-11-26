namespace PKIConformance.Core.Peers;

/// <summary>
/// lego (https://github.com/go-acme/lego), the ACME client of Go, as a peer:
/// run through the WSL bridge, one storage directory per use.
/// </summary>
/// <remarks>
/// The version is the one pinned in build/peers/pins.env; Debian's lego is
/// three years behind and has neither ARI nor profiles (PLAN.md, section 6).
/// </remarks>
public sealed class Lego(String TrustedRootFile) : Peer("lego", TrustedRootFile)
{

    #region Properties

    /// <summary>
    /// What <c>lego --version</c> says - for messages and the interop matrix.
    /// </summary>
    public static String Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => Wsl.Run("lego --version", TimeSpan.FromSeconds(15)).StdOut.Trim());

    /// <summary>
    /// Where this lego keeps its accounts and certificates.
    /// </summary>
    public String StoragePath
        => WslDirectory;

    #endregion


    #region Run(Arguments, Environment = null, Timeout = null)

    /// <summary>
    /// Run lego with the given command and options - <c>--path</c> is added -
    /// and return what it said, both streams in one, in plain text.
    /// </summary>
    /// <param name="Arguments">The command and its options.</param>
    /// <param name="Environment">More environment, as "NAME=value ..." for sh.</param>
    /// <param name="Timeout">How long it may take.</param>
    /// <param name="Answer">What to answer a question lego asks on its console, as "y".</param>
    public Wsl.Result Run(String     Arguments,
                          String?    Environment  = null,
                          TimeSpan?  Timeout      = null,
                          String?    Answer       = null)

        => Shell($"{(Answer is not null ? $"printf '%s\\n' {Quote(Answer)} | " : "")}" +
                 $"LEGO_CA_CERTIFICATES={Quote(TrustedRoot)} {Environment} lego --log.format text {Arguments} --path {Quote(StoragePath)}",
                 Timeout ?? TimeSpan.FromSeconds(120));

    #endregion

    #region Certificate(Name) / Key(Name)

    /// <summary>
    /// The certificate lego keeps of the name - the leaf and its issuers, as
    /// lego bundles them - or null.
    /// </summary>
    public String? Certificate(String Name)
        => Files($"{FileNameOf(Name)}.crt").Select(file => file.Content).FirstOrDefault();

    /// <summary>
    /// The private key lego keeps of the name, or null.
    /// </summary>
    public String? Key(String Name)
        => Files($"{FileNameOf(Name)}.key").Select(file => file.Content).FirstOrDefault();

    /// <summary>
    /// The name of lego's files of a certificate: "*" written as "_", and ":"
    /// - of an IPv6 address - as "-" ("::1" is kept as "--1.crt").
    /// </summary>
    public static String FileNameOf(String Name)
        => Name.Replace("*", "_").Replace(":", "-");

    #endregion

}
