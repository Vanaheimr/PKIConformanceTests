namespace PKIConformance.Core.Peers;

/// <summary>
/// acme.sh (https://github.com/acmesh-official/acme.sh), the ACME client in
/// shell, as a peer: Debian's package, its home, configuration and
/// certificates in the peer's directory.
/// </summary>
/// <remarks>
/// Debian 13 has acme.sh 3.1.1: no ARI and no profiles - grey cells.
/// </remarks>
public sealed class AcmeSh : Peer
{

    /// <summary>
    /// An acme.sh that trusts the given root - a PEM file of this process.
    /// </summary>
    public AcmeSh(String TrustedRootFile)
        : base("acmesh", TrustedRootFile)
    {
        // acme.sh writes into them, and makes neither.
        System.IO.Directory.CreateDirectory(PathOf("config"));
        System.IO.Directory.CreateDirectory(PathOf("certs"));
    }

    #region Properties

    /// <summary>What <c>acme.sh --version</c> says.</summary>
    public static String Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => "acme.sh " + Wsl.Run("acme.sh --version", TimeSpan.FromSeconds(15)).StdOut.Trim().Split('\n').Last().Trim());

    #endregion


    #region Run(Arguments, Environment = null, Timeout = null)

    /// <summary>
    /// Run acme.sh with the given command and options; its directories and the
    /// trust of the bench's root are added.
    /// </summary>
    public Wsl.Result Run(String     Arguments,
                          String?    Environment  = null,
                          TimeSpan?  Timeout      = null)

        => Shell($"{Environment} acme.sh --home {Quote(WslDirectory)} --config-home {Quote(WslPathOf("config"))} --cert-home {Quote(WslPathOf("certs"))} " +
                 $"--ca-bundle {Quote(TrustedRoot)} --log {Quote(WslPathOf("acme.sh.log"))} {Arguments}",
                 Timeout ?? TimeSpan.FromSeconds(180));

    #endregion

    #region Certificate(Name) / FullChain(Name) / Key(Name)

    private String? Of(String Name, String File)
        => Read($"certs/{Name}_ecc/{File}") ?? Read($"certs/{Name}/{File}");

    /// <summary>The leaf acme.sh keeps of the name, or null.</summary>
    public String? Certificate(String Name)
        => Of(Name, $"{Name}.cer");

    /// <summary>The leaf and its issuers acme.sh keeps of the name, or null.</summary>
    public String? FullChain(String Name)
        => Of(Name, "fullchain.cer");

    /// <summary>The private key acme.sh keeps of the name, or null.</summary>
    public String? Key(String Name)
        => Of(Name, $"{Name}.key");

    /// <summary>What acme.sh wrote into its log.</summary>
    public String Log
        => Read("acme.sh.log") ?? "";

    #endregion

}
