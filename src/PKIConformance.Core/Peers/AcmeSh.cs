namespace PKIConformance.Core.Peers;

/// <summary>
/// A build of acme.sh: Debian's package, or upstream's at its pin, a clone
/// at the release tag beside it (build/peers/pins.env).
/// </summary>
/// <param name="Tier">"Debian" or "Upstream".</param>
/// <param name="Script">The acme.sh that runs; its dnsapi/ beside it.</param>
public sealed record AcmeShBuild(String  Tier,
                                 String  Script)
{

    /// <summary>Debian 13's acme.sh, 3.1.1: no ARI and no profiles.</summary>
    public static AcmeShBuild Debian { get; } = new ("Debian", "/usr/bin/acme.sh");

    /// <summary>
    /// Upstream's acme.sh at its pin: ARI - the window read at every renewal,
    /// "replaces" sent - and profiles.
    /// </summary>
    public static AcmeShBuild Upstream
        => new ("Upstream", $"{Pins.Lib}/acme.sh-{Pins.Get("ACMESH_VERSION")}/acme.sh");

    /// <summary>
    /// What <c>acme.sh --version</c> says, and "(Debian)" for Debian's:
    /// "acme.sh 3.1.1 (Debian)", "acme.sh 3.1.7".
    /// </summary>
    public String Version
        => versions.GetOrAdd(Tier, _ => {
               var said = Wsl.Run($"{Peer.Quote(Script)} --version", TimeSpan.FromSeconds(15)).StdOut.Trim().Split('\n').Last().Trim().TrimStart('v');
               return $"acme.sh {said}" + (Tier == "Debian" ? " (Debian)" : "");
           });

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<String, String> versions = new ();

    /// <inheritdoc/>
    public override String ToString()
        => Version;

}


/// <summary>
/// acme.sh (https://github.com/acmesh-official/acme.sh), the ACME client in
/// shell, as a peer - Debian's or upstream's - its home, configuration and
/// certificates in the peer's directory.
/// </summary>
public sealed class AcmeSh : Peer
{

    /// <summary>The build that runs.</summary>
    public AcmeShBuild Build { get; }

    /// <summary>
    /// An acme.sh that trusts the given root - a PEM file of this process.
    /// </summary>
    /// <param name="TrustedRootFile">The root it trusts.</param>
    /// <param name="Build">Debian's, by default, or upstream's.</param>
    public AcmeSh(String        TrustedRootFile,
                  AcmeShBuild?  Build = null)

        : base("acmesh", TrustedRootFile)

    {

        this.Build = Build ?? AcmeShBuild.Debian;

        // acme.sh writes into them, and makes neither.
        System.IO.Directory.CreateDirectory(PathOf("config"));
        System.IO.Directory.CreateDirectory(PathOf("certs"));

    }


    #region Run(Arguments, Environment = null, Timeout = null)

    /// <summary>
    /// Run acme.sh with the given command and options; its directories and the
    /// trust of the bench's root are added.
    /// </summary>
    public Wsl.Result Run(String     Arguments,
                          String?    Environment  = null,
                          TimeSpan?  Timeout      = null)

        => Shell($"{Environment} {Quote(Build.Script)} --home {Quote(WslDirectory)} --config-home {Quote(WslPathOf("config"))} --cert-home {Quote(WslPathOf("certs"))} " +
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
