namespace PKIConformance.Core.Peers;

/// <summary>
/// certbot (https://certbot.eff.org), the EFF's ACME client in Python, as a
/// peer: Debian's package, with its config, work and logs directories in the
/// peer's own.
/// </summary>
/// <remarks>
/// <para>
/// certbot is started through a launcher of the suite's that takes
/// /usr/local off Python's path first: a <c>cryptography</c> installed by pip
/// there shadows Debian's and certbot dies on import (PLAN.md, "Learned in
/// phase 0"). What runs is Debian's certbot with Debian's libraries, as on a
/// clean Debian 13.
/// </para>
/// <para>
/// Debian 13 has certbot 4.0.0: profiles, no ARI (4.1.0) and no IP
/// identifiers - those cells of the matrix are grey for it.
/// </para>
/// </remarks>
public sealed class Certbot : Peer
{

    #region Data

    private const String LauncherCode = """
                                        import sys
                                        sys.path[:] = [p for p in sys.path if not p.startswith("/usr/local/")]
                                        sys.argv[0] = "certbot"
                                        from certbot.main import main
                                        sys.exit(main())
                                        """;

    private readonly String launcher;

    #endregion

    #region Properties

    /// <summary>What <c>certbot --version</c> says.</summary>
    public static String Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => {
        using var probe = new Certbot(Path.GetTempFileName());
        return probe.Run("--version").StdOut.Trim().Split('\n').LastOrDefault()?.Trim() ?? "certbot ?";
    });

    #endregion

    #region Constructor(s)

    /// <summary>
    /// A certbot that trusts the given root - a PEM file of this process.
    /// </summary>
    public Certbot(String TrustedRootFile)
        : base("certbot", TrustedRootFile)
    {
        launcher = Write("run-certbot.py", LauncherCode);
    }

    #endregion


    #region Run(Arguments, Timeout = null)

    /// <summary>
    /// Run certbot with the given subcommand and options; the directories,
    /// --non-interactive and the trust of the bench's root are added.
    /// </summary>
    public Wsl.Result Run(String     Arguments,
                          TimeSpan?  Timeout = null)

        => Shell($"REQUESTS_CA_BUNDLE={Quote(TrustedRoot)} python3 {Quote(launcher)} {Arguments} --non-interactive " +
                 $"--config-dir {Quote(WslPathOf("config"))} --work-dir {Quote(WslPathOf("work"))} --logs-dir {Quote(WslPathOf("logs"))}",
                 Timeout ?? TimeSpan.FromSeconds(180));

    #endregion

    #region Live(Name, File) / Log

    /// <summary>
    /// A file of certbot's live/ directory of the certificate name -
    /// "fullchain.pem", "cert.pem", "chain.pem", "privkey.pem" - or null.
    /// </summary>
    public String? Live(String CertificateName, String File)
        => Read($"config/live/{CertificateName}/{File}");

    /// <summary>What certbot wrote into its log - the evidence of a failure.</summary>
    public String Log
        => Read("logs/letsencrypt.log") ?? "";

    #endregion

}
