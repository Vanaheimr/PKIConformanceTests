namespace PKIConformance.Core.Peers;

/// <summary>
/// lego (https://github.com/go-acme/lego), the ACME client of Go, as a peer:
/// run through the WSL bridge, one storage directory per use.
/// </summary>
/// <remarks>
/// The version is the one pinned in build/peers/pins.env; Debian's lego is
/// three years behind and has neither ARI nor profiles (PLAN.md, section 6).
/// </remarks>
public sealed class Lego : IDisposable
{

    #region Properties

    /// <summary>
    /// What <c>lego --version</c> says - for messages and the interop matrix.
    /// </summary>
    public static String Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => Wsl.Run("lego --version", TimeSpan.FromSeconds(15)).StdOut.Trim());

    /// <summary>
    /// Where this lego keeps its accounts and certificates, inside WSL.
    /// </summary>
    public String  StoragePath      { get; } = $"/tmp/pkiconformance-lego-{Guid.NewGuid():N}";

    /// <summary>
    /// The PEM file of the root lego trusts the ACME server's TLS by, as WSL
    /// sees it - handed over in LEGO_CA_CERTIFICATES.
    /// </summary>
    public String  TrustedRootFile  { get; }

    #endregion

    #region Constructor(s)

    /// <summary>
    /// A lego that trusts the given root - a PEM file of this process.
    /// </summary>
    public Lego(String TrustedRootFile)
    {
        this.TrustedRootFile = Wsl.ToWslPath(TrustedRootFile);
    }

    #endregion


    #region Run(Arguments, Timeout = null)

    /// <summary>
    /// Run lego with the given command and options - <c>--path</c> is added -
    /// and return what it said, both streams in one, in plain text.
    /// </summary>
    public Wsl.Result Run(String     Arguments,
                          TimeSpan?  Timeout   = null)

        => Wsl.Run($"LEGO_CA_CERTIFICATES='{TrustedRootFile}' lego --log.format text {Arguments} --path '{StoragePath}' 2>&1",
                   Timeout ?? TimeSpan.FromSeconds(90));

    #endregion

    #region Files(Name)

    /// <summary>
    /// The files of the given name lego wrote, with their content.
    /// </summary>
    public IReadOnlyList<(String Path, String Content)> Files(String Name)
    {

        var paths = Wsl.Run($"find '{StoragePath}' -type f -name '{Name}' 2>/dev/null", TimeSpan.FromSeconds(15)).
                        StdOut.
                        Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return [.. paths.Select(path => (path, Wsl.Run($"cat '{path}'", TimeSpan.FromSeconds(15)).StdOut))];

    }

    #endregion

    #region Dispose()

    /// <summary>
    /// Take the storage away again.
    /// </summary>
    public void Dispose()
        => Wsl.Run($"rm -rf '{StoragePath}'", TimeSpan.FromSeconds(15));

    #endregion

}
