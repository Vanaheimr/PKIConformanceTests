namespace PKIConformance.Core.Peers;

/// <summary>
/// An ACME client of the world - certbot, lego, acme.sh, dehydrated, uacme -
/// run as the native Linux program it is, through the WSL bridge (or
/// directly, on Linux), with a directory of its own for everything it keeps.
/// </summary>
/// <remarks>
/// The directory is one of this process's temporary directory, handed to the
/// peer by its WSL path: the test reads what the peer wrote as files of its
/// own. Natively both paths are the same.
/// </remarks>
public abstract class Peer : IDisposable
{

    #region Properties

    /// <summary>The peer's directory, as this process sees it.</summary>
    public String  Directory     { get; }

    /// <summary>The peer's directory, as the peer sees it.</summary>
    public String  WslDirectory  { get; }

    /// <summary>The PEM file of the root the peer trusts the ACME server's TLS by, as the peer sees it.</summary>
    public String  TrustedRoot   { get; }

    #endregion

    #region Constructor(s)

    /// <summary>
    /// A peer of the given name, trusting the given root - a PEM file of this
    /// process.
    /// </summary>
    protected Peer(String  Name,
                   String  TrustedRootFile)
    {

        this.Directory     = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-{Name}-{Guid.NewGuid():N}"[..48])).FullName;
        this.WslDirectory  = Wsl.ToWslPath(Directory);
        this.TrustedRoot   = Wsl.ToWslPath(TrustedRootFile);

    }

    #endregion


    #region Paths and files

    /// <summary>A path below the peer's directory, as the peer sees it.</summary>
    public String WslPathOf(String Relative)
        => $"{WslDirectory}/{Relative}";

    /// <summary>A path below the peer's directory, as this process sees it.</summary>
    public String PathOf(String Relative)
        => Path.Combine(Directory, Relative.Replace('/', Path.DirectorySeparatorChar));

    /// <summary>A file below the peer's directory, or null.</summary>
    public String? Read(String Relative)
        => File.Exists(PathOf(Relative)) ? File.ReadAllText(PathOf(Relative)) : null;

    /// <summary>Write a file below the peer's directory.</summary>
    public String Write(String Relative, String Content)
    {
        var path = PathOf(Relative);
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, Content);
        return WslPathOf(Relative);
    }

    /// <summary>Every file of the given name below the peer's directory, with its content.</summary>
    public IReadOnlyList<(String Path, String Content)> Files(String Name)

        => [ .. System.IO.Directory.EnumerateFiles(Directory, Name, SearchOption.AllDirectories).
                                     Order().
                                     Select(path => (path, File.ReadAllText(path))) ];

    /// <summary>A text quoted for sh, in single quotes.</summary>
    public static String Quote(String Text)
        => "'" + Text.Replace("'", "'\\''") + "'";

    #endregion

    #region Shell(Command, Timeout = null)

    /// <summary>
    /// Run a command line of sh for the peer, both streams in one.
    /// </summary>
    protected static Wsl.Result Shell(String     Command,
                                      TimeSpan?  Timeout = null)

        => Wsl.Run($"{Command} 2>&1", Timeout ?? TimeSpan.FromSeconds(120));

    #endregion

    #region Dispose()

    /// <summary>
    /// Take the directory away again.
    /// </summary>
    public virtual void Dispose()
    {
        try
        {
            System.IO.Directory.Delete(Directory, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Left behind in the temporary directory: not worth failing a test over.
        }
        GC.SuppressFinalize(this);
    }

    #endregion

}
