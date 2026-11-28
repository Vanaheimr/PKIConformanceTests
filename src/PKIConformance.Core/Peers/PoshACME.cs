namespace PKIConformance.Core.Peers;

/// <summary>
/// Posh-ACME (https://poshac.me), the ACME client of PowerShell, as a peer of
/// the Windows leg: its module at its pin (build/peers/setup-windows.ps1),
/// run by Windows PowerShell 5.1 - the PowerShell every Windows has - with a
/// home of its own per test (POSHACME_HOME), so that nothing of the user's
/// Posh-ACME is read or written.
/// </summary>
/// <remarks>
/// Posh-ACME trusts the server's TLS by Windows' store, which the suite does
/// not touch; the server's certificate is let through by
/// <c>Set-PAServer -SkipCertificateCheck</c>, which is Posh-ACME's own.
/// </remarks>
public sealed class PoshACME : IDisposable
{

    #region Properties

    /// <summary>The module's directory, as setup-windows.ps1 unpacks it.</summary>
    public static String ModuleDirectory
        => Path.Combine(Pins.WindowsLib, $"Posh-ACME-{Pins.Get("POSHACME_VERSION")}");

    /// <summary>The module's manifest.</summary>
    public static String Module
        => Path.Combine(ModuleDirectory, "Posh-ACME.psd1");

    /// <summary>Windows PowerShell 5.1.</summary>
    public static String PowerShell
        => Native.Find("powershell.exe") ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");

    /// <summary>"Posh-ACME 4.35.0" - its column of the interop matrix.</summary>
    public static String Name
        => $"Posh-ACME {Pins.Get("POSHACME_VERSION")}";

    /// <summary>Its home of this test: POSHACME_HOME.</summary>
    public String Home { get; }

    #endregion

    #region Constructor(s)

    public PoshACME()
    {
        Home = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-posh-acme-{Guid.NewGuid():N}"[..48])).FullName;
    }

    #endregion


    #region Run(Script, Timeout = null)

    /// <summary>
    /// Run a script of Posh-ACME's cmdlets: the module imported, every error
    /// terminating, and an error said as "ERROR: ..." with the exit code 1 -
    /// a problem document of the server's, which Posh-ACME says by its
    /// "detail" alone, by its type as well ("PROBLEM=...").
    /// </summary>
    public Wsl.Result Run(String     Script,
                          TimeSpan?  Timeout = null)

        => Native.Run(PowerShell,
                      [ "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                        "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; " +
                        $"Import-Module {Quote(Module)}; " +
                        "try { " + Script + " } " +
                        "catch { Write-Output ('ERROR: ' + $_.Exception.Message); " +
                                "if ($_.Exception.Data -and $_.Exception.Data.type) { Write-Output ('PROBLEM=' + $_.Exception.Data.type) }; " +
                                "Write-Output ($_ | Out-String); exit 1 }" ],
                      new Dictionary<String, String?> {
                          ["POSHACME_HOME"] = Home,
                          // A test process started from PowerShell 7 hands down
                          // its module path, and Windows PowerShell then loads
                          // 7's modules of its own names, and fails: it is to
                          // find its own.
                          ["PSModulePath"]  = null
                      },
                      Timeout ?? TimeSpan.FromMinutes(3));

    /// <summary>A text quoted for PowerShell, in single quotes.</summary>
    public static String Quote(String Text)
        => "'" + Text.Replace("'", "''") + "'";

    #endregion

    #region Value(Result, Name)

    /// <summary>
    /// What a script said as "NAME=value" on a line of its own - the way the
    /// tests have it tell the paths and URLs they judge.
    /// </summary>
    public static String? Value(Wsl.Result Result, String Name)
        => Result.StdOut.Split('\n').
                  Select(line => line.Trim()).
                  Where (line => line.StartsWith(Name + "=", StringComparison.Ordinal)).
                  Select(line => line[(Name.Length + 1)..]).
                  LastOrDefault();

    #endregion

    #region Dispose()

    public void Dispose()
    {
        try
        {
            Directory.Delete(Home, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Left in the temporary directory.
        }
    }

    #endregion

}
