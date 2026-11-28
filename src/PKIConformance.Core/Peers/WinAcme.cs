using System.Text.Json.Nodes;

namespace PKIConformance.Core.Peers;

/// <summary>
/// win-acme (https://www.win-acme.com), the ACME client of IIS's world, as a
/// peer of the Windows leg: its release at its pin (setup-windows.ps1), run
/// unattended (<c>--source</c>) from a copy of its own, with a settings.json
/// of the test's and its configuration, logs and cache in the peer's
/// directory - so that nothing of a win-acme of the user's is read or
/// written, no scheduled task is made, and nobody but the server under test
/// is asked anything.
/// </summary>
/// <remarks>
/// <para>
/// win-acme reads its settings from beside wacs.exe alone; hence the copy.
/// It trusts the server's TLS by Windows' store, which the suite does not
/// touch: <c>"Acme": { "ValidateServerCertificate": false }</c>, its own
/// setting, lets the server's certificate through.
/// </para>
/// <para>
/// 2.4.1 is built of simple-acme's code (https://simple-acme.com), whose
/// reference its arguments are of.
/// </para>
/// </remarks>
public sealed class WinAcme : IDisposable
{

    #region Properties

    /// <summary>Where setup-windows.ps1 unpacked it.</summary>
    public static String InstallDirectory
        => Path.Combine(Pins.WindowsLib, $"win-acme-{Pins.Get("WINACME_VERSION")}");

    /// <summary>wacs.exe as installed.</summary>
    public static String Installed
        => Path.Combine(InstallDirectory, "wacs.exe");

    /// <summary>"win-acme 2.4.1" - its column of the interop matrix.</summary>
    public static String Name
        => $"win-acme {Pins.Get("WINACME_TAG").TrimStart('v')}";

    /// <summary>The peer's directory: its copy of win-acme, its configuration, its files.</summary>
    public String Directory      { get; }

    /// <summary>Where it keeps its accounts, renewals, logs and cache.</summary>
    public String Configuration  => Path.Combine(Directory, "config");

    /// <summary>Where the PEM files of its certificates go (<c>--store pemfiles</c>).</summary>
    public String PemFiles       => Path.Combine(Directory, "pem");

    /// <summary>The directory URL it asks.</summary>
    public String BaseUri        { get; }

    private String Executable    => Path.Combine(Directory, "program", "wacs.exe");

    #endregion

    #region Constructor(s)

    /// <summary>
    /// A win-acme of its own for the server of the directory URL.
    /// </summary>
    /// <param name="BaseUri">The directory URL.</param>
    /// <param name="Settings">How the test changes the settings, beyond the bench's.</param>
    public WinAcme(String               BaseUri,
                   Action<JsonObject>?  Settings = null)
    {

        this.BaseUri    = BaseUri;
        this.Directory  = System.IO.Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), $"pkiconformance-win-acme-{Guid.NewGuid():N}"[..48])).FullName;

        var program     = System.IO.Directory.CreateDirectory(Path.Combine(Directory, "program")).FullName;

        foreach (var file in System.IO.Directory.EnumerateFiles(InstallDirectory, "*", SearchOption.AllDirectories))
        {
            var target = Path.Combine(program, Path.GetRelativePath(InstallDirectory, file));
            System.IO.Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target);
        }

        System.IO.Directory.CreateDirectory(Configuration);
        System.IO.Directory.CreateDirectory(PemFiles);

        var settings    = JsonNode.Parse(File.ReadAllText(Path.Combine(program, "settings_default.json")))!.AsObject();

        settings["Client"]!["ClientName"]                 = "pkiconformance";
        settings["Client"]!["ConfigurationPath"]          = Configuration;
        settings["Client"]!["LogPath"]                    = Path.Combine(Configuration, "Log");
        settings["Client"]!["VersionCheck"]               = false;
        settings["Acme"]!  ["DefaultBaseUri"]             = BaseUri;
        settings["Acme"]!  ["ValidateServerCertificate"]  = false;
        settings["Acme"]!  ["PublicSuffixListUri"]        = "";
        settings["Cache"]! ["Path"]                       = Path.Combine(Configuration, "Certificates");
        settings["Security"]!["EncryptConfig"]            = false;

        Settings?.Invoke(settings);

        File.WriteAllText(Path.Combine(program, "settings.json"), settings.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));

    }

    #endregion


    #region Run(Arguments)

    /// <summary>
    /// Run wacs.exe with the arguments, against the server, without a
    /// scheduled task, verbosely - its log of the run after its output.
    /// </summary>
    public Wsl.Result Run(params String[] Arguments)
    {

        var result = Native.Run(Executable,
                                [ .. Arguments, "--baseuri", BaseUri, "--notaskscheduler", "--verbose" ],
                                Timeout: TimeSpan.FromMinutes(3),
                                WorkingDirectory: Directory);

        return result;

    }

    /// <summary>What win-acme logged, all of it - the evidence of a failure.</summary>
    public String Log
        => System.IO.Directory.Exists(Configuration)
               ? String.Join("\n", System.IO.Directory.EnumerateFiles(Configuration, "log-*.txt", SearchOption.AllDirectories).Order().Select(File.ReadAllText))
               : "";

    /// <summary>A PEM file of the certificate of the name - "chain" (the leaf and its issuers), "key", "crt" - or null.</summary>
    public String? Pem(String Name, String Kind)
        => Path.Combine(PemFiles, $"{Name}-{Kind}.pem") is var path && File.Exists(path) ? File.ReadAllText(path) : null;

    #endregion

    #region Dispose()

    public void Dispose()
    {
        try
        {
            System.IO.Directory.Delete(Directory, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Left in the temporary directory.
        }
    }

    #endregion

}
