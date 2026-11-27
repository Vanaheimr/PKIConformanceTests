namespace PKIConformance.Core;

/// <summary>
/// The versions the peers from upstream are pinned to, as build/peers/pins.env
/// has them - the file setup-wsl.sh installs them by, read here so that a
/// test finds what was installed, and says which version it ran against.
/// </summary>
public static class Pins
{

    private static readonly Lazy<IReadOnlyDictionary<String, String>> pins = new (Load);

    /// <summary>
    /// The value of a pin - "PEBBLE_VERSION", say.
    /// </summary>
    public static String Get(String Name)

        => pins.Value.TryGetValue(Name, out var value)
               ? value
               : throw new KeyNotFoundException($"build/peers/pins.env has no {Name}.");

    /// <summary>
    /// Where the peers from upstream go that are no single binary on the
    /// PATH (setup-wsl.sh's LIB).
    /// </summary>
    public const String Lib = "/usr/local/lib/pkiconformance";

    private static IReadOnlyDictionary<String, String> Load()
    {

        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {

            var file = Path.Combine(directory.FullName, "build", "peers", "pins.env");

            if (File.Exists(file))
                return File.ReadAllLines(file).
                            Select (line => line.Trim()).
                            Where  (line => line.Length > 0 && !line.StartsWith('#') && line.Contains('=')).
                            Select (line => line.Split('=', 2)).
                            ToDictionary(pair => pair[0].Trim(), pair => pair[1].Trim());

        }

        throw new FileNotFoundException($"No build/peers/pins.env above {AppContext.BaseDirectory}.");

    }

}
