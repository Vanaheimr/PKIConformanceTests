using System.Text.Json.Nodes;

namespace PKIConformance.Core;

/// <summary>
/// The recorded references of fixtures/ - what certbot writes into live/,
/// say - found above the test's assembly, in the checkout it was built from.
/// </summary>
public static class Fixtures
{

    /// <summary>
    /// The fixture at the given path below fixtures/, as JSON.
    /// </summary>
    public static JsonObject JSON(String Relative)

        => JsonNode.Parse(File.ReadAllText(PathOf(Relative))) as JsonObject
               ?? throw new FormatException($"fixtures/{Relative} is no JSON object.");

    /// <summary>
    /// The path of a fixture below fixtures/.
    /// </summary>
    public static String PathOf(String Relative)
    {

        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var file = Path.Combine(directory.FullName, "fixtures", Relative.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(file))
                return file;
        }

        throw new FileNotFoundException($"No fixtures/{Relative} above {AppContext.BaseDirectory}.");

    }

}
