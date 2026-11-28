using System.Text.Json;
using System.Text.Json.Nodes;

namespace PKIConformance.Core.Peers;

/// <summary>
/// Python's acme - the library certbot is built on, at certbot's pin, from
/// certbot's venv - driven by a script of the suite's (PythonACME.py) for
/// what no client of the command line does: an account's key changed, an
/// authorization deactivated, a CSR of other names than the order's, and a
/// certificate revoked by another account that proved its names.
/// </summary>
/// <remarks>
/// Everything ACME of it is acme's - its JWS, its JSON, its nonces, its web
/// server of http-01 - so neither Hermod nor RawACME is on its side of the
/// wire. The script reports what the server answered step by step, and the
/// test judges it (<see cref="PythonACMEReport"/>).
/// </remarks>
public sealed class PythonACME : Peer
{

    #region Data

    private readonly String driver;

    #endregion

    #region Properties

    /// <summary>The python3 of certbot's venv, which has acme at certbot's pin.</summary>
    public static String Python
        => $"{Pins.Lib}/certbot-{Pins.Get("CERTBOT_VERSION")}/bin/python3";

    /// <summary>"acme 5.10.0 (Python)" - or why it does not start.</summary>
    public static String Version
        => version.Value;

    private static readonly Lazy<String> version = new (() => {
        var said = Wsl.Run($"{Quote(Python)} -I -c 'import importlib.metadata as m; print(m.version(\"acme\"))' 2>&1", TimeSpan.FromSeconds(30));
        var text = said.StdOut.Trim();
        return said.Success && text.Length > 0 && Char.IsDigit(text[0])
                   ? $"acme {text} (Python)"
                   : $"Python's acme does not start: {said}";
    });

    #endregion

    #region Constructor(s)

    /// <summary>
    /// A driver of Python's acme that trusts the given root - a PEM file of
    /// this process.
    /// </summary>
    public PythonACME(String TrustedRootFile)

        : base("python-acme", TrustedRootFile)

    {

        using var stream = typeof(PythonACME).Assembly.GetManifestResourceStream("PKIConformance.Core.Peers.PythonACME.py")
                               ?? throw new InvalidOperationException("PythonACME.py is not a resource of PKIConformance.Core.");
        using var reader = new StreamReader(stream);

        driver = Write("PythonACME.py", reader.ReadToEnd());

    }

    #endregion


    #region Run(Scenario, Arguments, Timeout = null)

    /// <summary>
    /// Run a scenario of the driver against the directory: the arguments as
    /// the script takes them ("names", "port", "email", ...), and the report
    /// it wrote of what the server answered.
    /// </summary>
    /// <param name="Scenario">"issue", "key-change", "deactivate-authz", "csr-of-other-names" or "revoke-by-proof".</param>
    /// <param name="Directory">The directory URL, as the driver reaches it.</param>
    /// <param name="Arguments">The scenario's own arguments.</param>
    /// <param name="Timeout">How long it may take; three minutes by default.</param>
    public PythonACMEReport Run(String                        Scenario,
                                String                        Directory,
                                IDictionary<String, Object?>  Arguments,
                                TimeSpan?                     Timeout = null)
    {

        var arguments = new Dictionary<String, Object?>(Arguments) {
                            ["scenario"]   = Scenario,
                            ["directory"]  = Directory,
                            ["report"]     = WslPathOf("report.json"),
                            ["log"]        = WslPathOf("acme.log")
                        };

        var file   = Write("arguments.json", JsonSerializer.Serialize(arguments));

        File.Delete(PathOf("report.json"));

        var result = Shell($"REQUESTS_CA_BUNDLE={Quote(TrustedRoot)} {Quote(Python)} -I {Quote(driver)} {Quote(file)}",
                           Timeout ?? TimeSpan.FromMinutes(3));

        var report = Read("report.json");

        return new PythonACMEReport(Scenario,
                                    result,
                                    report is not null ? JsonNode.Parse(report)?.AsObject() : null,
                                    Read("acme.log") ?? "");

    }

    #endregion

}


/// <summary>
/// What a scenario of <see cref="PythonACME"/> reported: every step with what
/// the server answered, and the values the test judges.
/// </summary>
/// <param name="Scenario">The scenario.</param>
/// <param name="Result">How the script ran.</param>
/// <param name="Report">Its report, or null where it wrote none.</param>
/// <param name="Log">acme's log of the run: every request and answer.</param>
public sealed record PythonACMEReport(String       Scenario,
                                      Wsl.Result   Result,
                                      JsonObject?  Report,
                                      String       Log)
{

    /// <summary>The step of the name, or null where the scenario did not get to it.</summary>
    public JsonObject? Step(String Name)
        => Report?["steps"]?.AsArray().OfType<JsonObject>().FirstOrDefault(step => step["step"]?.GetValue<String>() == Name);

    /// <summary>Whether the step of the name succeeded.</summary>
    public Boolean? Ok(String Name)
        => Step(Name)?["ok"]?.GetValue<Boolean>();

    /// <summary>The type of the problem the server answered the step with, or null.</summary>
    public String? Problem(String Name)
        => Step(Name)?["problem"]?.GetValue<String>();

    /// <summary>A value of the report, as text - or null.</summary>
    public String? Value(String Name)
        => Report?["values"]?[Name] switch {
               null                                                  => null,
               JsonValue value when value.TryGetValue<String>(out var text) => text,
               var node                                              => node.ToJsonString()
           };

    /// <summary>A list of the report, as texts.</summary>
    public IReadOnlyList<String?> Values(String Name)
        => Report?["values"]?[Name] is JsonArray array
               ? [ .. array.Select(node => node?.GetValue<String>()) ]
               : [];

    /// <summary>The evidence of a red test: the report, the script's output, the end of acme's log.</summary>
    public override String ToString()
        => $"{Scenario}: {Report?.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) ?? "no report"}\n" +
           $"--- the script ---\n{Result}\n" +
           $"--- acme's log ---\n{Log[^Math.Min(Log.Length, 6000)..]}";

}
