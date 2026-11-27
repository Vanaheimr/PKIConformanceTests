using System.Xml.Linq;

using PKIConformance.Core;

namespace PKIConformance.InteropReport;

/// <summary>
/// How an interop test came out.
/// </summary>
public enum Outcome
{
    /// <summary>The peer and this family's side agreed.</summary>
    Passed,
    /// <summary>The test ran and failed.</summary>
    Failed,
    /// <summary>The test did not run: a peer or a tool was missing.</summary>
    NotRun
}


/// <summary>
/// One interop test's result, as its line of <see cref="InteropCells.Line"/>
/// says what it is a cell of.
/// </summary>
/// <param name="Matrix">The matrix: <see cref="InteropCells.Clients"/>, <see cref="InteropCells.Servers"/>, <see cref="InteropCells.Reference"/> or <see cref="InteropCells.Bench"/> - or null where the test wrote no line.</param>
/// <param name="Peer">The peer of other hands and its version.</param>
/// <param name="Against">This family's side and its commit.</param>
/// <param name="Cell">The cell.</param>
/// <param name="Finding">The finding that keeps it red, if any.</param>
/// <param name="ToDo">The ToDo that keeps it red, if any.</param>
/// <param name="Test">The test: its class and its name with its arguments.</param>
/// <param name="Outcome">How it came out.</param>
/// <param name="Message">Its message, on one line - for a red one, why.</param>
public sealed record Result(String?  Matrix,
                            String   Peer,
                            String   Against,
                            String   Cell,
                            String?  Finding,
                            String?  ToDo,
                            String   Test,
                            Outcome  Outcome,
                            String?  Message)
{

    /// <summary>What keeps a red test red - its finding or its ToDo - or null.</summary>
    public String? Reason
        => Finding ?? ToDo;

}


/// <summary>
/// The interop results of TRX files.
/// </summary>
/// <remarks>
/// A TRX file keeps a test's class, its name, its outcome and its output -
/// not NUnit's categories or properties. So a result is an interop result
/// when the test wrote its line (<see cref="InteropCells.Line"/>), or when
/// it is of an interop class (PKIInterop.*) and did not run: a fixture that
/// skips in its OneTimeSetUp never reaches the SetUp that writes the line,
/// and its tests must not vanish from the count. A file without a single
/// line is no interop run of this suite's (or one from before the lines),
/// and is passed over.
/// </remarks>
public static class TrxReader
{

    private static readonly XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";

    /// <summary>
    /// The interop results of every TRX file of the paths - files, or
    /// directories searched recursively - and when the earliest run began.
    /// </summary>
    public static (IReadOnlyList<Result> Results, DateTimeOffset? Started) Read(IEnumerable<String> Paths)
    {

        var results  = new List<Result>();

        // In the order the runs began: a test of two of them counts as it came out last.
        var runs     = Expand(Paths).
                           Select (file => XDocument.Load(file)).
                           Where  (document => document.Descendants(ns + "StdOut").Any(stdout => stdout.Value.Contains(InteropCells.Prefix, StringComparison.Ordinal))).
                           Select (document => (Document: document, Start: StartOf(document))).
                           OrderBy(run => run.Start ?? DateTimeOffset.MinValue).
                           ToArray();

        var started  = runs.Select(run => run.Start).FirstOrDefault(start => start is not null);

        foreach (var (document, _) in runs)
        {

            var classOf = document.Descendants(ns + "UnitTest").
                                   ToDictionary(test => (String?) test.Attribute("id") ?? "",
                                                test => (String?) test.Element(ns + "TestMethod")?.Attribute("className") ?? "");

            foreach (var result in document.Descendants(ns + "UnitTestResult"))
            {

                var className  = classOf.GetValueOrDefault((String?) result.Attribute("testId") ?? "", "");
                var name       = (String?) result.Attribute("testName") ?? "?";
                var outcome    = ((String?) result.Attribute("outcome")) switch {
                                     "Passed"                         => Outcome.Passed,
                                     "Failed" or "Error" or "Timeout" => Outcome.Failed,
                                     _                                => Outcome.NotRun
                                 };
                var output     = String.Concat(result.Descendants(ns + "StdOut").Select(stdout => stdout.Value));
                var message    = OneLine(result.Descendants(ns + "Message").FirstOrDefault()?.Value);
                var test       = $"{className[(className.LastIndexOf('.') + 1)..]}.{name}";
                var line       = InteropCells.TryParse(output);

                if (line is not null)
                    results.Add(new Result(line.GetValueOrDefault("matrix"),
                                           line.GetValueOrDefault("peer",    "?"),
                                           line.GetValueOrDefault("against", "?"),
                                           line.GetValueOrDefault("cell",    name),
                                           line.GetValueOrDefault("finding"),
                                           line.GetValueOrDefault("todo"),
                                           test,
                                           outcome,
                                           message));

                else if (className.StartsWith("PKIInterop.", StringComparison.Ordinal))
                    results.Add(new Result(null, className[(className.LastIndexOf('.') + 1)..], "?", name, null, null, test, outcome, message));

            }

        }

        // A test of two runs - a run again of one project, say - counts once, as it came out last.
        var unique = results.GroupBy (result => (result.Matrix, result.Peer, result.Test)).
                             Select  (group  => group.Last()).
                             ToList();

        return (unique, started);

    }

    private static DateTimeOffset? StartOf(XDocument Document)
        => DateTimeOffset.TryParse((String?) Document.Root?.Element(ns + "Times")?.Attribute("start"), out var start) ? start : null;

    private static String? OneLine(String? Message)
    {
        if (String.IsNullOrWhiteSpace(Message))
            return null;
        var line = String.Join(" ", Message.Split([ '\r', '\n' ], StringSplitOptions.RemoveEmptyEntries).Select(part => part.Trim()));
        return line.Length <= 200 ? line : line[..197] + "...";
    }

    private static IEnumerable<String> Expand(IEnumerable<String> Paths)
    {
        foreach (var path in Paths)
        {
            if (Directory.Exists(path))
                foreach (var file in Directory.EnumerateFiles(path, "*.trx", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
                    yield return file;
            else if (File.Exists(path))
                yield return path;
            else
                throw new FileNotFoundException($"No TRX file or directory: {path}");
        }
    }

}
