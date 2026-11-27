namespace PKIConformance.InteropReport;

/// <summary>
/// Renders the TRX files of an interop run into <c>docs/INTEROP-MATRIX.md</c>.
/// </summary>
/// <remarks>
/// <code>
/// dotnet run --project InteropReport -- &lt;trx file or directory&gt;... [-o &lt;output.md&gt;]
/// </code>
/// The exit code is 1 where a red test has neither a finding nor a ToDo -
/// where the matrix says something nobody has explained yet - else 0.
/// </remarks>
public static class Program
{

    /// <summary>The entry point.</summary>
    public static Int32 Main(String[] Arguments)
    {

        var inputs = new List<String>();
        var output = Path.Combine("docs", "INTEROP-MATRIX.md");

        for (var i = 0; i < Arguments.Length; i++)
        {
            if (Arguments[i] is "-o" or "--output")
            {
                if (++i >= Arguments.Length)
                {
                    Console.Error.WriteLine("error: -o needs a file.");
                    return 64;
                }
                output = Arguments[i];
            }
            else
                inputs.Add(Arguments[i]);
        }

        if (inputs.Count == 0)
        {
            Console.Error.WriteLine("""
                Usage: dotnet run --project InteropReport -- <trx file or directory>... [-o <output.md>]

                Renders the interop results of the TRX files into the matrices of
                docs/INTEROP-MATRIX.md (the default output). Make the TRX files with
                  wsl sh build/test-in-wsl.sh -c Release --filter "TestCategory=WSL"
                which leaves them in artifacts/.
                """);
            return 64;
        }

        var (results, started) = TrxReader.Read(inputs);

        var directory = Path.GetDirectoryName(Path.GetFullPath(output));
        if (!String.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        File.WriteAllText(output, MatrixRenderer.Render(results, started));

        var unexplained = MatrixRenderer.Unexplained(results);

        Console.WriteLine($"{output}: {results.Count} interop tests, " +
                          $"{results.Count(result => result.Outcome == Outcome.Passed)} passed, " +
                          $"{results.Count(result => result.Outcome == Outcome.Failed)} failed ({unexplained.Count} unexplained), " +
                          $"{results.Count(result => result.Outcome == Outcome.NotRun)} not run.");

        foreach (var result in unexplained)
            Console.WriteLine($"  unexplained: {result.Peer} {result.Test}");

        return unexplained.Count > 0 ? 1 : 0;

    }

}
