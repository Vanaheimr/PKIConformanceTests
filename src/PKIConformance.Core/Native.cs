using System.Diagnostics;

namespace PKIConformance.Core;

/// <summary>
/// A program of the host run as it is - no shell, no WSL - its arguments one
/// by one, as the peers of the Windows leg and its openssl are run.
/// </summary>
public static class Native
{

    #region Run(FileName, Arguments, Environment = null, Timeout = null, WorkingDirectory = null)

    /// <summary>
    /// Run the program to its end - or kill it at the timeout - with its
    /// standard input closed, so that a prompt it shows reads its end at once
    /// instead of waiting for an answer nobody gives.
    /// </summary>
    /// <param name="FileName">The program.</param>
    /// <param name="Arguments">Its arguments, each as it is to arrive.</param>
    /// <param name="Environment">Variables of its environment to set, or with null to take away.</param>
    /// <param name="Timeout">How long it may take; two minutes by default.</param>
    /// <param name="WorkingDirectory">Where it runs.</param>
    public static Wsl.Result Run(String                                  FileName,
                                 IEnumerable<String>                     Arguments,
                                 IReadOnlyDictionary<String, String?>?   Environment       = null,
                                 TimeSpan?                               Timeout           = null,
                                 String?                                 WorkingDirectory  = null)
    {

        var start = new ProcessStartInfo(FileName) {
                        RedirectStandardInput   = true,
                        RedirectStandardOutput  = true,
                        RedirectStandardError   = true,
                        UseShellExecute         = false,
                        CreateNoWindow          = true,
                        WorkingDirectory        = WorkingDirectory ?? ""
                    };

        foreach (var argument in Arguments)
            start.ArgumentList.Add(argument);

        if (Environment is not null)
            foreach (var (name, value) in Environment)
            {
                if (value is null)
                    start.Environment.Remove(name);
                else
                    start.Environment[name] = value;
            }

        using var process = Process.Start(start)
                                ?? throw new InvalidOperationException($"{FileName} did not start.");

        process.StandardInput.Close();

        var stdOut = process.StandardOutput.ReadToEndAsync();
        var stdErr = process.StandardError. ReadToEndAsync();

        if (!process.WaitForExit((Int32) (Timeout ?? TimeSpan.FromMinutes(2)).TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            process.WaitForExit();
            return new Wsl.Result(-1, stdOut.Result, $"{FileName} timed out after {Timeout ?? TimeSpan.FromMinutes(2)}.\n{stdErr.Result}");
        }

        process.WaitForExit();

        return new Wsl.Result(process.ExitCode, stdOut.Result, stdErr.Result);

    }

    #endregion

    #region Find(Program)

    /// <summary>
    /// The full path of a program on the PATH - "openssl.exe" - or null.
    /// </summary>
    public static String? Find(String Program)
    {

        foreach (var directory in (System.Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var path = Path.Combine(directory.Trim('"'), Program);
            if (File.Exists(path))
                return path;
        }

        return null;

    }

    #endregion

}
