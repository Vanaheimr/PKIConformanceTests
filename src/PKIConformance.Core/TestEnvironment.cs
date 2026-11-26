using System.Diagnostics;

using NUnit.Framework;

namespace PKIConformance.Core;

/// <summary>
/// One-time capability probing (WSL, the peers, the way from WSL to a server
/// of this process, Docker) with Assert.Ignore-based gating, so that an
/// environment without a prerequisite skips instead of failing - and says
/// what would provide it.
/// </summary>
public static class TestEnvironment
{

    /// <summary>
    /// What build/peers/setup-wsl.sh installs, for the hints below.
    /// </summary>
    public const String SetupHint = "wsl -u root sh build/peers/setup-wsl.sh";

    #region WSL

    /// <summary>
    /// Require a POSIX shell with the given peers on its PATH.
    /// </summary>
    /// <param name="tools">The executables the calling test needs on the PATH.</param>
    /// <remarks>
    /// The category is still called <c>WSL</c> because that is where the peers
    /// live on a developer machine. On a Linux host - a CI runner, say - the
    /// same tests run against the peers directly, with no bridge and no
    /// firewall between them and the server under test.
    /// </remarks>
    public static void RequireWsl(params String[] tools)
    {

        if (!Wsl.IsAvailable)
            Assert.Ignore(Wsl.UsesWslBridge
                              ? $"WSL is not available - skipping. Install WSL, then: {SetupHint}"
                              :  "No POSIX shell available - skipping.");

        foreach (var tool in tools)
            if (!Wsl.HasTool(tool))
                Assert.Ignore(Wsl.UsesWslBridge
                                  ? $"'{tool}' not found inside WSL - skipping. Install the peers: {SetupHint}"
                                  : $"'{tool}' not found on the PATH - skipping. Install the peers: sh build/peers/setup-wsl.sh");

    }

    /// <summary>
    /// Require that a peer inside WSL reaches the given URL of a server of this
    /// process. Under WSL's NAT that is the Windows host's address, and the
    /// Windows firewall decides; natively it is the one loopback.
    /// </summary>
    /// <param name="URL">What a peer is to reach.</param>
    /// <param name="TrustedRootFile">The PEM file of the root its TLS is trusted by, as this process names it.</param>
    public static void RequireReachableFromWsl(Uri     URL,
                                               String  TrustedRootFile)
    {

        RequireWsl("curl");

        var result = Wsl.Run($"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 --cacert '{Wsl.ToWslPath(TrustedRootFile)}' '{URL}'", TimeSpan.FromSeconds(15));

        // 60: the connection was there, and the TLS was not the bench's - a
        // broken bench, not a closed way, and not to be skipped over.
        if (result.ExitCode == 60)
            Assert.Fail($"{URL} answers WSL with a TLS certificate the bench's root ({TrustedRootFile}) does not vouch for. {result}");

        if (!result.Success || result.StdOut.Trim() is "" or "000")
            Assert.Ignore($"{URL} cannot be reached from WSL - skipping. Under WSL's NAT the Windows firewall has to let " +
                          $"WSL in (or set networkingMode=mirrored in .wslconfig), or run the suite inside WSL: build/test-in-wsl.sh. {result}");

    }

    #endregion

    #region Docker

    private static readonly Lazy<Boolean> hasDocker = new(() => {
        try
        {

            // On Windows the daemon lives in WSL, as everything else of the peers does.
            if (Wsl.UsesWslBridge)
                return Wsl.IsAvailable && Wsl.Run("docker info --format '{{.ServerVersion}}'", TimeSpan.FromSeconds(15), asRoot: true).Success;

            using var process = Process.Start(new ProcessStartInfo {
                                                  FileName                = "docker",
                                                  Arguments               = "info --format {{.ServerVersion}}",
                                                  RedirectStandardOutput  = true,
                                                  RedirectStandardError   = true,
                                                  UseShellExecute         = false,
                                                  CreateNoWindow          = true
                                              });

            if (process is null)
                return false;

            if (!process.WaitForExit(5000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return false;
            }

            return process.ExitCode == 0;

        }
        catch
        {
            return false;
        }
    });

    public static Boolean HasDockerDaemon
        => hasDocker.Value;

    public static void RequireDocker()
    {
        if (!HasDockerDaemon)
            Assert.Ignore("No reachable Docker daemon - skipping Docker-based interop test.");
    }

    #endregion

}
