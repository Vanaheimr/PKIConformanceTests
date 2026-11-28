namespace PKIConformance.Core;

/// <summary>
/// NUnit category names used to gate tests on external prerequisites.
/// Default CI filter: TestCategory!=Online&amp;TestCategory!=WSL&amp;TestCategory!=Windows&amp;TestCategory!=Docker&amp;TestCategory!=KnownIssue&amp;TestCategory!=ToDo.
/// </summary>
public static class TestCategories
{

    /// <summary>
    /// Needs outbound internet (Let's Encrypt staging).
    /// </summary>
    public const String Online      = "Online";

    /// <summary>
    /// Needs WSL - or, on a Linux host, the shell itself - with the peers
    /// installed: certbot, lego, acme.sh, Pebble, BIND (build/peers/setup-wsl.sh).
    /// </summary>
    public const String Wsl         = "WSL";

    /// <summary>
    /// Needs Windows with the peers of the Windows leg installed: Posh-ACME
    /// and win-acme (build/peers/setup-windows.ps1) - run natively, no WSL.
    /// </summary>
    public const String Windows     = "Windows";

    /// <summary>
    /// Needs a reachable Docker daemon (Boulder).
    /// </summary>
    public const String Docker      = "Docker";

    /// <summary>
    /// Longer-running tests (&gt; ~5 s).
    /// </summary>
    public const String Slow        = "Slow";

    /// <summary>
    /// Encodes an RFC requirement an implemented feature is currently known to
    /// violate - see FINDINGS.md.
    /// </summary>
    public const String KnownIssue  = "KnownIssue";

    /// <summary>
    /// Encodes a feature that is not implemented yet - see the ToDos in
    /// PLAN.md, section 2.4. Green the day it is.
    /// </summary>
    public const String ToDo        = "ToDo";

}
