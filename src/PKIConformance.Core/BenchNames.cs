namespace PKIConformance.Core;

/// <summary>
/// The DNS names of the bench - "acme.test", "www.acme.test" and
/// "n01.acme.test" to "n16.acme.test" - which the run of
/// build/bench-namespace.sh lets resolve to 127.0.0.1, in an /etc/hosts of
/// its namespace alone.
/// </summary>
/// <remarks>
/// They are needed where a real ACME client proves a name by http-01 against
/// the PKI, which resolves it through the operating system until T-S5. Every
/// other name - dns-01, a refused name - needs no resolution.
/// </remarks>
public static class BenchNames
{

    /// <summary>The zone.</summary>
    public const String Zone = "acme.test";

    /// <summary>"www.acme.test".</summary>
    public const String WWW  = "www.acme.test";

    /// <summary>"n01.acme.test" to "n16.acme.test".</summary>
    public static IReadOnlyList<String> Numbered
        => [ .. Enumerable.Range(1, 16).Select(n => $"n{n:00}.{Zone}") ];

    /// <summary>Every name of the bench.</summary>
    public static IReadOnlyList<String> All
        => [ Zone, WWW, .. Numbered ];

    /// <summary>
    /// Whether the names resolve to the loopback - in this process, by the
    /// system, as the PKI resolves them.
    /// </summary>
    public static Boolean Resolve
        => resolve.Value;

    private static readonly Lazy<Boolean> resolve = new (() => {
        try
        {
            return All.All(name => System.Net.Dns.GetHostAddresses(name).Any(IPAddress.IsLoopback));
        }
        catch (System.Net.Sockets.SocketException)
        {
            return false;
        }
    });

}
