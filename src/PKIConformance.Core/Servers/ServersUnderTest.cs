namespace PKIConformance.Core.Servers;

/// <summary>
/// Every ACME server the server suites run against, by name - what a
/// <c>[TestFixtureSource]</c> hands each fixture.
/// </summary>
/// <remarks>
/// Today the PKI's alone. Once the server has moved into Hermod (PLAN.md,
/// section 0.2), Hermod's with a CA of the test joins it here, and every
/// server test runs against both without being touched.
/// </remarks>
public static class ServersUnderTest
{

    /// <summary>
    /// The PKI's ACME server.
    /// </summary>
    public const String PKI = "PKI";

    /// <summary>
    /// The names of every server under test.
    /// </summary>
    public static readonly IReadOnlyList<String> All = [ PKI ];

    /// <summary>
    /// Start the server of the given name.
    /// </summary>
    public static async Task<IACMEServerUnderTest> StartAsync(String              Name,
                                                              ACMEServerOptions?  Options = null)

        => Name switch {
               PKI  => await PKIACMEServer.StartAsync(Options),
               _    => throw new ArgumentException($"There is no ACME server under test called '{Name}'.", nameof(Name))
           };

}
