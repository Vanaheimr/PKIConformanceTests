namespace PKIConformance.Core.Peers;

/// <summary>
/// An ACME server of the world - Pebble, step-ca, Boulder - started for a
/// test of Hermod's client: where its directory is, what its TLS is trusted
/// by, the name server it resolves and reads dns-01 through, and the root
/// what it issues chains to.
/// </summary>
public interface IACMEServerPeer : IDisposable
{

    /// <summary>Its name and version, as the evidence of a test names it: "Pebble 2.10.3".</summary>
    String        Name             { get; }

    /// <summary>The URL of its directory.</summary>
    Uri           DirectoryURL     { get; }

    /// <summary>The PEM file of the root its TLS is trusted by.</summary>
    String        TrustedRootFile  { get; }

    /// <summary>Its name server, where the delegates of dns-01 write.</summary>
    IChallengeDNS DNS              { get; }

    /// <summary>What it wrote, as the evidence of a red test.</summary>
    String        Log              { get; }

    /// <summary>The root of what it issues, in PEM - the one of its default chain.</summary>
    Task<String>  IssuingRootPEMAsync(CancellationToken CancellationToken = default);

}
