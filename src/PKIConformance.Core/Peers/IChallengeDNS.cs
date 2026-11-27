namespace PKIConformance.Core.Peers;

/// <summary>
/// The name server an ACME server of the world resolves and reads dns-01
/// through - a challtestsrv of the bench's, or the one inside Boulder's
/// stack - as the delegates of Hermod's DNS01ChallengeResponder write it.
/// </summary>
public interface IChallengeDNS
{

    /// <summary>Add a TXT record - a value beside the ones the name has already.</summary>
    Task      SetTXTAsync  (String Name, String Value, CancellationToken CancellationToken = default);

    /// <summary>Take every TXT record of the name away.</summary>
    Task      ClearTXTAsync(String Name, CancellationToken CancellationToken = default);

    /// <summary>What it answers for a name and type now, as dig sees it.</summary>
    String[]  Query        (String Name, String Type);

    /// <summary>What it wrote: every record it added and removed.</summary>
    String    Log          { get; }

}
