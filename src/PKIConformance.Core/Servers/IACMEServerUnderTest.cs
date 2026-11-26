namespace PKIConformance.Core.Servers;

/// <summary>
/// An ACME server (RFC 8555) the suite tests, started for a test fixture.
/// </summary>
/// <remarks>
/// <para>
/// Every server test talks to this and not to a product directly, because the
/// server is moving: today it is the PKI's (<see cref="PKIACMEServer"/>), and
/// after it moved into Hermod it is Hermod's with a CA of the test as well -
/// the PKI then being one issuer among others (PLAN.md, section 0.2). The
/// same tests then run against both.
/// </para>
/// <para>
/// Nothing in here is how the tests judge the server: they speak to it over
/// HTTPS, with codecs and peers of their own.
/// </para>
/// </remarks>
public interface IACMEServerUnderTest : IAsyncDisposable
{

    /// <summary>
    /// What is tested, and at which commit - for messages and the interop matrix.
    /// </summary>
    String    Name                 { get; }

    /// <summary>
    /// The directory, as this process reaches it.
    /// </summary>
    Uri       DirectoryURL         { get; }

    /// <summary>
    /// The directory, as a peer inside WSL reaches it - or, natively, the same
    /// as <see cref="DirectoryURL"/>. Null where the server was not started to
    /// be reached from there.
    /// </summary>
    Uri?      DirectoryURLFromWsl  { get; }

    /// <summary>
    /// The TLS the server is reached through - made by the bench, not by the
    /// server - and an HTTP client of .NET that trusts it.
    /// </summary>
    BenchTLS  TLS                  { get; }

    /// <summary>
    /// The root every certificate the server issues chains to, in PEM - what a
    /// test hands to openssl verify.
    /// </summary>
    String    IssuingRootPEM       { get; }

    /// <summary>
    /// A key of an external account binding (RFC 8555, section 7.3.4) as the
    /// CA hands it out of band: its key identifier and its MAC key - made the
    /// way the server's operator makes one, not over ACME.
    /// </summary>
    Task<(String KeyId, Byte[] MACKey)> NewExternalAccountKeyAsync();

    /// <summary>
    /// The accounts as the server keeps them - what an interop test compares
    /// a peer's view with: the operator's side of the same account.
    /// </summary>
    IReadOnlyList<ServerAccount> Accounts();

    /// <summary>
    /// The certificates the server issued over ACME, and whether it holds
    /// them revoked.
    /// </summary>
    IReadOnlyList<ServerIssued> Issued();

    /// <summary>
    /// The newest CRL of the CA that issues, DER - or null where there is none.
    /// </summary>
    Byte[]? CRL();

}

/// <summary>
/// An account as the server under test keeps it.
/// </summary>
/// <param name="Id">The server's identifier of it.</param>
/// <param name="Status">"valid", "deactivated" or "revoked".</param>
/// <param name="Contacts">Its contact URLs.</param>
/// <param name="KeyType">The "kty" of its key: "EC" or "RSA".</param>
/// <param name="KeyDetail">The curve of an EC key, the modulus size in bits of an RSA key.</param>
/// <param name="ExternalAccount">The key identifier of its external account binding, if any.</param>
public sealed record ServerAccount(String                 Id,
                                   String                 Status,
                                   IReadOnlyList<String>  Contacts,
                                   String                 KeyType,
                                   String?                KeyDetail,
                                   String?                ExternalAccount);

/// <summary>
/// A certificate the server under test issued over ACME.
/// </summary>
/// <param name="DER">The certificate.</param>
/// <param name="AccountId">The account it was issued to.</param>
/// <param name="Replaces">The ARI identifier of the certificate it replaces (RFC 9773), if any.</param>
/// <param name="Revoked">Whether the server holds it revoked.</param>
/// <param name="Reason">The reason code of its revocation (RFC 5280, section 5.3.1), if revoked.</param>
public sealed record ServerIssued(Byte[]   DER,
                                  String   AccountId,
                                  String?  Replaces,
                                  Boolean  Revoked,
                                  Int32?   Reason);
