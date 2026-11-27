namespace PKIConformance.Core;

/// <summary>
/// The cells of the interop matrices (PLAN.md, sections 4.5 and 4.6) - the
/// rows of <c>docs/INTEROP-MATRIX.md</c>, in their order - and the line by
/// which a test declares its cell in its output, for InteropReport to read
/// out of the TRX files.
/// </summary>
/// <remarks>
/// <para>
/// A TRX file keeps neither NUnit's categories nor its properties, only a
/// test's name, its outcome and its output. So every interop test says in
/// its output what it is a cell of: the matrix, the peer and its version,
/// what it ran against, the cell, and the finding or ToDo that keeps it red
/// (<see cref="Line"/>), written by its fixture's SetUp from its
/// <see cref="CellAttribute"/>.
/// </para>
/// <para>
/// This file is compiled into InteropReport as well, which has neither NUnit
/// nor the submodules: nothing in here may need more than the BCL.
/// </para>
/// </remarks>
public static class InteropCells
{

    #region Matrices

    /// <summary>Interop A: real clients against the PKI (PLAN.md, section 4.5).</summary>
    public const String Clients    = "A";

    /// <summary>Interop B: Hermod against real servers (PLAN.md, section 4.6).</summary>
    public const String Servers    = "B";

    /// <summary>The reference run: certbot's files against the manager's (PLAN.md, section 4.6).</summary>
    public const String Reference  = "R";

    /// <summary>The bench itself, tested before it judges anything.</summary>
    public const String Bench      = "Bench";

    #endregion

    #region Interop A - real clients against the PKI

    /// <summary>Section 7.3: a new account, its terms of service agreed to, a contact given.</summary>
    public const String Account                = "Account: new + ToS + contact";
    /// <summary>Section 7.3.4.</summary>
    public const String AccountEAB             = "Account: external account binding";
    /// <summary>Section 7.3.2.</summary>
    public const String AccountContact         = "Account: a new contact";
    /// <summary>Section 7.3.6.</summary>
    public const String AccountDeactivated     = "Account: deactivated";
    /// <summary>Section 7.3.5.</summary>
    public const String AccountKeyRollover     = "Account: key rollover";
    /// <summary>Section 6.2: the kinds of account key, and one refused.</summary>
    public const String AccountKeys            = "Account: kinds of key";
    /// <summary>Section 8.3, the client's own web server.</summary>
    public const String Http01OwnServer        = "http-01: own web server";
    /// <summary>Section 8.3, files in a webroot the bench serves.</summary>
    public const String Http01Webroot          = "http-01: webroot";
    /// <summary>Section 8.4 by RFC 2136: the record reaches BIND, whatever the server makes of it.</summary>
    public const String Dns01Record            = "dns-01 by RFC 2136: the record written";
    /// <summary>Section 8.4 by RFC 2136: the certificate.</summary>
    public const String Dns01Certificate       = "dns-01 by RFC 2136: the certificate";
    /// <summary>Section 7.1.3: a wildcard, proven by dns-01.</summary>
    public const String Wildcard               = "Wildcard";
    /// <summary>Section 7.4: an order of sixteen names.</summary>
    public const String SixteenNames           = "16 names";
    /// <summary>RFC 8738: an IPv4 address.</summary>
    public const String IPv4                   = "IP identifier v4 (RFC 8738)";
    /// <summary>RFC 8738: an IPv6 address.</summary>
    public const String IPv6                   = "IP identifier v6 (RFC 8738)";
    /// <summary>Section 7.4: a CSR of the client's own.</summary>
    public const String OwnCSR                 = "Own CSR";
    /// <summary>Section 7.4: every kind of certificate key the client makes.</summary>
    public const String CertificateKeys        = "Certificate keys";
    /// <summary>draft-ietf-acme-profiles.</summary>
    public const String Profiles               = "Profiles";
    /// <summary>Section 7.4: a renewal the client is told to make.</summary>
    public const String RenewalForced          = "Renewal: forced";
    /// <summary>RFC 9773, section 4: a renewal of the client's own, because the server's window is due.</summary>
    public const String RenewalByARI           = "Renewal: when the window of ARI is due";
    /// <summary>RFC 9773, section 5.</summary>
    public const String RenewalReplaces        = "Renewal: \"replaces\" (RFC 9773)";
    /// <summary>Section 7.6: by the account, for a reason, listed by the CRL.</summary>
    public const String RevokedByAccount       = "Revocation by the account, in the CRL";
    /// <summary>Section 7.6: by the certificate's own key.</summary>
    public const String RevokedByCertificateKey = "Revocation by the certificate's key";
    /// <summary>RFC 8737 asked for alone, which the PKI does not offer.</summary>
    public const String TlsAlpn01Alone         = "tls-alpn-01 alone: no challenge for it";
    /// <summary>Section 6.7: a name the server does not sign for.</summary>
    public const String RefusedName            = "Refused: rejectedIdentifier";
    /// <summary>Section 7.3.4: no binding where one is required.</summary>
    public const String RefusedNoEAB           = "Refused: externalAccountRequired";
    /// <summary>Section 8.3: a wrong answer at the token's path.</summary>
    public const String RefusedWrongAnswer     = "Refused: a wrong answer";
    /// <summary>RFC 8738, section 3: an address ordered as a DNS name, by a client without RFC 8738.</summary>
    public const String RefusedAddressAsName   = "Refused: an address ordered as a DNS name";

    /// <summary>The rows of interop A, in their order.</summary>
    public static readonly IReadOnlyList<String> ClientRows = [
        Account, AccountEAB, AccountContact, AccountDeactivated, AccountKeyRollover, AccountKeys,
        Http01OwnServer, Http01Webroot, Dns01Record, Dns01Certificate, Wildcard, SixteenNames, IPv4, IPv6,
        OwnCSR, CertificateKeys, Profiles, RenewalForced, RenewalByARI, RenewalReplaces,
        RevokedByAccount, RevokedByCertificateKey, TlsAlpn01Alone, RefusedName, RefusedNoEAB, RefusedWrongAnswer, RefusedAddressAsName
    ];

    #endregion

    #region Interop B - Hermod against real servers

    /// <summary>Section 7.3.</summary>
    public const String HermodAccount          = "Account: new + ToS + contact";
    /// <summary>Section 7.3.1: the same key finds the same account.</summary>
    public const String HermodAccountFound     = "Account: found by its key";
    /// <summary>Section 7.3.1: onlyReturnExisting with a new key.</summary>
    public const String HermodAccountNone      = "Account: none for a new key";
    /// <summary>Section 7.3.4.</summary>
    public const String HermodEABBound         = "EAB: bound";
    /// <summary>Section 7.3.4: required, and Hermod has none to give.</summary>
    public const String HermodEABMissing       = "EAB: required, Hermod says so and sends nothing";
    /// <summary>Section 7.3.4: a wrong MAC.</summary>
    public const String HermodEABWrongMAC      = "EAB: a wrong MAC refused";
    /// <summary>Section 8.3 by Hermod's responder.</summary>
    public const String HermodHttp01           = "http-01: a name";
    /// <summary>Section 8.3, sixteen names.</summary>
    public const String HermodHttp01Sixteen    = "http-01: 16 names";
    /// <summary>Section 8.4 by Hermod's responder.</summary>
    public const String HermodDns01            = "dns-01, the record taken away after";
    /// <summary>Section 7.1.3.</summary>
    public const String HermodWildcard         = "Wildcard by dns-01, its base by http-01";
    /// <summary>RFC 8738.</summary>
    public const String HermodIPv4             = "IP identifier v4 (RFC 8738)";
    /// <summary>RFC 8738.</summary>
    public const String HermodIPv6             = "IP identifier v6 (RFC 8738)";
    /// <summary>Section 7.4.</summary>
    public const String HermodCertificateKeys  = "Certificate keys P-256, P-384, RSA 2048, 4096";
    /// <summary>Section 6.5: Pebble's storm of badNonce.</summary>
    public const String HermodNonceStorm       = "badNonce storms";
    /// <summary>Section 7.4.2: chains of every length.</summary>
    public const String HermodChains           = "Chains of 1, 2, 4 intermediates";
    /// <summary>Section 7.4.2: alternate chains, the default one kept.</summary>
    public const String HermodAlternateRoots   = "Alternate roots: the default chain kept";
    /// <summary>Section 7.1.4: a valid authorization reused.</summary>
    public const String HermodAuthzReuse       = "A valid authorization reused";
    /// <summary>draft-ietf-acme-profiles.</summary>
    public const String HermodProfileIssued    = "Profiles: issued";
    /// <summary>draft-ietf-acme-profiles: invalidProfile.</summary>
    public const String HermodProfileUnknown   = "Profiles: an unknown one refused";
    /// <summary>draft-ietf-acme-profiles: none asked for that the server does not advertise.</summary>
    public const String HermodProfileUnadvertised = "Profiles: an unadvertised one not asked for";
    /// <summary>RFC 9773, section 4.</summary>
    public const String HermodARIWindow        = "ARI: the window in the lifetime";
    /// <summary>RFC 9773, section 5.</summary>
    public const String HermodARIReplaces      = "ARI: \"replaces\" sent and taken";
    /// <summary>Section 7.6.</summary>
    public const String HermodRevocation       = "Revocation with a reason, as the server keeps it";
    /// <summary>Section 7.6: alreadyRevoked.</summary>
    public const String HermodAlreadyRevoked   = "Revocation again: alreadyRevoked";
    /// <summary>The manager's files.</summary>
    public const String ManagerFiles           = "Manager: files";
    /// <summary>The manager renews when the server's window of ARI is due.</summary>
    public const String ManagerRenewsByARI     = "Manager: renewal when the server's window is due";
    /// <summary>The manager renews by a third of the lifetime, where there is no ARI.</summary>
    public const String ManagerRenewsByThird   = "Manager: renewal by a third of the lifetime, without ARI";

    /// <summary>The rows of interop B, in their order.</summary>
    public static readonly IReadOnlyList<String> ServerRows = [
        HermodAccount, HermodAccountFound, HermodAccountNone, HermodEABBound, HermodEABMissing, HermodEABWrongMAC,
        HermodHttp01, HermodHttp01Sixteen, HermodDns01, HermodWildcard, HermodIPv4, HermodIPv6, HermodCertificateKeys,
        HermodNonceStorm, HermodChains, HermodAlternateRoots, HermodAuthzReuse,
        HermodProfileIssued, HermodProfileUnknown, HermodProfileUnadvertised, HermodARIWindow, HermodARIReplaces,
        HermodRevocation, HermodAlreadyRevoked, ManagerFiles, ManagerRenewsByARI, ManagerRenewsByThird
    ];

    #endregion

    #region The reference run - certbot's files

    /// <summary>fullchain.pem and privkey.pem named, moded, encoded and of the key of certbot's.</summary>
    public const String ReferenceFiles         = "Manager's files named, moded, encoded as certbot's";
    /// <summary>The final newline of certbot's files.</summary>
    public const String ReferenceFinalNewline  = "Manager's files end with a newline as certbot's";
    /// <summary>Hermod's ServerCertificateFile reads certbot's live/.</summary>
    public const String ReferenceReads         = "ServerCertificateFile reads certbot's live/";
    /// <summary>A manager pointed at certbot's live/ takes it over.</summary>
    public const String ReferenceTakesOver     = "Manager takes certbot's live/ over, orders nothing";

    /// <summary>The rows of the reference run, in their order.</summary>
    public static readonly IReadOnlyList<String> ReferenceRows = [
        ReferenceFiles, ReferenceFinalNewline, ReferenceReads, ReferenceTakesOver
    ];

    #endregion


    #region Line(...) / TryParse(...)

    /// <summary>What starts the line of a test's cell in its output.</summary>
    public const String Prefix = "INTEROP-MATRIX:";

    /// <summary>
    /// The line by which a test declares its cell.
    /// </summary>
    /// <param name="Matrix"><see cref="Clients"/>, <see cref="Servers"/>, <see cref="Reference"/> or <see cref="Bench"/>.</param>
    /// <param name="Peer">The peer of other hands, with its version: "certbot 5.10.0", "Pebble 2.10.3".</param>
    /// <param name="Against">This family's side and its commit: "PKI ba8324a9", "Hermod 0a93a6fb".</param>
    /// <param name="Cell">The cell.</param>
    /// <param name="Finding">The finding that keeps it red, if any.</param>
    /// <param name="ToDo">The ToDo that keeps it red, if any.</param>
    public static String Line(String   Matrix,
                              String   Peer,
                              String   Against,
                              String   Cell,
                              String?  Finding  = null,
                              String?  ToDo     = null)

        => $"{Prefix} matrix={Matrix} | peer={Peer} | against={Against} | cell={Cell}" +
           (Finding is not null ? $" | finding={Finding}" : "") +
           (ToDo    is not null ? $" | todo={ToDo}"       : "");

    /// <summary>
    /// The fields of a line of <see cref="Line"/> in a test's output - or null
    /// where there is none.
    /// </summary>
    public static IReadOnlyDictionary<String, String>? TryParse(String Output)
    {

        var line = Output.Split('\n').
                          Select(candidate => candidate.Trim()).
                          FirstOrDefault(candidate => candidate.StartsWith(Prefix, StringComparison.Ordinal));

        if (line is null)
            return null;

        return line[Prefix.Length..].
                   Split(" | ").
                   Select(field => field.Trim().Split('=', 2)).
                   Where (pair  => pair.Length == 2).
                   GroupBy(pair => pair[0]).
                   ToDictionary(group => group.Key, group => group.First()[1]);

    }

    #endregion

}
