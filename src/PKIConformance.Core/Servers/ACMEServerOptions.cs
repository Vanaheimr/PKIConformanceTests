using org.GraphDefined.Vanaheimr.Hermod.DNS;

namespace PKIConformance.Core.Servers;

/// <summary>
/// How a server under test is started.
/// </summary>
/// <param name="ReachableFromWsl">Listen on every address, so that a peer inside WSL reaches it - not only on loopback. The TLS certificate then names the address WSL reaches it at as well.</param>
/// <param name="ExternalAccountRequired">Open accounts only with an external account binding (RFC 8555, section 7.3.4).</param>
/// <param name="AllowedNames">The names and networks it signs for; every name where null.</param>
/// <param name="Challenges">The challenge types it offers; all it has where null.</param>
/// <param name="HTTP01Port">The port http-01 asks at; 80 where null, as RFC 8555 has it.</param>
/// <param name="TermsOfService">The terms of service of the directory's meta data, which a new account then has to agree to.</param>
/// <param name="DNSClient">How it resolves every name - pointed at the suite's own authoritative server (PLAN.md, section 0.3). One of its own where null.</param>
public sealed record ACMEServerOptions(Boolean                  ReachableFromWsl         = false,
                                       Boolean                  ExternalAccountRequired  = false,
                                       IReadOnlyList<String>?   AllowedNames             = null,
                                       IReadOnlyList<String>?   Challenges               = null,
                                       UInt16?                  HTTP01Port               = null,
                                       String?                  TermsOfService           = null,
                                       DNSClient?               DNSClient                = null);
