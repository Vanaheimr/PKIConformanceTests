using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PKIConformance.Core.RawACME;

/// <summary>
/// A public JSON Web Key of EC or RSA (RFC 7517, RFC 7518 section 6), its
/// thumbprint (RFC 7638), and the key it stands for.
/// </summary>
/// <remarks>
/// <para>
/// The members are kept as the text they are on the wire. A JWK is made from
/// a key here as RFC 7518 wants it - coordinates of the full size of the curve
/// (sections 6.2.1.2 and 6.2.1.3), a modulus and an exponent in as few octets
/// as their values need (section 6.3.1) - and one read from somewhere else is
/// kept as it came, so that a test can see what somebody else made of it.
/// </para>
/// </remarks>
public sealed class RawJWK
{

    #region Properties

    /// <summary>"EC" or "RSA".</summary>
    public String   Kty  { get; }

    /// <summary>The curve of an EC key: "P-256", "P-384", "P-521".</summary>
    public String?  Crv  { get; }

    /// <summary>The x coordinate of an EC key, base64url.</summary>
    public String?  X    { get; }

    /// <summary>The y coordinate of an EC key, base64url.</summary>
    public String?  Y    { get; }

    /// <summary>The modulus of an RSA key, base64url.</summary>
    public String?  N    { get; }

    /// <summary>The public exponent of an RSA key, base64url.</summary>
    public String?  E    { get; }

    #endregion

    #region Constructor(s)

    private RawJWK(String   Kty,
                   String?  Crv  = null,
                   String?  X    = null,
                   String?  Y    = null,
                   String?  N    = null,
                   String?  E    = null)
    {
        this.Kty  = Kty;
        this.Crv  = Crv;
        this.X    = X;
        this.Y    = Y;
        this.N    = N;
        this.E    = E;
    }

    /// <summary>
    /// An EC key as its members say it.
    /// </summary>
    public static RawJWK EC(String Crv, String X, String Y)
        => new ("EC", Crv: Crv, X: X, Y: Y);

    /// <summary>
    /// An RSA key as its members say it.
    /// </summary>
    public static RawJWK RSA(String N, String E)
        => new ("RSA", N: N, E: E);

    #endregion


    #region (static) Of(Key)

    /// <summary>
    /// The public JWK of a key of .NET, as RFC 7518 wants it written.
    /// </summary>
    public static RawJWK Of(AsymmetricAlgorithm Key)
    {

        switch (Key)
        {

            case ECDsa ec:
            {

                var parameters  = ec.ExportParameters(false);
                var (crv, size) = CurveOf(parameters.Curve);

                return EC(crv,
                          RawBase64Url.Encode(FullSize(parameters.Q.X!, size)),
                          RawBase64Url.Encode(FullSize(parameters.Q.Y!, size)));

            }

            case System.Security.Cryptography.RSA rsa:
            {

                var parameters = rsa.ExportParameters(false);

                return RSA(RawBase64Url.Encode(Minimal(parameters.Modulus!)),
                           RawBase64Url.Encode(Minimal(parameters.Exponent!)));

            }

            default:
                throw new ArgumentException($"A JWK of {Key.GetType().Name} is none of EC or RSA.", nameof(Key));

        }

    }

    #endregion

    #region (static) Parse(JSON)

    /// <summary>
    /// The JWK of a JSON object - its members of the key as they are, every
    /// other member left aside.
    /// </summary>
    public static RawJWK Parse(String JSON)
    {

        using var document = JsonDocument.Parse(JSON);
        var       root     = document.RootElement;

        String? Member(String Name)
            => root.TryGetProperty(Name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

        return Member("kty") switch {
                   "EC"   => EC (Member("crv") ?? "", Member("x") ?? "", Member("y") ?? ""),
                   "RSA"  => RSA(Member("n")   ?? "", Member("e") ?? ""),
                   var k  => throw new FormatException($"A JWK of the type '{k}' is none of EC or RSA.")
               };

    }

    #endregion


    #region Canonical / ToJSON() / Thumbprint

    /// <summary>
    /// RFC 7638, section 3: the required members only, ordered
    /// lexicographically by their names, without any whitespace.
    /// </summary>
    public String Canonical

        => Kty == "EC"
               ? RawJson.Object(("crv", RawJson.Quote(Crv!)), ("kty", RawJson.Quote("EC")),  ("x", RawJson.Quote(X!)), ("y", RawJson.Quote(Y!)))
               : RawJson.Object(("e",   RawJson.Quote(E!)),   ("kty", RawJson.Quote("RSA")), ("n", RawJson.Quote(N!)));

    /// <summary>
    /// The JWK as JSON - the canonical form, which is a JWK of its own.
    /// </summary>
    public String ToJSON()
        => Canonical;

    /// <summary>
    /// The SHA-256 JWK thumbprint, base64url (RFC 7638, section 3).
    /// </summary>
    public String Thumbprint
        => RawBase64Url.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical)));

    #endregion

    #region Import()

    /// <summary>
    /// The public key the JWK stands for, as a key of .NET - for verifying.
    /// </summary>
    public AsymmetricAlgorithm Import()
    {

        if (Kty == "EC")
        {

            var curve = Crv switch {
                            "P-256" => ECCurve.NamedCurves.nistP256,
                            "P-384" => ECCurve.NamedCurves.nistP384,
                            "P-521" => ECCurve.NamedCurves.nistP521,
                            _       => throw new FormatException($"'{Crv}' is no curve of RFC 7518.")
                        };

            return ECDsa.Create(new ECParameters {
                                    Curve  = curve,
                                    Q      = new ECPoint { X = RawBase64Url.Decode(X!), Y = RawBase64Url.Decode(Y!) }
                                });

        }

        var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = RawBase64Url.Decode(N!), Exponent = RawBase64Url.Decode(E!) });
        return rsa;

    }

    #endregion


    #region (static) CurveOf(Curve)

    /// <summary>
    /// The name RFC 7518 gives a curve of .NET, and the octets of its coordinates.
    /// </summary>
    public static (String Name, Int32 Octets) CurveOf(ECCurve Curve)

        => Curve.Oid.Value switch {
               "1.2.840.10045.3.1.7"  => ("P-256", 32),
               "1.3.132.0.34"         => ("P-384", 48),
               "1.3.132.0.35"         => ("P-521", 66),
               var oid                => throw new ArgumentException($"The curve {oid} ({Curve.Oid.FriendlyName}) is none of RFC 7518.")
           };

    #endregion

    #region (private static) FullSize(Octets, Size) / Minimal(Octets)

    /// <summary>
    /// A coordinate left-padded with zeros to the size of the curve: RFC 7518,
    /// section 6.2.1.2, "The length of this octet string MUST be the full size
    /// of a coordinate for the curve".
    /// </summary>
    private static Byte[] FullSize(Byte[] Octets, Int32 Size)
    {

        var value = Minimal(Octets);

        if (value.Length > Size)
            throw new ArgumentException($"A coordinate of {value.Length} octets is larger than its curve.");

        var full = new Byte[Size];
        value.CopyTo(full, Size - value.Length);
        return full;

    }

    /// <summary>
    /// An unsigned big-endian integer without leading zero octets: RFC 7518,
    /// section 6.3.1, for "n" and "e".
    /// </summary>
    private static Byte[] Minimal(Byte[] Octets)
    {

        var start = 0;

        while (start < Octets.Length - 1 && Octets[start] == 0)
            start++;

        return Octets[start..];

    }

    #endregion

}
