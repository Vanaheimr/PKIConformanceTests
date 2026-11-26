using System.Security.Cryptography;

namespace PKIConformance.Core.RawACME;

/// <summary>
/// A private key of the raw codec, and the JWS algorithm it signs with
/// (RFC 7518, section 3): ES256, ES384, ES512, RS256 or PS256.
/// </summary>
/// <remarks>
/// The signatures are .NET's, as they come; what the raw codec adds is how
/// JWS wants them - ECDSA as R and S of the full size of the curve, one after
/// the other (RFC 7518, section 3.4), not DER - and, where a test asks for
/// it, the wrong form on purpose.
/// </remarks>
public sealed class RawKey : IDisposable
{

    #region Properties

    /// <summary>
    /// The key of .NET.
    /// </summary>
    public AsymmetricAlgorithm  Key        { get; }

    /// <summary>
    /// The JWS algorithm it signs with.
    /// </summary>
    public String               Algorithm  { get; }

    /// <summary>
    /// Its public JWK.
    /// </summary>
    public RawJWK               JWK        { get; }

    #endregion

    #region Constructor(s)

    /// <summary>
    /// A key of .NET that signs with the given algorithm.
    /// </summary>
    public RawKey(AsymmetricAlgorithm  Key,
                  String               Algorithm)
    {

        this.Key        = Key;
        this.Algorithm  = Algorithm;
        this.JWK        = RawJWK.Of(Key);

        var fits = (Key, Algorithm) switch {
                       (ECDsa,                            "ES256" or "ES384" or "ES512")  => true,
                       (System.Security.Cryptography.RSA, "RS256" or "PS256")             => true,
                       _                                                                   => false
                   };

        if (!fits)
            throw new ArgumentException($"A {Key.GetType().Name} does not sign {Algorithm}.", nameof(Algorithm));

    }

    #endregion


    #region (static) Generate(Algorithm, RSABits = 2048)

    /// <summary>
    /// A new key for the algorithm: ES256 on P-256, ES384 on P-384, ES512 on
    /// P-521 (RFC 7518, section 3.4), RS256 and PS256 on RSA of the given size.
    /// </summary>
    public static RawKey Generate(String  Algorithm,
                                  Int32   RSABits = 2048)

        => Algorithm switch {
               "ES256"            => new (ECDsa.Create(ECCurve.NamedCurves.nistP256), Algorithm),
               "ES384"            => new (ECDsa.Create(ECCurve.NamedCurves.nistP384), Algorithm),
               "ES512"            => new (ECDsa.Create(ECCurve.NamedCurves.nistP521), Algorithm),
               "RS256" or "PS256" => new (System.Security.Cryptography.RSA.Create(RSABits), Algorithm),
               _                  => throw new ArgumentException($"'{Algorithm}' is no algorithm of the raw codec.", nameof(Algorithm))
           };

    #endregion

    #region Sign(Data, ECDSAFormat = IeeeP1363FixedFieldConcatenation)

    /// <summary>
    /// The signature of the octets, as JWS wants it - or, for a test that is to
    /// see it refused, ECDSA in another format.
    /// </summary>
    public Byte[] Sign(Byte[]              Data,
                       DSASignatureFormat  ECDSAFormat = DSASignatureFormat.IeeeP1363FixedFieldConcatenation)

        => (Key, Algorithm) switch {
               (ECDsa ec, "ES256")                           => ec. SignData(Data, HashAlgorithmName.SHA256, ECDSAFormat),
               (ECDsa ec, "ES384")                           => ec. SignData(Data, HashAlgorithmName.SHA384, ECDSAFormat),
               (ECDsa ec, "ES512")                           => ec. SignData(Data, HashAlgorithmName.SHA512, ECDSAFormat),
               (System.Security.Cryptography.RSA rsa, "RS256") => rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
               (System.Security.Cryptography.RSA rsa, "PS256") => rsa.SignData(Data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
               _                                             => throw new InvalidOperationException()
           };

    #endregion

    #region (static) Verify(JWK, Algorithm, Data, Signature)

    /// <summary>
    /// Whether the signature of the octets holds by the public key of the JWK
    /// and the algorithm - read strictly: ECDSA only as R and S of the full
    /// size, and only on the curve the algorithm names.
    /// </summary>
    public static Boolean Verify(RawJWK  JWK,
                                 String  Algorithm,
                                 Byte[]  Data,
                                 Byte[]  Signature)
    {

        using var key = JWK.Import();

        switch (key, Algorithm)
        {

            case (ECDsa ec, "ES256" or "ES384" or "ES512"):
            {

                var (crv, size) = RawJWK.CurveOf(ec.ExportParameters(false).Curve);

                var (curveOfAlgorithm, hash) = Algorithm switch {
                                                   "ES384" => ("P-384", HashAlgorithmName.SHA384),
                                                   "ES512" => ("P-521", HashAlgorithmName.SHA512),
                                                   _       => ("P-256", HashAlgorithmName.SHA256)
                                               };

                return crv == curveOfAlgorithm &&
                       Signature.Length == 2 * size &&
                       ec.VerifyData(Data, Signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            }

            case (System.Security.Cryptography.RSA rsa, "RS256"):
                return rsa.VerifyData(Data, Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            case (System.Security.Cryptography.RSA rsa, "PS256"):
                return rsa.VerifyData(Data, Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            default:
                return false;

        }

    }

    #endregion

    #region Dispose()

    public void Dispose()
        => Key.Dispose();

    #endregion

}
