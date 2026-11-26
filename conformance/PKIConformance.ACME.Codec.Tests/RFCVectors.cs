using System.Security.Cryptography;

using PKIConformance.Core.RawACME;

namespace PKIConformance.ACME.Codec.Tests;

/// <summary>
/// The examples of the RFCs, as they are printed there - the long values
/// split where the RFC splits them, so that each line can be held against
/// the text (https://www.rfc-editor.org/rfc/rfc7515.txt and the others).
/// </summary>
public static class RFCVectors
{

    #region RFC 7515, Appendix C - base64url

    /// <summary>RFC 7515, Appendix C: "3 236 255 224 193" encodes as "A-z_4ME".</summary>
    public static readonly Byte[] AppendixC_Octets  = [ 3, 236, 255, 224, 193 ];

    /// <summary>RFC 7515, Appendix C.</summary>
    public const           String AppendixC_Encoded = "A-z_4ME";

    #endregion

    #region RFC 7638, section 3.1 - the JWK thumbprint of an RSA key

    /// <summary>RFC 7638, section 3.1: "n" of the example key.</summary>
    public const String RFC7638_N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt" +
                                    "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
                                    "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD" +
                                    "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9" +
                                    "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH" +
                                    "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    /// <summary>RFC 7638, section 3.1: "e" of the example key.</summary>
    public const String RFC7638_E          = "AQAB";

    /// <summary>RFC 7638, section 3.1: the JWK as printed, with the members that do not count and in the order of the RFC.</summary>
    public static String RFC7638_JWK
        => $$"""{ "kty": "RSA", "n": "{{RFC7638_N}}", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29" }""";

    /// <summary>RFC 7638, section 3.1: its SHA-256 thumbprint.</summary>
    public const String RFC7638_Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    #endregion

    #region RFC 7515, Appendices A.2 and A.3 - JWS

    /// <summary>RFC 7515, Appendix A.1-A.3: BASE64URL(JWS Payload), the same in every example - with a CR LF in it.</summary>
    public const String RFC7515_Payload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                                          "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

    /// <summary>RFC 7515, Appendix A.2.1: BASE64URL(UTF8({"alg":"RS256"})).</summary>
    public const String A2_Protected = "eyJhbGciOiJSUzI1NiJ9";

    public const String A2_N  = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" +
                                "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" +
                                "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" +
                                "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" +
                                "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" +
                                "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";

    public const String A2_E  = "AQAB";

    public const String A2_D  = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I" +
                                "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0" +
                                "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn" +
                                "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT" +
                                "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh" +
                                "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";

    public const String A2_P  = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi" +
                                "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG" +
                                "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc";

    public const String A2_Q  = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa" +
                                "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA" +
                                "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";

    public const String A2_DP = "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q" +
                                "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb" +
                                "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0";

    public const String A2_DQ = "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa" +
                                "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky" +
                                "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU";

    public const String A2_QI = "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o" +
                                "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU" +
                                "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U";

    /// <summary>RFC 7515, Appendix A.2.1: BASE64URL(JWS Signature) - RSASSA-PKCS1-v1_5 is deterministic, so a signer has to come to exactly this.</summary>
    public const String A2_Signature = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
                                       "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
                                       "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
                                       "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
                                       "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
                                       "p0igcN_IoypGlUPQGe77Rw";

    /// <summary>RFC 7515, Appendix A.3.1: BASE64URL(UTF8({"alg":"ES256"})).</summary>
    public const String A3_Protected = "eyJhbGciOiJFUzI1NiJ9";

    public const String A3_X  = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    public const String A3_Y  = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    public const String A3_D  = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

    /// <summary>RFC 7515, Appendix A.3.1: R || S, base64url. ECDSA is randomized: this verifies, and is not what a signer comes to again.</summary>
    public const String A3_Signature = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA" +
                                       "pmWQxfKTUJqPP3-Kg6NU1Q";

    /// <summary>
    /// The RSA key of Appendix A.2, private, as a key of the raw codec.
    /// </summary>
    public static RawKey A2_Key()
    {

        var n   = RawBase64Url.Decode(A2_N);
        var rsa = RSA.Create();

        rsa.ImportParameters(new RSAParameters {
                                 Modulus   = n,
                                 Exponent  = RawBase64Url.Decode(A2_E),
                                 D         = PadLeft(RawBase64Url.Decode(A2_D),  n.Length),
                                 P         = PadLeft(RawBase64Url.Decode(A2_P),  (n.Length + 1) / 2),
                                 Q         = PadLeft(RawBase64Url.Decode(A2_Q),  (n.Length + 1) / 2),
                                 DP        = PadLeft(RawBase64Url.Decode(A2_DP), (n.Length + 1) / 2),
                                 DQ        = PadLeft(RawBase64Url.Decode(A2_DQ), (n.Length + 1) / 2),
                                 InverseQ  = PadLeft(RawBase64Url.Decode(A2_QI), (n.Length + 1) / 2)
                             });

        return new RawKey(rsa, "RS256");

    }

    /// <summary>
    /// The EC key of Appendix A.3, private, as a key of the raw codec.
    /// </summary>
    public static RawKey A3_Key()

        => new (ECDsa.Create(new ECParameters {
                                 Curve  = ECCurve.NamedCurves.nistP256,
                                 Q      = new ECPoint { X = RawBase64Url.Decode(A3_X), Y = RawBase64Url.Decode(A3_Y) },
                                 D      = RawBase64Url.Decode(A3_D)
                             }),
                "ES256");

    private static Byte[] PadLeft(Byte[] Octets, Int32 Length)
    {
        if (Octets.Length >= Length)
            return Octets;
        var padded = new Byte[Length];
        Octets.CopyTo(padded, Length - Octets.Length);
        return padded;
    }

    #endregion

    #region RFC 9773, section 4.1 and Appendix A - the ARI identifier of a certificate

    /// <summary>RFC 9773, Appendix A: the example certificate.</summary>
    public const String RFC9773_Certificate = """
                                              -----BEGIN CERTIFICATE-----
                                              MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
                                              cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
                                              BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
                                              7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
                                              qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
                                              yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
                                              +FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
                                              -----END CERTIFICATE-----
                                              """;

    /// <summary>RFC 9773, section 4.1, step 3: its unique identifier.</summary>
    public const String RFC9773_CertificateId = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE";

    /// <summary>The DER of the example certificate.</summary>
    public static Byte[] RFC9773_CertificateDER()

        => Convert.FromBase64String(String.Concat(RFC9773_Certificate.Split('\n').
                                                                      Select(line => line.Trim()).
                                                                      Where (line => !line.StartsWith("-----"))));

    #endregion

}
