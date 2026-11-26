using System.Formats.Asn1;

namespace PKIConformance.Core.RawACME;

/// <summary>
/// The unique identifier of a certificate in ACME Renewal Information
/// (RFC 9773, section 4.1), read from the certificate's DER with the ASN.1
/// reader of .NET - not with X509Certificate2, whose SerialNumber is what
/// Hermod reads.
/// </summary>
public static class RawARI
{

    private const String AuthorityKeyIdentifier = "2.5.29.35";

    /// <summary>
    /// <i>"base64url(AKI keyIdentifier) || '.' || base64url(Serial)"</i> - the
    /// serial number as the content octets of its DER INTEGER, a leading zero
    /// octet included where it has one. Null for a certificate without an
    /// Authority Key Identifier with a keyIdentifier.
    /// </summary>
    /// <param name="Certificate">The certificate, DER.</param>
    public static String? CertificateId(Byte[] Certificate)
    {

        var certificate     = new AsnReader(Certificate, AsnEncodingRules.DER).ReadSequence();
        var tbs             = certificate.ReadSequence();

        // version [0] EXPLICIT, where it is there.
        if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

        var serial          = tbs.ReadIntegerBytes().ToArray();

        tbs.ReadSequence();     // signature
        tbs.ReadSequence();     // issuer
        tbs.ReadSequence();     // validity
        tbs.ReadSequence();     // subject
        tbs.ReadSequence();     // subjectPublicKeyInfo

        var keyIdentifier   = (Byte[]?) null;

        while (tbs.HasData)
        {

            var tag = tbs.PeekTag();

            // extensions [3] EXPLICIT SEQUENCE OF Extension
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {

                var extensions = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3)).ReadSequence();

                while (extensions.HasData)
                {

                    var extension = extensions.ReadSequence();
                    var oid       = extension.ReadObjectIdentifier();

                    if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                        extension.ReadBoolean();

                    var value     = extension.ReadOctetString();

                    if (oid == AuthorityKeyIdentifier)
                    {

                        // AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
                        var aki = new AsnReader(value, AsnEncodingRules.DER).ReadSequence();

                        if (aki.HasData && aki.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                            keyIdentifier = aki.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));

                    }

                }

            }
            else
                tbs.ReadEncodedValue();

        }

        return keyIdentifier is null
                   ? null
                   : $"{RawBase64Url.Encode(keyIdentifier)}.{RawBase64Url.Encode(serial)}";

    }

}
