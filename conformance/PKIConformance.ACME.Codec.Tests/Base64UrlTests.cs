using System.Text;

using NUnit.Framework;

using PKIConformance.Core.RawACME;

namespace PKIConformance.ACME.Codec.Tests;

/// <summary>
/// RFC 7515, section 2: <i>"Base64url Encoding: Base64 encoding using the URL-
/// and filename-safe character set defined in Section 5 of RFC 4648, with all
/// trailing '=' characters omitted"</i> - of the raw reference.
/// </summary>
/// <remarks>
/// Every other codec of the suite stands on this one: a reference that is
/// wrong here makes every verdict above it worthless. So it is held against
/// the examples of RFC 7515 and RFC 4648 before anything is held against it.
/// </remarks>
[Property("RFC", "7515 §2")]
public class Base64UrlTests
{

    [Test]
    [Property("RFC", "7515 App. C")]
    public void RawACME_Encodes_The_Example_Of_RFC_7515_Appendix_C()
        => Assert.That(RawBase64Url.Encode(RFCVectors.AppendixC_Octets), Is.EqualTo(RFCVectors.AppendixC_Encoded));

    [Test]
    [Property("RFC", "7515 App. C")]
    public void RawACME_Decodes_The_Example_Of_RFC_7515_Appendix_C()
        => Assert.That(RawBase64Url.Decode(RFCVectors.AppendixC_Encoded), Is.EqualTo(RFCVectors.AppendixC_Octets));

    /// <summary>
    /// RFC 4648, section 10, without the padding JWS omits.
    /// </summary>
    [TestCase("",       "")]
    [TestCase("f",      "Zg")]
    [TestCase("fo",     "Zm8")]
    [TestCase("foo",    "Zm9v")]
    [TestCase("foob",   "Zm9vYg")]
    [TestCase("fooba",  "Zm9vYmE")]
    [TestCase("foobar", "Zm9vYmFy")]
    [Property("RFC", "4648 §10")]
    public void RawACME_Agrees_With_The_Test_Vectors_Of_RFC_4648(String Text, String Encoded)
    {
        Assert.Multiple(() => {
            Assert.That(RawBase64Url.Encode(Text),                                Is.EqualTo(Encoded));
            Assert.That(Encoding.ASCII.GetString(RawBase64Url.Decode(Encoded)),   Is.EqualTo(Text));
        });
    }

    /// <summary>
    /// The two characters base64url has in place of "+" and "/", at both ends.
    /// </summary>
    [Test]
    [Property("RFC", "4648 §5")]
    public void RawACME_Uses_Minus_And_Underscore()
    {
        Assert.Multiple(() => {
            Assert.That(RawBase64Url.Encode([ 0xFB, 0xFF ]),  Is.EqualTo("-_8"));
            Assert.That(RawBase64Url.Decode("-_8"),           Is.EqualTo(new Byte[] { 0xFB, 0xFF }));
        });
    }

    /// <summary>
    /// What the reference refuses, so that a party under test that accepts it
    /// is seen to: padding, the characters of base64, whitespace, a length
    /// that leaves bits over, and bits set beyond the last octet (RFC 4648,
    /// section 3.5).
    /// </summary>
    [TestCase("Zg==",  Description = "padding")]
    [TestCase("Zm9+",  Description = "'+' of base64")]
    [TestCase("Zm9/",  Description = "'/' of base64")]
    [TestCase("Zm 9v", Description = "whitespace")]
    [TestCase("Z",     Description = "one character: six bits, no octet")]
    [TestCase("Zm9vY", Description = "length 5: six bits over")]
    [TestCase("Zh",    Description = "the four bits below 'f' set")]
    [TestCase("Zm8",   Description = "canonical 'fo' (RFC 4648: Zm8=) - the control: accepted")]
    [TestCase("Zm9",   Description = "the two bits below 'fo' set")]
    public void RawACME_Is_Strict(String Text)
    {

        var accepted = RawBase64Url.TryDecode(Text, out _, out var error);

        if (Text == "Zm8")
            Assert.That(accepted, Is.True,  error);
        else
            Assert.That(accepted, Is.False, $"\"{Text}\" was accepted");

    }

    /// <summary>
    /// Round trip of every length from 0 to 64 octets.
    /// </summary>
    [Test]
    public void RawACME_Round_Trips_Every_Length()
    {

        var random = new Random(8555);

        Assert.Multiple(() => {
            for (var length = 0; length <= 64; length++)
            {
                var octets = new Byte[length];
                random.NextBytes(octets);
                Assert.That(RawBase64Url.Decode(RawBase64Url.Encode(octets)), Is.EqualTo(octets), $"{length} octets");
                Assert.That(RawBase64Url.Encode(octets), Does.Not.Contain("="), $"{length} octets");
            }
        });

    }

}
