using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using PKIConformance.Core.RawACME;

using HermodAccountKey    = org.GraphDefined.Vanaheimr.Hermod.ACME.ACMEAccountKey;
using HermodChallengeTask = org.GraphDefined.Vanaheimr.Hermod.ACME.ACMEChallengeTask;
using HermodIdentifier    = org.GraphDefined.Vanaheimr.Hermod.ACME.ACMEIdentifier;
using PKIIdentifier       = cloud.charging.open.PKI.Enrollment.ACMEIdentifier;
using PKIValidator        = cloud.charging.open.PKI.Enrollment.ACMEValidator;

namespace PKIConformance.ACME.Codec.Tests;

/// <summary>
/// RFC 8555, section 8.1: the key authorization - <i>"keyAuthorization = token
/// || '.' || base64url(Thumbprint(accountKey))"</i> - and section 8.4: what
/// dns-01 makes of it, <i>"the base64url encoding of the SHA-256 digest of the
/// key authorization"</i>, in a TXT record of "_acme-challenge" below the name.
/// </summary>
/// <remarks>
/// The client publishes it, the server looks for it: two computations of one
/// value, by two parties that never compare notes but through the challenge.
/// </remarks>
[Property("RFC", "8555 §8.1")]
public class KeyAuthorizationTests
{

    private const String Token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";

    [Test]
    public void RawACME_Writes_The_Key_Authorization_Of_The_RFC_7638_Key()
        => Assert.That(RawChallenge.KeyAuthorization(Token, RawJWK.Parse(RFCVectors.RFC7638_JWK)),
                       Is.EqualTo($"{Token}.{RFCVectors.RFC7638_Thumbprint}"));

    [Test]
    [Property("RFC", "8555 §8.4")]
    public void RawACME_Writes_The_dns01_Value_As_43_Characters_Of_base64url()
    {

        var value = RawChallenge.DNS01Value($"{Token}.{RFCVectors.RFC7638_Thumbprint}");

        Assert.Multiple(() => {
            Assert.That(value,                              Has.Length.EqualTo(43));
            Assert.That(RawBase64Url.Decode(value),         Has.Length.EqualTo(32));
        });

    }

    [TestCase("www.example.org", "_acme-challenge.www.example.org")]
    [TestCase("*.example.org",   "_acme-challenge.example.org")]
    [Property("RFC", "8555 §8.4, §7.1.3")]
    public void RawACME_Names_The_dns01_Record_Below_The_Name(String Identifier, String Name)
        => Assert.That(RawChallenge.DNS01Name(Identifier), Is.EqualTo(Name));

    #region Hermod

    [Test]
    [Property("Level", "MUST")]
    public void Hermod_Writes_The_Key_Authorization_Of_Section_8_1()
    {

        using var key = HermodAccountKey.Generate();

        Assert.That(key.KeyAuthorization(Token), Is.EqualTo(RawChallenge.KeyAuthorization(Token, RawJWK.Parse(key.JWK.ToString()))));

    }

    [TestCase("www.example.org", false, "_acme-challenge.www.example.org")]
    [TestCase("example.org",     true,  "_acme-challenge.example.org")]
    [Property("RFC",   "8555 §8.4")]
    [Property("Level", "MUST")]
    public void Hermod_Publishes_The_dns01_Record_Of_Section_8_4(String Identifier, Boolean Wildcard, String Name)
    {

        using var key  = HermodAccountKey.Generate();
        var       task = new HermodChallengeTask(HermodIdentifier.From(Identifier), Wildcard, "dns-01", Token, key.KeyAuthorization(Token));

        Assert.Multiple(() => {
            Assert.That(task.DNSRecordName,   Is.EqualTo(Name));
            Assert.That(task.DNSRecordValue,  Is.EqualTo(RawChallenge.DNS01Value(RawChallenge.KeyAuthorization(Token, RawJWK.Parse(key.JWK.ToString())))));
        });

    }

    [Test]
    [Property("RFC",   "8555 §8.3")]
    [Property("Level", "MUST")]
    public void Hermod_Answers_http01_At_The_Path_Of_Section_8_3()
    {

        var task = new HermodChallengeTask(HermodIdentifier.From("www.example.org"), false, "http-01", Token, $"{Token}.x");

        Assert.That(task.HTTPPath, Is.EqualTo(RawChallenge.HTTP01Path(Token)));

    }

    #endregion

    #region The PKI

    /// <summary>
    /// The PKI's dns-01: it asks for the TXT records of the name of section
    /// 8.4, and takes the value the reference computes - for a name and for a
    /// wildcard, which is proven at its base name.
    /// </summary>
    [TestCase("www.example.org", "_acme-challenge.www.example.org")]
    [TestCase("*.example.org",   "_acme-challenge.example.org")]
    [Property("RFC",   "8555 §8.4")]
    [Property("Level", "MUST")]
    public async Task PKI_Looks_For_The_dns01_Value_Of_Section_8_4(String Identifier, String Name)
    {

        using var key            = RawKey.Generate("ES256");
        var       authorization  = RawChallenge.KeyAuthorization(Token, key.JWK);
        var       asked          = new List<String>();

        using var validator      = Validator((name, _) => {
                                                 asked.Add(name);
                                                 return Task.FromResult<IReadOnlyList<String>>([ "something else", RawChallenge.DNS01Value(authorization) ]);
                                             });

        var problem              = await validator.ValidateAsync("dns-01", new PKIIdentifier("dns", Identifier), Token, authorization, 80);

        Assert.Multiple(() => {
            Assert.That(problem?.Message, Is.Null,                        "the value of section 8.4 was not taken");
            Assert.That(asked,            Is.EqualTo(new[] { Name }));
        });

    }

    /// <summary>
    /// And refuses the key authorization itself, undigested - what a client
    /// that forgot the digest would publish.
    /// </summary>
    [Test]
    [Property("RFC",   "8555 §8.4")]
    [Property("Level", "MUST")]
    public async Task PKI_Refuses_The_Key_Authorization_Undigested_In_dns01()
    {

        using var key            = RawKey.Generate("ES256");
        var       authorization  = RawChallenge.KeyAuthorization(Token, key.JWK);

        using var validator      = Validator((_, _) => Task.FromResult<IReadOnlyList<String>>([ authorization ]));

        var problem              = await validator.ValidateAsync("dns-01", new PKIIdentifier("dns", "www.example.org"), Token, authorization, 80);

        Assert.That(problem?.Type, Is.EqualTo("incorrectResponse"));

    }

    /// <summary>
    /// A validator of the PKI that asks the given zone instead of a name server.
    /// </summary>
    private static PKIValidator Validator(Func<String, CancellationToken, Task<IReadOnlyList<String>>> Zone)

        => new (new DNSClient(SearchForIPv4DNSServers: false, SearchForIPv6DNSServers: false)) {
               LookupTXT = Zone
           };

    #endregion

}
