using System.Text;

namespace PKIConformance.Core.RawACME;

/// <summary>
/// base64url without padding (RFC 7515, section 2; RFC 4648, section 5),
/// written out by hand - the reference every other encoder of the suite is
/// judged by, so it uses none of them.
/// </summary>
/// <remarks>
/// The decoder is strict where RFC 4648 lets a decoder choose: no padding, no
/// characters outside the alphabet, no whitespace, no length that leaves six
/// bits over, and no bits set in what fills the last character up (section
/// 3.5, "canonical encoding"). Whether a party under test is as strict is a
/// question for its own tests; the reference answers it without doubt.
/// </remarks>
public static class RawBase64Url
{

    private const String Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    #region Encode(Octets)

    /// <summary>
    /// The octets in base64url, without padding.
    /// </summary>
    public static String Encode(ReadOnlySpan<Byte> Octets)
    {

        var text = new StringBuilder((Octets.Length * 4 + 2) / 3);
        var i    = 0;

        for (; i + 3 <= Octets.Length; i += 3)
        {
            var block = (Octets[i] << 16) | (Octets[i + 1] << 8) | Octets[i + 2];
            text.Append(Alphabet[(block >> 18) & 63]).
                 Append(Alphabet[(block >> 12) & 63]).
                 Append(Alphabet[(block >>  6) & 63]).
                 Append(Alphabet[ block        & 63]);
        }

        switch (Octets.Length - i)
        {

            case 1:
            {
                var block = Octets[i] << 16;
                text.Append(Alphabet[(block >> 18) & 63]).
                     Append(Alphabet[(block >> 12) & 63]);
                break;
            }

            case 2:
            {
                var block = (Octets[i] << 16) | (Octets[i + 1] << 8);
                text.Append(Alphabet[(block >> 18) & 63]).
                     Append(Alphabet[(block >> 12) & 63]).
                     Append(Alphabet[(block >>  6) & 63]);
                break;
            }

        }

        return text.ToString();

    }

    /// <summary>
    /// The UTF-8 of the text in base64url, without padding.
    /// </summary>
    public static String Encode(String Text)
        => Encode(Encoding.UTF8.GetBytes(Text));

    #endregion

    #region TryDecode(Text, out Octets, out Error)

    /// <summary>
    /// The octets of strict base64url - or why the text is none.
    /// </summary>
    public static Boolean TryDecode(String       Text,
                                    out Byte[]   Octets,
                                    out String?  Error)
    {

        Octets = [];
        Error  = null;

        if (Text.Length % 4 == 1)
        {
            Error = $"{Text.Length} characters leave six bits over, which no octets make.";
            return false;
        }

        var values = new Int32[Text.Length];

        for (var i = 0; i < Text.Length; i++)
        {

            values[i] = Alphabet.IndexOf(Text[i]);

            if (values[i] < 0)
            {
                Error = Text[i] == '='
                            ? "base64url of JWS has no padding."
                            : $"'{Text[i]}' at {i} is not of the base64url alphabet.";
                return false;
            }

        }

        var octets = new List<Byte>(Text.Length * 3 / 4);
        var j      = 0;

        for (; j + 4 <= values.Length; j += 4)
        {
            var block = (values[j] << 18) | (values[j + 1] << 12) | (values[j + 2] << 6) | values[j + 3];
            octets.Add((Byte) (block >> 16));
            octets.Add((Byte) (block >>  8));
            octets.Add((Byte)  block);
        }

        switch (values.Length - j)
        {

            case 2:
                if ((values[j + 1] & 0x0F) != 0)
                {
                    Error = "The last character has bits set that belong to no octet (RFC 4648, section 3.5).";
                    return false;
                }
                octets.Add((Byte) ((values[j] << 2) | (values[j + 1] >> 4)));
                break;

            case 3:
                if ((values[j + 2] & 0x03) != 0)
                {
                    Error = "The last character has bits set that belong to no octet (RFC 4648, section 3.5).";
                    return false;
                }
                octets.Add((Byte) ((values[j]     << 2) | (values[j + 1] >> 4)));
                octets.Add((Byte) ((values[j + 1] << 4) | (values[j + 2] >> 2)));
                break;

        }

        Octets = [.. octets];
        return true;

    }

    #endregion

    #region Decode(Text)

    /// <summary>
    /// The octets of strict base64url.
    /// </summary>
    /// <exception cref="FormatException">The text is no strict base64url.</exception>
    public static Byte[] Decode(String Text)

        => TryDecode(Text, out var octets, out var error)
               ? octets
               : throw new FormatException(error);

    #endregion

}
