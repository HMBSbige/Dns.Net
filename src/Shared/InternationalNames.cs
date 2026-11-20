using Dns.Net.Abstractions;
using System.Globalization;
using System.Text;

namespace Dns.Net;

// The IDNA conversion of System.Net.DnsResolver (RFC 5891), shared so that DnsClient and SpecialUseNames see the same name.
internal static class InternationalNames
{
	// The host name rules (RFC 1123) reject an underscore, for one.
	public static IdnMapping Mapping { get; } = new() { AllowUnassigned = false, UseStd3AsciiRules = true };

	// An ASCII name stays as it is, as the conversion would reject its escapes and underscores; null if the name does not convert.
	public static string? ToAscii(string name)
	{
		if (Ascii.IsValid(name))
		{
			return name;
		}

		try
		{
			return Mapping.GetAscii(name);
		}
		catch (ArgumentException)
		{
			return null;
		}
	}

	// A name that does not convert stays in presentation format.
	public static string ToUnicode(DnsName name)
	{
		string text = name.ToString();

		if (!HasAceLabel(name))
		{
			return text;
		}

		try
		{
			return Mapping.GetUnicode(text);
		}
		catch (ArgumentException)
		{
			return text;
		}

		static bool HasAceLabel(DnsName name)
		{
			Span<byte> encoded = stackalloc byte[DnsName.MaxEncodedLength];
			_ = name.TryEncode(encoded, out _);

			for (int i = 0; encoded[i] is not 0; i += encoded[i] + 1)
			{
				if (encoded[i] >= 4 && Ascii.EqualsIgnoreCase(encoded.Slice(i + 1, 4), "xn--"u8))
				{
					return true;
				}
			}

			return false;
		}
	}
}
