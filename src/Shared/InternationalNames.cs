using Dns.Net.Abstractions;
using System.Globalization;
using System.Text;

namespace Dns.Net;

// The IDNA conversion of System.Net.DnsResolver (RFC 5891), shared so that DnsClient, SpecialUseNames and the query records (DnsMxRecord, DnsSrvRecord and others) see names the same way.
internal static class InternationalNames
{
	// The host name rules (RFC 1123) reject an underscore, for one.
	private static readonly IdnMapping Mapping = new() { UseStd3AsciiRules = true };

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

		// Only an ACE label (RFC 5890) converts. A match after an escaped dot only costs a failed conversion, as the STD3 rules reject the backslash.
		if (!text.StartsWith("xn--", StringComparison.OrdinalIgnoreCase) && !text.Contains(".xn--", StringComparison.OrdinalIgnoreCase))
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
	}
}
