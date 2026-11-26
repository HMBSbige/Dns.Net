using Dns.Net.Abstractions;

namespace Dns.Net;

// RFC 6761; RFC 7686. Shared so that DnsClientExtensions and DnsClient judge a name the same way.
internal static class SpecialUseNames
{
	private const string Invalid = "invalid";

	private const string Localhost = "localhost";

	private const string Onion = "onion";

	private static readonly DnsName InvalidName = DnsName.Parse(Invalid);

	private static readonly DnsName LocalhostName = DnsName.Parse(Localhost);

	private static readonly DnsName OnionName = DnsName.Parse(Onion);

	// For a name already in the ASCII form that a client queries.
	public static bool IsOnion(DnsName name)
	{
		return name.IsSubdomainOf(OnionName);
	}

	// Judged by the labels, so that escapes count as the characters they stand for; a name that does not parse is judged by its text.
	// The three are distinct top-level domains, so a name is in at most one of them.
	public static SpecialUseDomain GetDomain(string hostName)
	{
		// A name that does not convert is not ASCII, so it does not parse either.
		string ascii = InternationalNames.ToAscii(hostName) ?? hostName;

		bool parsed = DnsName.TryParse(ascii, out DnsName name);

		return IsIn(InvalidName, Invalid) ? SpecialUseDomain.Invalid
			: IsIn(LocalhostName, Localhost) ? SpecialUseDomain.Localhost
			: IsIn(OnionName, Onion) ? SpecialUseDomain.Onion
			: SpecialUseDomain.None;

		bool IsIn(DnsName domain, string text)
		{
			return parsed ? name.IsSubdomainOf(domain) : EndsWithReservedName(ascii, text);
		}
	}

	// A name that starts with a dot or has an empty label never matches.
	private static bool EndsWithReservedName(string hostName, string reservedName)
	{
		if (hostName.StartsWith('.') || hostName.Contains(".."))
		{
			return false;
		}

		ReadOnlySpan<char> name = hostName.AsSpan();

		if (name.EndsWith('.'))
		{
			name = name.Slice(0, name.Length - 1);
		}

		return name.EndsWith(reservedName, StringComparison.OrdinalIgnoreCase) && (name.Length == reservedName.Length || name[name.Length - reservedName.Length - 1] is '.');
	}
}

internal enum SpecialUseDomain
{
	None,
	Invalid,
	Localhost,
	Onion
}
