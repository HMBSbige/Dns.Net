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

	public static bool IsInvalid(string name)
	{
		return IsReservedName(name, InvalidName, Invalid);
	}

	public static bool IsLocalhost(string name)
	{
		return IsReservedName(name, LocalhostName, Localhost);
	}

	public static bool IsOnion(string name)
	{
		return IsReservedName(name, OnionName, Onion);
	}

	// For a name already in the ASCII form that a client queries.
	public static bool IsOnion(DnsName name)
	{
		return name.IsSubdomainOf(OnionName);
	}

	// Judged by the labels, so that escapes count as the characters they stand for; a name that does not parse is judged by its text.
	private static bool IsReservedName(string hostName, DnsName reservedName, string reservedText)
	{
		if (InternationalNames.ToAscii(hostName) is not { } ascii)
		{
			return EndsWithReservedName(hostName, reservedText);
		}

		return DnsName.TryParse(ascii, out DnsName name) ? name.IsSubdomainOf(reservedName) : EndsWithReservedName(ascii, reservedText);
	}

	// A name that starts with a dot or has an empty label never matches.
	private static bool EndsWithReservedName(string hostName, string reservedName)
	{
		if (hostName.StartsWith('.') || hostName.Contains("..", StringComparison.Ordinal))
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
