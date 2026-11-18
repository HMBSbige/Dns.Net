namespace Dns.Net.Abstractions;

/// <summary>
/// Identifies the class of a resource record, or the class that a question asks for (RFC 1035, Sec. 3.2.4 and 3.2.5).
/// </summary>
/// <remarks>Any other 16-bit value is valid and shows as <c>CLASS</c> followed by the number (RFC 3597, Sec. 5).</remarks>
public enum DnsClass : ushort
{
	/// <summary>
	/// The Internet (RFC 1035).
	/// </summary>
	Internet = 1,

	/// <summary>
	/// The Chaos system (RFC 1035).
	/// </summary>
	Chaos = 3,

	/// <summary>
	/// Hesiod (RFC 1035).
	/// </summary>
	Hesiod = 4,

	/// <summary>
	/// No class, as dynamic updates use it (RFC 2136).
	/// </summary>
	None = 254,

	/// <summary>
	/// Every class (RFC 1035).
	/// </summary>
	Any = 255
}
