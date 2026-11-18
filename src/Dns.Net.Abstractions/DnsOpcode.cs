namespace Dns.Net.Abstractions;

/// <summary>
/// Identifies the kind of a message, its OPCODE (RFC 1035, Sec. 4.1.1).
/// </summary>
/// <remarks>Only the values 0 to 15 can be encoded.</remarks>
public enum DnsOpcode : byte
{
	/// <summary>
	/// A standard query (RFC 1035).
	/// </summary>
	Query = 0,

	/// <summary>
	/// A server status request (RFC 1035).
	/// </summary>
	Status = 2,

	/// <summary>
	/// A notification that a zone has changed (RFC 1996).
	/// </summary>
	Notify = 4,

	/// <summary>
	/// A dynamic update (RFC 2136).
	/// </summary>
	Update = 5
}
