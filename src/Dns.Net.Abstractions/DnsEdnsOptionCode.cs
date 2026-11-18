namespace Dns.Net.Abstractions;

/// <summary>
/// Identifies an EDNS option (RFC 6891, Sec. 6.1.2).
/// </summary>
/// <remarks>Any other 16-bit value is valid.</remarks>
public enum DnsEdnsOptionCode : ushort
{
	/// <summary>
	/// The name server identifier (RFC 5001).
	/// </summary>
	Nsid = 3,

	/// <summary>
	/// The client subnet (RFC 7871).
	/// </summary>
	ClientSubnet = 8,

	/// <summary>
	/// The expiry timer of a zone (RFC 7314).
	/// </summary>
	Expire = 9,

	/// <summary>
	/// A DNS cookie (RFC 7873).
	/// </summary>
	Cookie = 10,

	/// <summary>
	/// The idle timeout of a TCP connection (RFC 7828).
	/// </summary>
	TcpKeepalive = 11,

	/// <summary>
	/// Padding (RFC 7830).
	/// </summary>
	Padding = 12,

	/// <summary>
	/// Extended error information (RFC 8914).
	/// </summary>
	ExtendedDnsError = 15
}
