namespace Dns.Net.Abstractions;

/// <summary>
/// Identifies the protocol that carries a DNS message.
/// </summary>
/// <remarks>Any other value identifies another protocol, such as an exchange within the process.</remarks>
public enum DnsProtocol
{
	/// <summary>
	/// Classic DNS over UDP (RFC 1035, Sec. 4.2.1).
	/// </summary>
	Udp,

	/// <summary>
	/// Classic DNS over TCP (RFC 1035, Sec. 4.2.2; RFC 7766).
	/// </summary>
	Tcp,

	/// <summary>
	/// DNS over TLS (RFC 7858).
	/// </summary>
	Tls,

	/// <summary>
	/// DNS over HTTPS (RFC 8484).
	/// </summary>
	Https,

	/// <summary>
	/// DNS over QUIC (RFC 9250).
	/// </summary>
	Quic
}
