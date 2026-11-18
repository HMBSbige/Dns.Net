namespace Dns.Net.Abstractions;

/// <summary>
/// Identifies the type of a resource record, or the type that a question asks for (RFC 1035, Sec. 3.2.2 and 3.2.3).
/// </summary>
/// <remarks>Any other 16-bit value is valid and shows as <c>TYPE</c> followed by the number (RFC 3597, Sec. 5).</remarks>
public enum DnsRecordType : ushort
{
	/// <summary>
	/// An IPv4 host address (RFC 1035).
	/// </summary>
	A = 1,

	/// <summary>
	/// An authoritative name server (RFC 1035).
	/// </summary>
	Ns = 2,

	/// <summary>
	/// The canonical name of an alias (RFC 1035).
	/// </summary>
	CName = 5,

	/// <summary>
	/// The start of a zone of authority (RFC 1035).
	/// </summary>
	Soa = 6,

	/// <summary>
	/// A domain name pointer (RFC 1035).
	/// </summary>
	Ptr = 12,

	/// <summary>
	/// Host information (RFC 1035).
	/// </summary>
	HInfo = 13,

	/// <summary>
	/// A mail exchange (RFC 1035).
	/// </summary>
	Mx = 15,

	/// <summary>
	/// Text strings (RFC 1035).
	/// </summary>
	Txt = 16,

	/// <summary>
	/// A signature, as SIG(0) uses (RFC 2931).
	/// </summary>
	Sig = 24,

	/// <summary>
	/// An IPv6 host address (RFC 3596).
	/// </summary>
	Aaaa = 28,

	/// <summary>
	/// The location of a service (RFC 2782).
	/// </summary>
	Srv = 33,

	/// <summary>
	/// A naming authority pointer (RFC 3403).
	/// </summary>
	Naptr = 35,

	/// <summary>
	/// The redirection of a subtree (RFC 6672).
	/// </summary>
	DName = 39,

	/// <summary>
	/// The EDNS pseudo-record (RFC 6891), which <see cref="DnsMessage.Edns" /> represents.
	/// </summary>
	Opt = 41,

	/// <summary>
	/// A delegation signer (RFC 4034).
	/// </summary>
	Ds = 43,

	/// <summary>
	/// A DNSSEC signature (RFC 4034).
	/// </summary>
	Rrsig = 46,

	/// <summary>
	/// The next secure record of a DNSSEC chain (RFC 4034).
	/// </summary>
	Nsec = 47,

	/// <summary>
	/// A DNSSEC public key (RFC 4034).
	/// </summary>
	DnsKey = 48,

	/// <summary>
	/// The hashed next secure record of a DNSSEC chain (RFC 5155).
	/// </summary>
	Nsec3 = 50,

	/// <summary>
	/// A TLS certificate association (RFC 6698).
	/// </summary>
	Tlsa = 52,

	/// <summary>
	/// A general-purpose service binding (RFC 9460).
	/// </summary>
	Svcb = 64,

	/// <summary>
	/// A service binding for HTTPS (RFC 9460).
	/// </summary>
	Https = 65,

	/// <summary>
	/// A transaction signature (RFC 8945).
	/// </summary>
	Tsig = 250,

	/// <summary>
	/// An incremental zone transfer (RFC 1995); valid in questions only.
	/// </summary>
	Ixfr = 251,

	/// <summary>
	/// A full zone transfer (RFC 5936); valid in questions only.
	/// </summary>
	Axfr = 252,

	/// <summary>
	/// Every record type (RFC 1035).
	/// </summary>
	Any = 255,

	/// <summary>
	/// A certification authority authorization (RFC 8659).
	/// </summary>
	Caa = 257
}
