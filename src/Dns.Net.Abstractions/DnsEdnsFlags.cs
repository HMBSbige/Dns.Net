namespace Dns.Net.Abstractions;

/// <summary>
/// Identifies the flags of the OPT pseudo-record (RFC 6891, Sec. 6.1.3).
/// </summary>
[Flags]
public enum DnsEdnsFlags : ushort
{
	/// <summary>
	/// No flag.
	/// </summary>
	None = 0,

	/// <summary>
	/// The CO bit: compact denial of existence (RFC 9824, Sec. 5.1).
	/// </summary>
	CompactAnswersOk = 0x4000,

	/// <summary>
	/// The DO bit: the sender can handle DNSSEC records (RFC 3225).
	/// </summary>
	DnssecOk = 0x8000
}
