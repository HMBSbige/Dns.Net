namespace Dns.Net.Abstractions;

/// <summary>
/// Identifies the principal of a TSIG (RFC 8945) or SIG(0) (RFC 2931) signature that the server transport verified.
/// </summary>
/// <remarks>
/// A handler that authorizes a request by name also checks <see cref="Type" />, as a SIG(0) key may be one that a client registered for itself (RFC 9665).
/// </remarks>
/// <param name="Type"><see cref="DnsRecordType.Tsig" /> for a TSIG signature, or <see cref="DnsRecordType.Sig" /> for a SIG(0) signature.</param>
/// <param name="Name">The principal of the signature (RFC 3007, Sec. 2), such as the name of a TSIG key or the SIG(0) signer.</param>
/// <exception cref="ArgumentOutOfRangeException"><paramref name="Type" /> is neither <see cref="DnsRecordType.Tsig" /> nor <see cref="DnsRecordType.Sig" />.</exception>
public sealed record DnsRequestSigner(DnsRecordType Type, DnsName Name)
{
	/// <summary>
	/// Gets <see cref="DnsRecordType.Tsig" /> for a TSIG signature, or <see cref="DnsRecordType.Sig" /> for a SIG(0) signature.
	/// </summary>
	/// <exception cref="ArgumentOutOfRangeException">The value set is neither <see cref="DnsRecordType.Tsig" /> nor <see cref="DnsRecordType.Sig" />.</exception>
	public DnsRecordType Type { get; init => field = CheckType(value); } = CheckType(Type);

	private static DnsRecordType CheckType(DnsRecordType type)
	{
		if (type is not (DnsRecordType.Tsig or DnsRecordType.Sig))
		{
			throw new ArgumentOutOfRangeException(nameof(Type), type, "The type is neither TSIG nor SIG.");
		}

		return type;
	}
}
