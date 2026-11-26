namespace Dns.Net.Abstractions;

/// <summary>
/// Represents an NS record (RFC 1035, Sec. 3.3.11).
/// </summary>
/// <remarks>
/// The type mirrors <see cref="System.Net.NsRecord" />. <see cref="IDnsQueryRecord{TSelf}.CreateRecords" /> keeps the escapes of <see cref="DnsName.ToString" />, except that a name with an <c>xn--</c> label comes back in Unicode, and in lowercase, when <see cref="System.Globalization.IdnMapping" /> converts the whole name, which it does not for a name with an escape, an underscore label or an invalid <c>xn--</c> label.
/// </remarks>
/// <param name="Name">The name of the name server.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsNsRecord(string Name, TimeSpan Ttl) : IDnsQueryRecord<DnsNsRecord>
{
	static DnsRecordType IDnsQueryRecord<DnsNsRecord>.Type => DnsRecordType.Ns;

	static DnsNsRecord[] IDnsQueryRecord<DnsNsRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create(answers, ttl, static (DnsNsData ns, TimeSpan recordTtl) => new DnsNsRecord(InternationalNames.ToUnicode(ns.Name), recordTtl));
	}
}
