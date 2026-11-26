namespace Dns.Net.Abstractions;

/// <summary>
/// Represents a CNAME record (RFC 1035, Sec. 3.3.1).
/// </summary>
/// <remarks>
/// The type mirrors <see cref="System.Net.CNameRecord" />. <see cref="IDnsQueryRecord{TSelf}.CreateRecords" /> keeps the escapes of <see cref="DnsName.ToString" />, except that a name with an <c>xn--</c> label comes back in Unicode, and in lowercase, when <see cref="System.Globalization.IdnMapping" /> converts the whole name, which it does not for a name with an escape, an underscore label or an invalid <c>xn--</c> label.
/// </remarks>
/// <param name="CanonicalName">The canonical name.</param>
/// <param name="Ttl">The TTL of the record.</param>
public readonly record struct DnsCNameRecord(string CanonicalName, TimeSpan Ttl) : IDnsQueryRecord<DnsCNameRecord>
{
	static DnsRecordType IDnsQueryRecord<DnsCNameRecord>.Type => DnsRecordType.CName;

	static DnsCNameRecord[] IDnsQueryRecord<DnsCNameRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create(answers, ttl, static (DnsCNameData cname, TimeSpan recordTtl) => new DnsCNameRecord(InternationalNames.ToUnicode(cname.CanonicalName), recordTtl));
	}
}
