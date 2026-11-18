using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of a CNAME record, the canonical name of an alias (RFC 1035, Sec. 3.3.1).
/// </summary>
/// <param name="CanonicalName">The canonical name.</param>
public sealed record DnsCNameData(DnsName CanonicalName) : DnsRecordData
{
	/// <summary>
	/// Gets <see cref="DnsRecordType.CName" />.
	/// </summary>
	public override DnsRecordType Type => DnsRecordType.CName;

	internal override void AppendPresentation(StringBuilder builder)
	{
		CanonicalName.AppendAbsolute(builder);
	}

	internal override void Write(ref DnsWireWriter writer)
	{
		writer.WriteName(CanonicalName, compress: true);
	}

	internal static DnsCNameData? Read(ref DnsWireReader reader)
	{
		return reader.TryReadName(out DnsName canonicalName) ? new DnsCNameData(canonicalName) : null;
	}
}
