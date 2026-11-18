using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of a PTR record, a name that the owner points to (RFC 1035, Sec. 3.3.12).
/// </summary>
/// <param name="Name">The name pointed to.</param>
public sealed record DnsPtrData(DnsName Name) : DnsRecordData
{
	/// <summary>
	/// Gets <see cref="DnsRecordType.Ptr" />.
	/// </summary>
	public override DnsRecordType Type => DnsRecordType.Ptr;

	internal override void AppendPresentation(StringBuilder builder)
	{
		Name.AppendAbsolute(builder);
	}

	internal override void Write(ref DnsWireWriter writer)
	{
		writer.WriteName(Name, compress: true);
	}

	internal static DnsPtrData? Read(ref DnsWireReader reader)
	{
		return reader.TryReadName(out DnsName name) ? new DnsPtrData(name) : null;
	}
}
