using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of an NS record, an authoritative name server (RFC 1035, Sec. 3.3.11).
/// </summary>
/// <param name="Name">The name of the name server.</param>
public sealed record DnsNsData(DnsName Name) : DnsRecordData
{
	/// <summary>
	/// Gets <see cref="DnsRecordType.Ns" />.
	/// </summary>
	public override DnsRecordType Type => DnsRecordType.Ns;

	internal override void AppendPresentation(StringBuilder builder)
	{
		Name.AppendAbsolute(builder);
	}

	internal override void Write(ref DnsWireWriter writer)
	{
		writer.WriteName(Name, compress: true);
	}

	internal static DnsNsData? Read(ref DnsWireReader reader)
	{
		return reader.TryReadName(out DnsName name) ? new DnsNsData(name) : null;
	}
}
