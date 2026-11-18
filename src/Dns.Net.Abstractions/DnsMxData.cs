using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of an MX record, a mail exchange for the owner (RFC 1035, Sec. 3.3.9).
/// </summary>
/// <param name="Preference">The preference of the exchange; lower values are preferred.</param>
/// <param name="Exchange">The name of the mail exchange.</param>
public sealed record DnsMxData(ushort Preference, DnsName Exchange) : DnsRecordData
{
	/// <summary>
	/// Gets <see cref="DnsRecordType.Mx" />.
	/// </summary>
	public override DnsRecordType Type => DnsRecordType.Mx;

	internal override void AppendPresentation(StringBuilder builder)
	{
		builder.Append($"{Preference} ");
		Exchange.AppendAbsolute(builder);
	}

	internal override void Write(ref DnsWireWriter writer)
	{
		writer.WriteUInt16(Preference);
		writer.WriteName(Exchange, compress: true);
	}

	internal static DnsMxData? Read(ref DnsWireReader reader)
	{
		return reader.TryReadUInt16(out ushort preference) && reader.TryReadName(out DnsName exchange) ? new DnsMxData(preference, exchange) : null;
	}
}
