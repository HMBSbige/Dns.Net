using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of an SRV record, the location of a service (RFC 2782).
/// </summary>
/// <param name="Priority">The priority of the target host; clients try the lowest value first.</param>
/// <param name="Weight">The relative weight among targets of the same priority.</param>
/// <param name="Port">The port of the service on the target host.</param>
/// <param name="Target">The name of the target host, or the root to say that the service is not available.</param>
public sealed record DnsSrvData(ushort Priority, ushort Weight, ushort Port, DnsName Target) : DnsRecordData
{
	/// <summary>
	/// Gets <see cref="DnsRecordType.Srv" />.
	/// </summary>
	public override DnsRecordType Type => DnsRecordType.Srv;

	internal override void AppendPresentation(StringBuilder builder)
	{
		builder.Append($"{Priority} {Weight} {Port} ");
		Target.AppendAbsolute(builder);
	}

	internal override void Write(ref DnsWireWriter writer)
	{
		writer.WriteUInt16(Priority);
		writer.WriteUInt16(Weight);
		writer.WriteUInt16(Port);
		// RFC 2782: the target is never compressed.
		writer.WriteName(Target, compress: false);
	}

	internal static DnsSrvData? Read(ref DnsWireReader reader)
	{
		return reader.TryReadUInt16(out ushort priority) && reader.TryReadUInt16(out ushort weight) && reader.TryReadUInt16(out ushort port) && reader.TryReadName(out DnsName target)
			? new DnsSrvData(priority, weight, port, target)
			: null;
	}
}
