using System.Buffers.Binary;
using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of an SOA record, which marks the start of a zone of authority (RFC 1035, Sec. 3.3.13).
/// </summary>
/// <remarks>Encoding drops any fraction of a second from the intervals.</remarks>
/// <param name="PrimaryNameServer">The primary name server of the zone, MNAME.</param>
/// <param name="ResponsibleMailbox">The mailbox of the person responsible for the zone, RNAME, whose first label is the local part.</param>
/// <param name="Serial">The version of the zone, SERIAL (RFC 1982).</param>
/// <param name="Refresh">The REFRESH interval.</param>
/// <param name="Retry">The RETRY interval.</param>
/// <param name="Expire">The EXPIRE interval.</param>
/// <param name="Minimum">The MINIMUM interval, the TTL of negative answers (RFC 2308, Sec. 4).</param>
/// <exception cref="ArgumentOutOfRangeException">An interval is negative or greater than 2^32 − 1 seconds.</exception>
public sealed record DnsSoaData(DnsName PrimaryNameServer, DnsName ResponsibleMailbox, uint Serial, TimeSpan Refresh, TimeSpan Retry, TimeSpan Expire, TimeSpan Minimum) : DnsRecordData
{
	private const int IntervalsLength = 5 * sizeof(uint);

	/// <summary>
	/// Gets how long secondary servers wait before they check the zone for a newer version, REFRESH.
	/// </summary>
	/// <exception cref="ArgumentOutOfRangeException">The value set is negative or greater than 2^32 − 1 seconds.</exception>
	public TimeSpan Refresh { get; init => field = WireSeconds.Check(value, nameof(Refresh)); } = WireSeconds.Check(Refresh, nameof(Refresh));

	/// <summary>
	/// Gets how long secondary servers wait before they retry a failed check, RETRY.
	/// </summary>
	/// <exception cref="ArgumentOutOfRangeException">The value set is negative or greater than 2^32 − 1 seconds.</exception>
	public TimeSpan Retry { get; init => field = WireSeconds.Check(value, nameof(Retry)); } = WireSeconds.Check(Retry, nameof(Retry));

	/// <summary>
	/// Gets how long secondary servers go on answering for the zone without a successful check, EXPIRE.
	/// </summary>
	/// <exception cref="ArgumentOutOfRangeException">The value set is negative or greater than 2^32 − 1 seconds.</exception>
	public TimeSpan Expire { get; init => field = WireSeconds.Check(value, nameof(Expire)); } = WireSeconds.Check(Expire, nameof(Expire));

	/// <summary>
	/// Gets how long resolvers may cache a negative answer from the zone, MINIMUM (RFC 2308, Sec. 4).
	/// </summary>
	/// <exception cref="ArgumentOutOfRangeException">The value set is negative or greater than 2^32 − 1 seconds.</exception>
	public TimeSpan Minimum { get; init => field = WireSeconds.Check(value, nameof(Minimum)); } = WireSeconds.Check(Minimum, nameof(Minimum));

	/// <summary>
	/// Gets <see cref="DnsRecordType.Soa" />.
	/// </summary>
	public override DnsRecordType Type => DnsRecordType.Soa;

	internal override void AppendPresentation(StringBuilder builder)
	{
		PrimaryNameServer.AppendAbsolute(builder);
		builder.Append(' ');
		ResponsibleMailbox.AppendAbsolute(builder);
		builder.Append($" {Serial} {WireSeconds.Of(Refresh)} {WireSeconds.Of(Retry)} {WireSeconds.Of(Expire)} {WireSeconds.Of(Minimum)}");
	}

	internal override void Write(ref DnsWireWriter writer)
	{
		writer.WriteName(PrimaryNameServer, compress: true);
		writer.WriteName(ResponsibleMailbox, compress: true);
		writer.WriteUInt32(Serial);
		writer.WriteUInt32(WireSeconds.Of(Refresh));
		writer.WriteUInt32(WireSeconds.Of(Retry));
		writer.WriteUInt32(WireSeconds.Of(Expire));
		writer.WriteUInt32(WireSeconds.Of(Minimum));
	}

	internal static DnsSoaData? Read(ref DnsWireReader reader)
	{
		if (!reader.TryReadName(out DnsName primaryNameServer) || !reader.TryReadName(out DnsName responsibleMailbox) || !reader.TryReadBytes(IntervalsLength, out ReadOnlySpan<byte> fields))
		{
			return null;
		}

		return new DnsSoaData(
			primaryNameServer,
			responsibleMailbox,
			BinaryPrimitives.ReadUInt32BigEndian(fields),
			TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(fields.Slice(4))),
			TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(fields.Slice(8))),
			TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(fields.Slice(12))),
			TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(fields.Slice(16))));
	}
}
