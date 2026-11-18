using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents a resource record (RFC 1035, Sec. 3.2.1): an owner name, a class, a TTL and typed data.
/// </summary>
/// <remarks>Equality also compares what encoding drops, such as the scope of an IPv6 address or fractions of a second.</remarks>
/// <param name="Name">The owner name.</param>
/// <param name="Ttl">How long the record may be cached, from zero to 2^32 − 1 seconds.</param>
/// <param name="Data">The data, which sets the type.</param>
/// <exception cref="ArgumentOutOfRangeException"><paramref name="Ttl" /> is negative or greater than 2^32 − 1 seconds.</exception>
/// <exception cref="ArgumentNullException"><paramref name="Data" /> is <see langword="null" />.</exception>
public sealed record DnsResourceRecord(DnsName Name, TimeSpan Ttl, DnsRecordData Data)
{
	private static readonly TimeSpan MaxTtl = TimeSpan.FromSeconds(uint.MaxValue);

	/// <summary>
	/// Gets how long the record may be cached, from zero to 2^32 − 1 seconds (RFC 8767, Sec. 4).
	/// </summary>
	/// <remarks>Encoding drops any fraction of a second.</remarks>
	/// <exception cref="ArgumentOutOfRangeException">The value set is negative or greater than 2^32 − 1 seconds.</exception>
	public TimeSpan Ttl { get; init => field = CheckTtl(value); } = CheckTtl(Ttl);

	/// <summary>
	/// Gets the data, which sets <see cref="Type" />.
	/// </summary>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	public DnsRecordData Data { get; init => field = CheckData(value); } = CheckData(Data);

	/// <summary>
	/// Gets the class; <see cref="DnsClass.Internet" /> by default.
	/// </summary>
	public DnsClass Class { get; init; } = DnsClass.Internet;

	/// <summary>
	/// Gets the type, which is that of <see cref="Data" />.
	/// </summary>
	public DnsRecordType Type => Data.Type;

	/// <summary>
	/// Returns the record as a line of a master file, such as <c>example.com. 300 IN A 192.0.2.1</c>.
	/// </summary>
	/// <remarks>A class or type without a mnemonic, and <see cref="DnsUnknownData" />, take the generic forms of RFC 3597, Sec. 5.</remarks>
	/// <returns>The record in presentation format.</returns>
	public override string ToString()
	{
		StringBuilder builder = new();
		Name.AppendAbsolute(builder);
		builder.Append($" {Ttl.Ticks / TimeSpan.TicksPerSecond} {Class.Mnemonic} {Type.Mnemonic} ");
		Data.AppendPresentation(builder);
		return builder.ToString();
	}

	private static TimeSpan CheckTtl(TimeSpan ttl)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(ttl, TimeSpan.Zero, nameof(Ttl));
		ArgumentOutOfRangeException.ThrowIfGreaterThan(ttl, MaxTtl, nameof(Ttl));
		return ttl;
	}

	private static DnsRecordData CheckData(DnsRecordData data)
	{
		ArgumentNullException.ThrowIfNull(data, nameof(Data));
		return data;
	}
}
