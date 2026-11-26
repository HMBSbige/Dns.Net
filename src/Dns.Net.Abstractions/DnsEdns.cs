using System.Buffers.Binary;
using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the EDNS(0) data of a message (RFC 6891), which travels in the OPT pseudo-record.
/// </summary>
/// <remarks>The upper bits of the extended response code are held in <see cref="DnsMessage.ResponseCode" />, not here.</remarks>
public sealed record DnsEdns
{
	/// <summary>
	/// The default UDP payload size, 1232 bytes, small enough to avoid IP fragmentation.
	/// </summary>
	public const ushort DefaultUdpPayloadSize = 1232;

	private const int OptionHeaderLength = 2 * sizeof(ushort);

	private readonly DnsEdnsOption[] _options = [];

	/// <summary>
	/// Initializes EDNS data with the default payload size, version 0, no flags and no options.
	/// </summary>
	public DnsEdns()
	{
	}

	// Takes ownership of options, which no caller can reach, so that decoding need not copy them again.
	private DnsEdns(DnsEdnsOption[] options)
	{
		_options = options;
	}

	/// <summary>
	/// Gets the largest UDP payload, in bytes, that the sender can receive; <see cref="DefaultUdpPayloadSize" /> by default.
	/// </summary>
	/// <remarks>A value below 512 is kept as it is, although receivers treat it as 512 (RFC 6891, Sec. 6.2.5).</remarks>
	public ushort UdpPayloadSize { get; init; } = DefaultUdpPayloadSize;

	/// <summary>
	/// Gets the EDNS version; 0, the only version defined, by default.
	/// </summary>
	public byte Version { get; init; }

	/// <summary>
	/// Gets the flags, all 16 bits of them; <see cref="DnsEdnsFlags.None" /> by default.
	/// </summary>
	/// <remarks>Bits without a name are kept, so that forwarding loses nothing.</remarks>
	public DnsEdnsFlags Flags { get; init; }

	/// <summary>
	/// Gets a value that indicates whether <see cref="DnsEdnsFlags.DnssecOk" /> is set in <see cref="Flags" />.
	/// </summary>
	/// <remarks>In an object initializer, set it after <see cref="Flags" />, which would otherwise overwrite it.</remarks>
	public bool DnssecOk
	{
		get => (Flags & DnsEdnsFlags.DnssecOk) is not 0;
		init => Flags = value ? Flags | DnsEdnsFlags.DnssecOk : Flags & ~DnsEdnsFlags.DnssecOk;
	}

	/// <summary>
	/// Gets the options; empty by default.
	/// </summary>
	/// <remarks>The instance holds a copy of the list, but shares the bytes of the options.</remarks>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	public IReadOnlyList<DnsEdnsOption> Options { get => _options; init => _options = ListCopy.ToArray(value, nameof(Options)); }

	/// <summary>
	/// Determines whether <paramref name="other" /> has the same payload size, version, flags and options.
	/// </summary>
	/// <param name="other">The EDNS data to compare with.</param>
	/// <returns><see langword="true" /> if the EDNS data are equal; otherwise, <see langword="false" />.</returns>
	public bool Equals(DnsEdns? other)
	{
		if (ReferenceEquals(this, other))
		{
			return true;
		}

		return other is not null
			&& UdpPayloadSize == other.UdpPayloadSize
			&& Version == other.Version
			&& Flags == other.Flags
			&& _options.AsSpan().SequenceEqual(other._options);
	}

	/// <summary>
	/// Returns a hash code consistent with <see cref="Equals(DnsEdns)" />.
	/// </summary>
	/// <returns>The hash code.</returns>
	public override int GetHashCode()
	{
		HashCode hash = new();
		hash.Add(UdpPayloadSize);
		hash.Add(Version);
		hash.Add(Flags);
		ListEquality.AddTo(ref hash, Options);
		return hash.ToHashCode();
	}

	/// <summary>
	/// Returns the EDNS data as dig shows it in the OPT pseudosection, such as <c>; EDNS: version: 0, flags: do; udp: 1232</c>, then a line for each option.
	/// </summary>
	/// <returns>The EDNS data in presentation format, with lines separated by <see cref="Environment.NewLine" />.</returns>
	public override string ToString()
	{
		StringBuilder builder = new();
		AppendTo(builder);
		return builder.ToString();
	}

	internal void AppendTo(StringBuilder builder)
	{
		const DnsEdnsFlags named = DnsEdnsFlags.DnssecOk | DnsEdnsFlags.CompactAnswersOk;

		builder.Append($"; EDNS: version: {Version}, flags:");

		if ((Flags & DnsEdnsFlags.DnssecOk) is not 0)
		{
			builder.Append(" do");
		}

		if ((Flags & DnsEdnsFlags.CompactAnswersOk) is not 0)
		{
			builder.Append(" co");
		}

		if ((Flags & ~named) is not 0)
		{
			builder.Append($"; MBZ: 0x{(ushort)(Flags & ~named):x4},");
		}
		else
		{
			builder.Append(';');
		}

		builder.Append($" udp: {UdpPayloadSize}");

		foreach (DnsEdnsOption option in _options)
		{
			builder.AppendLine().Append($"; {option}");
		}
	}

	// Writes the OPT record (RFC 6891, Sec. 6.1.2 and 6.1.3).
	internal void Write(ref DnsWireWriter writer, int upperResponseCode)
	{
		writer.WriteName(DnsName.Root, compress: false);
		writer.WriteUInt16((ushort)DnsRecordType.Opt);
		writer.WriteUInt16(UdpPayloadSize);
		writer.WriteUInt32((uint)upperResponseCode << 24 | (uint)Version << 16 | (ushort)Flags);
		int lengthOffset = writer.BeginLength();

		foreach (DnsEdnsOption option in _options)
		{
			writer.WriteUInt16((ushort)option.Code);
			writer.WriteUInt16((ushort)option.Data.Length);
			writer.WriteBytes(option.Data.Span);
		}

		writer.EndLength(lengthOffset);
	}

	// Reads the options of an OPT record whose CLASS and TTL fields the caller has read.
	internal static DnsEdns? Read(ref DnsWireReader reader, ushort udpPayloadSize, uint ttl)
	{
		ReadOnlySpan<byte> data = reader.ReadToLimit();
		int count = 0;

		for (int i = 0; i < data.Length; ++count)
		{
			if (data.Length - i < OptionHeaderLength || BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i + 2)) > data.Length - i - OptionHeaderLength)
			{
				reader.Fail("An EDNS option runs past the end of the OPT record.");
				return null;
			}

			i += OptionHeaderLength + BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i + 2));
		}

		DnsEdnsOption[] options = count is 0 ? [] : new DnsEdnsOption[count];

		if (count > 0)
		{
			// One copy of the RDATA holds the data of every option.
			byte[] copy = data.ToArray();

			for (int i = 0, j = 0; j < options.Length; ++j)
			{
				DnsEdnsOptionCode code = (DnsEdnsOptionCode)BinaryPrimitives.ReadUInt16BigEndian(copy.AsSpan(i));
				int length = BinaryPrimitives.ReadUInt16BigEndian(copy.AsSpan(i + 2));
				options[j] = new DnsEdnsOption(code, copy.AsMemory(i + OptionHeaderLength, length));
				i += OptionHeaderLength + length;
			}
		}

		return new DnsEdns(options)
		{
			UdpPayloadSize = udpPayloadSize,
			Version = (byte)(ttl >> 16),
			Flags = (DnsEdnsFlags)(ushort)ttl
		};
	}
}
