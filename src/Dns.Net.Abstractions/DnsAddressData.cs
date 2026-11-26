using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of an A record, an IPv4 address (RFC 1035, Sec. 3.4.1), or of an AAAA record, an IPv6 address (RFC 3596, Sec. 2.2).
/// </summary>
/// <remarks>The data keeps a copy of the address that it is given.</remarks>
public sealed record DnsAddressData : DnsRecordData
{
	private const int IPv4Length = 4;

	private const int IPv6Length = 16;

	private readonly IPAddress _address;

	// Named like the property, as positional records name their parameters, so that named arguments and named positional patterns such as DnsAddressData(Address: ...) work as on the other record data types.
#pragma warning disable IDE1006
	/// <summary>
	/// Initializes the data with a copy of an IPv4 or IPv6 address.
	/// </summary>
	/// <param name="Address">The IPv4 or IPv6 address, whose family selects the record type.</param>
	/// <exception cref="ArgumentNullException"><paramref name="Address" /> is <see langword="null" />.</exception>
	public DnsAddressData(IPAddress Address)
	{
		_address = CheckAddress(Address);
	}

	/// <summary>
	/// Deconstructs the data into its address.
	/// </summary>
	/// <param name="Address">The IPv4 or IPv6 address.</param>
	public void Deconstruct(out IPAddress Address)
	{
		Address = _address;
	}
#pragma warning restore IDE1006

	// The decoder's own address, which nothing else references, needs no copy.
	private DnsAddressData(ReadOnlySpan<byte> address)
	{
		_address = new IPAddress(address);
	}

	/// <summary>
	/// Gets the IPv4 or IPv6 address, whose family selects the record type.
	/// </summary>
	/// <remarks>
	/// The returned instance is shared by every reader of the data and must not be changed.
	/// Encoding and the presentation format drop <see cref="IPAddress.ScopeId" />.
	/// </remarks>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	public IPAddress Address { get => _address; init => _address = CheckAddress(value); }

	/// <summary>
	/// Gets <see cref="DnsRecordType.Aaaa" /> for an IPv6 address and <see cref="DnsRecordType.A" /> for an IPv4 address.
	/// </summary>
	public override DnsRecordType Type => Address.AddressFamily is AddressFamily.InterNetworkV6 ? DnsRecordType.Aaaa : DnsRecordType.A;

	internal override void AppendPresentation(StringBuilder builder)
	{
		builder.Append($"{(Address is { AddressFamily: AddressFamily.InterNetworkV6, ScopeId: not 0 } ? WithoutScope(Address) : Address)}");
	}

	internal override void Write(ref DnsWireWriter writer)
	{
		Span<byte> destination = writer.Allocate(Address.AddressFamily is AddressFamily.InterNetworkV6 ? IPv6Length : IPv4Length);
		bool written = Address.TryWriteBytes(destination, out _);
		Debug.Assert(written);
	}

	// Reads the address of an A record, if ipv6 is false, or of an AAAA record, which must be all of the RDATA.
	internal static DnsAddressData? Read(ref DnsWireReader reader, bool ipv6)
	{
		int length = ipv6 ? IPv6Length : IPv4Length;

		if (reader.Remaining != length)
		{
			reader.Fail(ipv6 ? "The RDATA of an AAAA record is not 16 bytes long." : "The RDATA of an A record is not 4 bytes long.");
			return null;
		}

		return reader.TryReadBytes(length, out ReadOnlySpan<byte> address) ? new DnsAddressData(address) : null;
	}

	private static IPAddress WithoutScope(IPAddress address)
	{
		Span<byte> bytes = stackalloc byte[IPv6Length];
		bool written = address.TryWriteBytes(bytes, out _);
		Debug.Assert(written);

		return new IPAddress(bytes);
	}

	private static IPAddress CheckAddress(IPAddress address)
	{
		ArgumentNullException.ThrowIfNull(address, nameof(Address));
		return IPAddressCopy.Of(address);
	}
}
