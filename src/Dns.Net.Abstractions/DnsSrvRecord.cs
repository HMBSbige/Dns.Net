using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents an SRV record (RFC 2782), with the addresses of the target that the response carries.
/// </summary>
/// <remarks>
/// The type mirrors <see cref="System.Net.SrvRecord" />. <see cref="IDnsQueryRecord{TSelf}.CreateRecords" /> keeps the escapes of <see cref="DnsName.ToString" />, except that a name with an <c>xn--</c> label comes back in Unicode, and in lowercase, when <see cref="System.Globalization.IdnMapping" /> converts the whole name, which it does not for a name with an escape, an underscore label or an invalid <c>xn--</c> label.
/// Equality compares the addresses one by one, rather than the lists.
/// </remarks>
/// <param name="Target">The name of the target host; <c>"."</c> says that the service is not available.</param>
/// <param name="Port">The port of the service on the target host.</param>
/// <param name="Priority">The priority of the target host; clients try the lowest value first.</param>
/// <param name="Weight">The relative weight for choosing among targets of the same priority.</param>
/// <param name="Ttl">The TTL of the record.</param>
/// <param name="Addresses">The addresses of the target host from the additional section of the response.</param>
public readonly record struct DnsSrvRecord(string Target, ushort Port, ushort Priority, ushort Weight, TimeSpan Ttl, [AllowNull] IReadOnlyList<DnsAddressRecord> Addresses) : IDnsQueryRecord<DnsSrvRecord>
{
	/// <summary>
	/// Gets the addresses of the target host from the additional section of the response.
	/// </summary>
	/// <remarks>The record keeps the list it is given, not a copy; a <see langword="null" /> list reads as empty.</remarks>
	[AllowNull]
	public IReadOnlyList<DnsAddressRecord> Addresses { get => field ?? []; init; } = Addresses;

	/// <summary>
	/// Determines whether <paramref name="other" /> has the same fields and addresses.
	/// </summary>
	/// <param name="other">The record to compare with.</param>
	/// <returns><see langword="true" /> if they are equal; otherwise, <see langword="false" />.</returns>
	public bool Equals(DnsSrvRecord other)
	{
		return Target == other.Target
			&& Port == other.Port
			&& Priority == other.Priority
			&& Weight == other.Weight
			&& Ttl == other.Ttl
			&& ListEquality.SequenceEqual(Addresses, other.Addresses);
	}

	/// <summary>
	/// Returns a hash code consistent with <see cref="Equals(DnsSrvRecord)" />.
	/// </summary>
	/// <returns>The hash code.</returns>
	public override int GetHashCode()
	{
		HashCode hash = new();
		hash.Add(Target);
		hash.Add(Port);
		hash.Add(Priority);
		hash.Add(Weight);
		hash.Add(Ttl);
		ListEquality.AddTo(ref hash, Addresses);
		return hash.ToHashCode();
	}

	static DnsRecordType IDnsQueryRecord<DnsSrvRecord>.Type => DnsRecordType.Srv;

	static DnsSrvRecord[] IDnsQueryRecord<DnsSrvRecord>.CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		DnsSrvRecord[] records = new DnsSrvRecord[answers.Length];
		int count = 0;

		// Indexed once for the whole RRset, and only if it has a record to build.
		Dictionary<DnsName, List<DnsAddressRecord>>? addresses = null;

		foreach (DnsResourceRecord answer in answers)
		{
			if (answer.Data is DnsSrvData srv)
			{
				addresses ??= IndexAddresses(response.Additionals);
				records[count++] = new DnsSrvRecord(InternationalNames.ToUnicode(srv.Target), srv.Port, srv.Priority, srv.Weight, ttl, addresses.GetValueOrDefault(srv.Target));
			}
		}

		return count == records.Length ? records : records.AsSpan(0, count).ToArray();
	}

	// Each owner has one list, which its SRV records share.
	private static Dictionary<DnsName, List<DnsAddressRecord>> IndexAddresses(IReadOnlyList<DnsResourceRecord> additionals)
	{
		Dictionary<DnsName, List<DnsAddressRecord>> addresses = [];

		foreach (DnsResourceRecord additional in additionals)
		{
			// A target of "." says that the service is not available (RFC 2782), so the root gets no addresses.
			if (additional is { Class: DnsClass.Internet, Name.IsRoot: false, Data: DnsAddressData { Address: var address } })
			{
				ref List<DnsAddressRecord>? list = ref CollectionsMarshal.GetValueRefOrAddDefault(addresses, additional.Name, out _);
				(list ??= []).Add(new DnsAddressRecord(IPAddressCopy.Of(address), additional.Ttl));
			}
		}

		foreach (List<DnsAddressRecord> list in addresses.Values)
		{
			TakeLeastTtlByFamily(CollectionsMarshal.AsSpan(list));
		}

		return addresses;
	}

	// RFC 2181, Sec. 5.2: the A records and the AAAA records of one owner are separate RRsets.
	private static void TakeLeastTtlByFamily(Span<DnsAddressRecord> addresses)
	{
		TimeSpan v4 = TimeSpan.MaxValue;
		TimeSpan v6 = TimeSpan.MaxValue;

		foreach (DnsAddressRecord address in addresses)
		{
			ref TimeSpan least = ref address.Address.AddressFamily is AddressFamily.InterNetwork ? ref v4 : ref v6;

			if (address.Ttl < least)
			{
				least = address.Ttl;
			}
		}

		foreach (ref DnsAddressRecord address in addresses)
		{
			address = address with { Ttl = address.Address.AddressFamily is AddressFamily.InterNetwork ? v4 : v6 };
		}
	}
}
