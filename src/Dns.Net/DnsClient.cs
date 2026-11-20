using Dns.Net.Abstractions;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace Dns.Net;

/// <summary>
/// Resolves records through any <see cref="IDnsTransport" />: builds the queries, follows CNAME chains, takes negative-cache TTLs from the SOA record (RFC 2308) and the addresses of SRV targets from the additional section.
/// </summary>
/// <remarks>
/// <para>The client neither owns nor disposes the transport, and allows concurrent calls whenever the transport does.</para>
/// <para>
/// A name is absolute: no search domain is appended. A name that is not ASCII is converted with <see cref="IdnMapping" /> under the STD3 rules, so a label with an underscore is valid only in an ASCII name.
/// Names in results keep the escapes of <see cref="DnsName.ToString" />, except that a name with an <c>xn--</c> label is converted to Unicode.
/// </para>
/// <para>
/// The client is a stub resolver: it expects a recursive resolver behind the transport and follows no referral.
/// It follows a CNAME chain only within the answer section (RFC 1034, Sec. 3.6.2); a loop or a chain of more than 16 CNAME records gives <see cref="DnsResponseCode.ServerFailure" />.
/// A response that does not answer the query or is truncated throws <see cref="InvalidDataException" />; exceptions of the transport come through as they are.
/// </para>
/// </remarks>
/// <param name="transport">The transport that sends the queries.</param>
/// <exception cref="ArgumentNullException"><paramref name="transport" /> is <see langword="null" />.</exception>
public sealed class DnsClient(IDnsTransport transport) : IDnsClient
{
	// Also bounds the work on a chain that loops.
	private const int MaxCNameRecords = 16;

	private delegate T[] RecordFactory<out T>(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response);

	/// <summary>
	/// Gets the transport that sends the queries, which the client does not own.
	/// </summary>
	public IDnsTransport Transport { get; } = transport ?? throw new ArgumentNullException(nameof(transport));

	/// <summary>
	/// Gets a value that indicates whether the client queries the special-use name <c>onion</c> and the names below it (RFC 7686) as it does any other name.
	/// </summary>
	/// <remarks>
	/// With <see langword="false" />, the default, such a name gets <see cref="DnsResponseCode.NxDomain" /> without a query (RFC 7686, Sec. 2).
	/// Set it to <see langword="true" /> when the transport goes to the DNSPort of Tor.
	/// </remarks>
	public bool QueriesOnionNames { get; init; }

	/// <inheritdoc />
	/// <exception cref="InvalidDataException">The response does not answer the query, or is truncated.</exception>
	public ValueTask<DnsQueryResult<DnsAddressRecord>> ResolveAddressesAsync(string name, AddressFamily addressFamily, CancellationToken cancellationToken = default)
	{
		QueryArguments.CheckName(name);
		QueryArguments.CheckAddressFamily(addressFamily);
		DnsName dnsName = ParseName(name);

		if (SkipsQuery(dnsName))
		{
			return OnionNames.NxDomain<DnsAddressRecord>(cancellationToken);
		}

		return addressFamily switch
		{
			AddressFamily.InterNetwork => ResolveCoreAsync(dnsName, DnsRecordType.A, CreateAddressRecords, cancellationToken),
			AddressFamily.InterNetworkV6 => ResolveCoreAsync(dnsName, DnsRecordType.Aaaa, CreateAddressRecords, cancellationToken),
			_ => ResolveBothFamiliesAsync(dnsName, cancellationToken)
		};
	}

	/// <inheritdoc />
	/// <remarks>
	/// Character strings of <see cref="DnsTxtRecord" /> are decoded with <see cref="Encoding.UTF8" />, with U+FFFD for an invalid sequence.
	/// For <see cref="DnsCNameRecord" />, the client does not follow the chain, and returns only the records owned by the name asked about.
	/// </remarks>
	/// <exception cref="NotSupportedException"><see cref="IDnsQueryRecord{TSelf}.Type" /> of <typeparamref name="TRecord" /> is OPT or 128 to 255.</exception>
	/// <exception cref="InvalidDataException">The response does not answer the query, or is truncated.</exception>
	/// <exception cref="InvalidOperationException"><see cref="IDnsQueryRecord{TSelf}.CreateRecords" /> of <typeparamref name="TRecord" /> returned <see langword="null" />.</exception>
	public ValueTask<DnsQueryResult<TRecord>> ResolveAsync<TRecord>(string name, CancellationToken cancellationToken = default) where TRecord : IDnsQueryRecord<TRecord>
	{
		QueryArguments.CheckName(name);
		DnsName dnsName = ParseName(name);
		DnsRecordType type = TRecord.Type;

		if (type is DnsRecordType.Opt or >= (DnsRecordType)128 and <= DnsRecordType.Any)
		{
			throw new NotSupportedException($"The record type {type} of {typeof(TRecord)} is a QTYPE or meta-type.");
		}

		return SkipsQuery(dnsName) ? OnionNames.NxDomain<TRecord>(cancellationToken) : ResolveCoreAsync(dnsName, type, TRecord.CreateRecords, cancellationToken);
	}

	private bool SkipsQuery(DnsName name)
	{
		return !QueriesOnionNames && SpecialUseNames.IsOnion(name);
	}

	private static DnsName ParseName(string name)
	{
		if (InternationalNames.ToAscii(name) is not { } ascii)
		{
			throw new ArgumentException("The name is not a valid internationalized domain name.", nameof(name));
		}

		return DnsName.TryParse(ascii, out DnsName result) ? result : throw new ArgumentException("The name is not a valid domain name in presentation format.", nameof(name));
	}

	private async ValueTask<DnsQueryResult<DnsAddressRecord>> ResolveBothFamiliesAsync(DnsName name, CancellationToken cancellationToken)
	{
		Task<DnsQueryResult<DnsAddressRecord>> a = ResolveCoreAsync(name, DnsRecordType.A, CreateAddressRecords, cancellationToken).AsTask();
		Task<DnsQueryResult<DnsAddressRecord>> aaaa = ResolveCoreAsync(name, DnsRecordType.Aaaa, CreateAddressRecords, cancellationToken).AsTask();

		await Task.WhenAll(a, aaaa).ConfigureAwait(false);

		return AddressResults.Merge(await a.ConfigureAwait(false), await aaaa.ConfigureAwait(false));
	}

	private async ValueTask<DnsQueryResult<T>> ResolveCoreAsync<T>(DnsName name, DnsRecordType type, RecordFactory<T> createRecords, CancellationToken cancellationToken)
	{
		DnsMessage query = DnsMessage.CreateQuery(new DnsQuestion(name, type));
		DnsMessage response = await Transport.SendAsync(query, cancellationToken).ConfigureAwait(false);

		if (!response.IsResponseTo(query))
		{
			throw new InvalidDataException("The transport returned a message that does not answer the query.");
		}

		if (response.IsTruncated)
		{
			throw new InvalidDataException("The transport returned a truncated response, which it must retry over a stream transport instead.");
		}

		if (response.ResponseCode is not DnsResponseCode.NoError)
		{
			return CreateEmptyResult<T>(response.ResponseCode, response);
		}

		T[]? records = FollowCNameChain(response, name, type, createRecords);

		if (records is null)
		{
			return new DnsQueryResult<T>(DnsResponseCode.ServerFailure, [], TimeSpan.Zero);
		}

		if (records.Length is 0)
		{
			return CreateEmptyResult<T>(DnsResponseCode.NoError, response);
		}

		return new DnsQueryResult<T>(DnsResponseCode.NoError, records, TimeSpan.Zero);
	}

	// Returns empty for NODATA, or null for a loop or a chain that is too long.
	// Each step reads the answer section once, so that the whole is linear in the size of the response.
	private static T[]? FollowCNameChain<T>(DnsMessage response, DnsName name, DnsRecordType type, RecordFactory<T> createRecords)
	{
		List<DnsResourceRecord>? rrset = null;
		List<DnsName>? owners = null;
		DnsName owner = name;

		for (int followed = 0; ; ++followed)
		{
			TimeSpan ttl = TimeSpan.MaxValue;
			DnsName? next = null;
			rrset?.Clear();

			foreach (DnsResourceRecord answer in response.Answers)
			{
				if (answer.Class is not DnsClass.Internet || answer.Name != owner)
				{
					continue;
				}

				if (answer.Type == type)
				{
					(rrset ??= []).Add(answer);
					ttl = answer.Ttl < ttl ? answer.Ttl : ttl;
				}
				else if (next is null && answer.Data is DnsCNameData cname)
				{
					next = cname.CanonicalName;
				}
			}

			if (rrset is { Count: not 0 })
			{
				T[] records = createRecords(CollectionsMarshal.AsSpan(rrset), ttl, response) ?? throw new InvalidOperationException($"CreateRecords of {typeof(T)} returned null.");

				if (records.Length is not 0)
				{
					return records;
				}
			}

			if (next is not { } target)
			{
				return [];
			}

			// An owner seen before would repeat the same steps until the limit.
			owners ??= [name];

			if (followed == MaxCNameRecords || owners.Contains(target))
			{
				return null;
			}

			owners.Add(target);
			owner = target;
		}
	}

	// RFC 2308, Sec. 5.
	private static DnsQueryResult<T> CreateEmptyResult<T>(DnsResponseCode responseCode, DnsMessage response)
	{
		TimeSpan ttl = TimeSpan.Zero;

		foreach (DnsResourceRecord authority in response.Authorities)
		{
			if (authority is { Class: DnsClass.Internet, Data: DnsSoaData soa })
			{
				ttl = authority.Ttl < soa.Minimum ? authority.Ttl : soa.Minimum;
				break;
			}
		}

		return new DnsQueryResult<T>(responseCode, [], NegativeCaching.Limit(responseCode, recordCount: 0, ttl));
	}

	private static DnsAddressRecord[] CreateAddressRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		return QueryRecords.Create<DnsAddressRecord>(answers, ttl, static (data, recordTtl) => data is DnsAddressData { Address: var address } ? new DnsAddressRecord(IPAddressCopy.Of(address), recordTtl) : null);
	}
}
