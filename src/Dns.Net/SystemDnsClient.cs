using Dns.Net.Abstractions;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

namespace Dns.Net;

/// <summary>
/// Resolves records through the DNS resolver of .NET: <see cref="System.Net.Dns" /> with the servers that the system is configured with, or a <see cref="DnsResolver" /> with the given servers.
/// </summary>
/// <remarks>
/// <para>
/// Results and exceptions of the resolver come through as they are, and can differ between platforms; a timeout, for example, may come back as SERVFAIL.
/// Only <see cref="DnsQueryResult{T}.NegativeCacheTtl" /> is changed: it is zero for anything but NXDOMAIN and NODATA (RFC 2308, Sec. 5).
/// A name that the resolver rejects, such as one with a label longer than 63 bytes, is not checked at the call: depending on the platform, it fails the task or comes back with an error response code.
/// The client treats no name apart, onion included, but the resolver of the system may: that of Windows answers from the hosts file.
/// Names in results are labels joined by dots, without escapes, so <c>a\.b.example</c> comes back as <c>a.b.example</c>.
/// </para>
/// <para>
/// On Android, where .NET cannot find the servers of the system, a client created without options resolves through a <see cref="DnsClient" /> over an <see cref="AndroidDnsTransport" />, and results follow the rules of <see cref="DnsClient" />, except that SERVFAIL, NOTIMP and REFUSED over UDP throw <see cref="IOException" />, as <see cref="AndroidDnsTransport" /> describes.
/// </para>
/// </remarks>
[UnsupportedOSPlatform("browser")]
[UnsupportedOSPlatform("wasi")]
public sealed class SystemDnsClient : IDnsClient, IDisposable, IAsyncDisposable
{
	// null for the static methods of System.Net.Dns, and on Android.
	private readonly DnsResolver? _resolver;

	private readonly DnsClient? _android;

	private volatile bool _disposed;

	/// <summary>
	/// Initializes a client that resolves with the servers that the system is configured with.
	/// </summary>
	/// <remarks>Before Android 10 (API level 29), each query throws <see cref="PlatformNotSupportedException" /> at the call.</remarks>
	[UnsupportedOSPlatform("android")]
	[SupportedOSPlatform("android29.0")]
	public SystemDnsClient()
	{
		if (OperatingSystem.IsAndroidVersionAtLeast(29))
		{
			_android = new DnsClient(new AndroidDnsTransport()) { QueriesOnionNames = true };
		}
	}

	/// <summary>
	/// Initializes a client that resolves through a new <see cref="DnsResolver" /> with <paramref name="options" />, which the client owns and disposes.
	/// </summary>
	/// <remarks>
	/// Exceptions of the constructor of <see cref="DnsResolver" /> come through as they are.
	/// On Android, empty <see cref="DnsResolverOptions.Servers" /> throw <see cref="PlatformNotSupportedException" />.
	/// </remarks>
	/// <param name="options">The options of the resolver; empty <see cref="DnsResolverOptions.Servers" /> stand for those of the system.</param>
	/// <exception cref="ArgumentNullException"><paramref name="options" /> is <see langword="null" />.</exception>
	public SystemDnsClient(DnsResolverOptions options)
	{
		ArgumentNullException.ThrowIfNull(options);

		_resolver = new DnsResolver(options);
	}

	/// <inheritdoc />
	/// <exception cref="ObjectDisposedException">The client is disposed.</exception>
	public ValueTask<DnsQueryResult<DnsAddressRecord>> ResolveAddressesAsync(string name, AddressFamily addressFamily, CancellationToken cancellationToken = default)
	{
		ArgumentException.ThrowIfNullOrEmpty(name);
		QueryArguments.CheckAddressFamily(addressFamily);
		CheckNullCharacter(name);
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (_android is not null)
		{
			return _android.ResolveAddressesAsync(name, addressFamily, cancellationToken);
		}

		Task<DnsResult<AddressRecord>> query = _resolver is null
			? System.Net.Dns.ResolveAddressesAsync(name, addressFamily, cancellationToken)
			: _resolver.ResolveAddressesAsync(name, addressFamily, cancellationToken);

		return MapAsync(query, ToQueryResult);
	}

	/// <inheritdoc />
	/// <exception cref="ObjectDisposedException">The client is disposed.</exception>
	/// <exception cref="NotSupportedException"><typeparamref name="TRecord" /> is none of the record types of the resolver of .NET.</exception>
	public ValueTask<DnsQueryResult<TRecord>> ResolveAsync<TRecord>(string name, CancellationToken cancellationToken = default) where TRecord : IDnsQueryRecord<TRecord>
	{
		ArgumentException.ThrowIfNullOrEmpty(name);
		CheckNullCharacter(name);
		ObjectDisposedException.ThrowIf(_disposed, this);

		// Also on Android, so that what resolves does not depend on the platform.
		if (!IsResolverType<TRecord>())
		{
			throw new NotSupportedException($"The resolver of .NET does not resolve records of the type {typeof(TRecord)}.");
		}

		if (_android is not null)
		{
			return _android.ResolveAsync<TRecord>(name, cancellationToken);
		}

		// For a value type, each comparison is a constant in the code compiled for TRecord.
		if (typeof(TRecord) == typeof(DnsSrvRecord))
		{
			return MapAsync<SrvRecord, DnsSrvRecord, TRecord>(_resolver?.ResolveSrvAsync(name, cancellationToken) ?? System.Net.Dns.ResolveSrvAsync(name, cancellationToken), ToQueryResult);
		}

		if (typeof(TRecord) == typeof(DnsMxRecord))
		{
			return MapAsync<MxRecord, DnsMxRecord, TRecord>(_resolver?.ResolveMxAsync(name, cancellationToken) ?? System.Net.Dns.ResolveMxAsync(name, cancellationToken), ToQueryResult);
		}

		if (typeof(TRecord) == typeof(DnsTxtRecord))
		{
			return MapAsync<TxtRecord, DnsTxtRecord, TRecord>(_resolver?.ResolveTxtAsync(name, cancellationToken) ?? System.Net.Dns.ResolveTxtAsync(name, cancellationToken), ToQueryResult);
		}

		if (typeof(TRecord) == typeof(DnsCNameRecord))
		{
			return MapAsync<CNameRecord, DnsCNameRecord, TRecord>(_resolver?.ResolveCNameAsync(name, cancellationToken) ?? System.Net.Dns.ResolveCNameAsync(name, cancellationToken), ToQueryResult);
		}

		if (typeof(TRecord) == typeof(DnsPtrRecord))
		{
			return MapAsync<PtrRecord, DnsPtrRecord, TRecord>(_resolver?.ResolvePtrAsync(name, cancellationToken) ?? System.Net.Dns.ResolvePtrAsync(name, cancellationToken), ToQueryResult);
		}

		if (typeof(TRecord) == typeof(DnsNsRecord))
		{
			return MapAsync<NsRecord, DnsNsRecord, TRecord>(_resolver?.ResolveNsAsync(name, cancellationToken) ?? System.Net.Dns.ResolveNsAsync(name, cancellationToken), ToQueryResult);
		}

		throw new UnreachableException();
	}

	/// <summary>
	/// Disposes the client, and the <see cref="DnsResolver" /> that it owns, if any.
	/// </summary>
	/// <remarks>Queries already started run to their end.</remarks>
	public void Dispose()
	{
		_disposed = true;
		_resolver?.Dispose();
	}

	/// <summary>
	/// Asynchronously disposes the client, and the <see cref="DnsResolver" /> that it owns, if any.
	/// </summary>
	/// <returns>A value task that completes when the client is disposed.</returns>
	public ValueTask DisposeAsync()
	{
		_disposed = true;
		return _resolver?.DisposeAsync() ?? ValueTask.CompletedTask;
	}

	private static bool IsResolverType<TRecord>()
	{
		return typeof(TRecord) == typeof(DnsSrvRecord)
			|| typeof(TRecord) == typeof(DnsMxRecord)
			|| typeof(TRecord) == typeof(DnsTxtRecord)
			|| typeof(TRecord) == typeof(DnsCNameRecord)
			|| typeof(TRecord) == typeof(DnsPtrRecord)
			|| typeof(TRecord) == typeof(DnsNsRecord);
	}

	// The resolver of Windows would end the name at a null character and query only the part before it.
	private static void CheckNullCharacter(string name)
	{
		if (name.Contains('\0'))
		{
			throw new ArgumentException("The name has a null character.", nameof(name));
		}
	}

	internal static DnsQueryResult<DnsAddressRecord> ToQueryResult(DnsResult<AddressRecord> result)
	{
		return Map(result, static record => new DnsAddressRecord(record.Address, record.Ttl));
	}

	internal static DnsQueryResult<DnsSrvRecord> ToQueryResult(DnsResult<SrvRecord> result)
	{
		Dictionary<IReadOnlyList<AddressRecord>, DnsAddressRecord[]>? mapped = null;
		return Map(result, record => new DnsSrvRecord(record.Target, record.Port, record.Priority, record.Weight, record.Ttl, ToAddressRecords(record.Addresses, ref mapped)));
	}

	internal static DnsQueryResult<DnsMxRecord> ToQueryResult(DnsResult<MxRecord> result)
	{
		return Map(result, static record => new DnsMxRecord(record.Exchange, record.Preference, record.Ttl));
	}

	internal static DnsQueryResult<DnsTxtRecord> ToQueryResult(DnsResult<TxtRecord> result)
	{
		return Map(result, static record => new DnsTxtRecord(record.Values, record.Ttl));
	}

	internal static DnsQueryResult<DnsCNameRecord> ToQueryResult(DnsResult<CNameRecord> result)
	{
		return Map(result, static record => new DnsCNameRecord(record.CanonicalName, record.Ttl));
	}

	internal static DnsQueryResult<DnsPtrRecord> ToQueryResult(DnsResult<PtrRecord> result)
	{
		return Map(result, static record => new DnsPtrRecord(record.Name, record.Ttl));
	}

	internal static DnsQueryResult<DnsNsRecord> ToQueryResult(DnsResult<NsRecord> result)
	{
		return Map(result, static record => new DnsNsRecord(record.Name, record.Ttl));
	}

	private static async ValueTask<DnsQueryResult<TResult>> MapAsync<TSource, TResult>(Task<DnsResult<TSource>> query, Func<DnsResult<TSource>, DnsQueryResult<TResult>> map)
	{
		return map(await query.ConfigureAwait(false));
	}

	// TRecord is TResult, which the compiler cannot see.
	private static ValueTask<DnsQueryResult<TRecord>> MapAsync<TSource, TResult, TRecord>(Task<DnsResult<TSource>> query, Func<DnsResult<TSource>, DnsQueryResult<TResult>> map)
	{
		Debug.Assert(typeof(TResult) == typeof(TRecord));

		ValueTask<DnsQueryResult<TResult>> mapped = MapAsync(query, map);
		return Unsafe.As<ValueTask<DnsQueryResult<TResult>>, ValueTask<DnsQueryResult<TRecord>>>(ref mapped);
	}

	private static DnsQueryResult<TResult> Map<TSource, TResult>(DnsResult<TSource> result, Func<TSource, TResult> map)
	{
		IReadOnlyList<TSource> source = result.Records;
		TResult[] records = new TResult[source.Count];

		for (int i = 0; i < records.Length; ++i)
		{
			records[i] = map(source[i]);
		}

		return new DnsQueryResult<TResult>(result.ResponseCode, records, NegativeCaching.Limit(result.ResponseCode, records.Length, result.NegativeCacheTtl));
	}

	// Maps each list once, by reference, so that SRV records that share a list of the resolver, as those with the same target do, share one array.
	private static DnsAddressRecord[] ToAddressRecords(IReadOnlyList<AddressRecord> source, ref Dictionary<IReadOnlyList<AddressRecord>, DnsAddressRecord[]>? mapped)
	{
		if (source.Count is 0)
		{
			return [];
		}

		mapped ??= new(ReferenceEqualityComparer.Instance);

		if (mapped.TryGetValue(source, out DnsAddressRecord[]? addresses))
		{
			return addresses;
		}

		addresses = new DnsAddressRecord[source.Count];

		for (int i = 0; i < addresses.Length; ++i)
		{
			addresses[i] = new DnsAddressRecord(source[i].Address, source[i].Ttl);
		}

		mapped.Add(source, addresses);
		return addresses;
	}
}
