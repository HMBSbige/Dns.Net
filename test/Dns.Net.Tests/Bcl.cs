using System.Net;
using System.Runtime.CompilerServices;

namespace Dns.Net.Tests;

// Builds System.Net.DnsResolver records and results, whose constructors are internal.
internal static class Bcl
{
	[UnsafeAccessor(UnsafeAccessorKind.Constructor)]
	public static extern AddressRecord NewAddressRecord(IPAddress address, TimeSpan ttl);

	[UnsafeAccessor(UnsafeAccessorKind.Constructor)]
	public static extern SrvRecord NewSrvRecord(string target, ushort port, ushort priority, ushort weight, TimeSpan ttl, IReadOnlyList<AddressRecord>? addresses);

	[UnsafeAccessor(UnsafeAccessorKind.Constructor)]
	public static extern MxRecord NewMxRecord(string exchange, ushort preference, TimeSpan ttl);

	[UnsafeAccessor(UnsafeAccessorKind.Constructor)]
	public static extern TxtRecord NewTxtRecord(IReadOnlyList<string> values, TimeSpan ttl);

	[UnsafeAccessor(UnsafeAccessorKind.Constructor)]
	public static extern CNameRecord NewCNameRecord(string canonicalName, TimeSpan ttl);

	[UnsafeAccessor(UnsafeAccessorKind.Constructor)]
	public static extern PtrRecord NewPtrRecord(string name, TimeSpan ttl);

	[UnsafeAccessor(UnsafeAccessorKind.Constructor)]
	public static extern NsRecord NewNsRecord(string name, TimeSpan ttl);

	public static DnsResult<T> NewResult<T>(DnsResponseCode responseCode, IReadOnlyList<T>? records, TimeSpan negativeCacheTtl)
	{
		return Results<T>.New(responseCode, records, negativeCacheTtl);
	}

	// A constructor accessor for a generic type must sit in a generic class.
	private static class Results<T>
	{
		[UnsafeAccessor(UnsafeAccessorKind.Constructor)]
		public static extern DnsResult<T> New(DnsResponseCode responseCode, IReadOnlyList<T>? records, TimeSpan negativeCacheTtl);
	}
}
