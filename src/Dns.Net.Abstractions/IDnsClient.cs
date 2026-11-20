using System.Net;
using System.Net.Sockets;

namespace Dns.Net.Abstractions;

/// <summary>
/// Defines a client that resolves the records of one type at one name, with results shaped like <see cref="System.Net.DnsResult{T}" />.
/// </summary>
/// <remarks>
/// <para>
/// An outcome of DNS, such as NXDOMAIN or SERVFAIL, comes back in <see cref="DnsQueryResult{T}.ResponseCode" />; each implementation documents its exceptions.
/// Names in results have no trailing dot, and the root is <c>"."</c>.
/// </para>
/// <para>Arguments are checked before the value task is returned. Implementations must allow concurrent calls on one instance.</para>
/// </remarks>
public interface IDnsClient
{
	/// <summary>
	/// Asynchronously resolves the IPv4 addresses (A records), the IPv6 addresses (AAAA records), or both, of a host.
	/// </summary>
	/// <remarks>
	/// With <see cref="AddressFamily.Unspecified" />, the A and AAAA queries go out together, either failing fails the whole, and the result lists the A records before the AAAA records.
	/// Without records, the response code is NXDOMAIN if either query got it, else the first that is not <see cref="DnsResponseCode.NoError" />.
	/// </remarks>
	/// <param name="name">The host name.</param>
	/// <param name="addressFamily"><see cref="AddressFamily.InterNetwork" /> for A records, <see cref="AddressFamily.InterNetworkV6" /> for AAAA records, or <see cref="AddressFamily.Unspecified" /> for both.</param>
	/// <param name="cancellationToken">The token used to cancel the queries.</param>
	/// <returns>A value task whose result holds the address records, in the order of the response.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="name" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="name" /> is empty, or not a valid name for the implementation.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="addressFamily" /> is not <see cref="AddressFamily.Unspecified" />, <see cref="AddressFamily.InterNetwork" /> or <see cref="AddressFamily.InterNetworkV6" />.</exception>
	/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
	ValueTask<DnsQueryResult<DnsAddressRecord>> ResolveAddressesAsync(string name, AddressFamily addressFamily, CancellationToken cancellationToken = default);

	/// <summary>
	/// Asynchronously resolves the records of type <typeparamref name="TRecord" /> of a name.
	/// </summary>
	/// <typeparam name="TRecord">The type of the records, whose <see cref="IDnsQueryRecord{TSelf}.Type" /> the query asks for.</typeparam>
	/// <param name="name">The name.</param>
	/// <param name="cancellationToken">The token used to cancel the query.</param>
	/// <returns>A value task whose result holds the records, in the order of the response.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="name" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="name" /> is empty, or not a valid name for the implementation.</exception>
	/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
	ValueTask<DnsQueryResult<TRecord>> ResolveAsync<TRecord>(string name, CancellationToken cancellationToken = default) where TRecord : IDnsQueryRecord<TRecord>;
}
