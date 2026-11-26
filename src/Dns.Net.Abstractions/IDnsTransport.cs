namespace Dns.Net.Abstractions;

/// <summary>
/// Defines a transport that sends a query to a server and returns its response, such as over UDP, TCP, TLS, HTTPS or QUIC.
/// </summary>
/// <remarks>
/// The transport returns only the complete response that answers the query, as <see cref="DnsMessage.IsResponseTo" /> determines, whatever identifier it used on the wire.
/// An outcome of DNS, such as NXDOMAIN, comes back in <see cref="DnsMessage.ResponseCode" />; only a failure of the transport throws.
/// Implementations must allow concurrent calls on one instance.
/// </remarks>
public interface IDnsTransport
{
	/// <summary>
	/// Asynchronously sends <paramref name="query" /> and returns the response, with the <see cref="DnsMessage.Id" /> of <paramref name="query" />.
	/// </summary>
	/// <param name="query">The query.</param>
	/// <param name="cancellationToken">The token used to cancel the exchange.</param>
	/// <returns>A value task whose result is the response.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="query" /> is <see langword="null" />.</exception>
	/// <exception cref="InvalidOperationException"><paramref name="query" /> cannot be encoded.</exception>
	/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
	ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default);
}
