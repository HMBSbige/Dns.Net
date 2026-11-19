using System.Net;

namespace Dns.Net.Abstractions;

/// <summary>
/// Describes a request that a server received: the message, and how and where it arrived.
/// </summary>
/// <remarks>
/// A server transport may derive a context of its own to hand the handler what its protocol knows, such as the HTTP request; a handler that needs it tests for that type.
/// A handler that changes the request derives a context with <see langword="with" />, which keeps the derived type and <see cref="Signer" />.
/// </remarks>
/// <param name="Request">The request message.</param>
/// <param name="Protocol">The protocol that carried the request.</param>
/// <exception cref="ArgumentNullException"><paramref name="Request" /> is <see langword="null" />.</exception>
public record DnsRequestContext(DnsMessage Request, DnsProtocol Protocol)
{
	/// <summary>
	/// Gets the request message.
	/// </summary>
	/// <exception cref="ArgumentNullException">The value set is <see langword="null" />.</exception>
	public DnsMessage Request { get; init => field = CheckRequest(value); } = CheckRequest(Request);

	/// <summary>
	/// Gets the endpoint of the client, or <see langword="null" /> if the server transport does not know it.
	/// </summary>
	public EndPoint? RemoteEndPoint { get; init; }

	/// <summary>
	/// Gets the endpoint at which the server received the request, or <see langword="null" /> if the server transport does not know it.
	/// </summary>
	public EndPoint? LocalEndPoint { get; init; }

	/// <summary>
	/// Gets the principal of the signature that the server transport verified, or <see langword="null" /> if the request is unauthenticated.
	/// </summary>
	/// <remarks>Only the server transport sets it. The signature record is gone from <see cref="Request" />, so a handler authorizes the request by this property.</remarks>
	public DnsRequestSigner? Signer { get; init; }

	private static DnsMessage CheckRequest(DnsMessage request)
	{
		ArgumentNullException.ThrowIfNull(request, nameof(Request));
		return request;
	}
}
