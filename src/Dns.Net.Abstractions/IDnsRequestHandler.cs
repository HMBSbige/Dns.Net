namespace Dns.Net.Abstractions;

/// <summary>
/// Defines the logic of a DNS server: it answers each request that a server transport receives.
/// </summary>
/// <remarks>
/// <para>
/// The server transport does what needs the bytes on the wire or the keys of the server; forwarding, caching and the like compose as handlers that wrap another handler.
/// Before the handler, it drops messages with the QR bit set, and answers a request that does not decode with <see cref="DnsMessage.CreateErrorResponse" />.
/// It takes the TSIG or SIG(0) record out of every request, sets <see cref="DnsRequestContext.Signer" /> to the principal it verified, and signs responses where needed; over UDP it truncates a response that does not fit.
/// </para>
/// <para>
/// The handler returns at most one response for each request, without a TSIG or SIG(0) record.
/// It also answers the errors the request calls for, such as BADVERS (RFC 6891, Sec. 6.1.3) or FORMERR for a QUERY with several questions (RFC 9619, Sec. 4).
/// Implementations must allow concurrent calls on one instance.
/// </para>
/// </remarks>
public interface IDnsRequestHandler
{
	/// <summary>
	/// Asynchronously answers a request.
	/// </summary>
	/// <remarks><see cref="DnsMessage.CreateResponse" /> starts a response with the fields that it must copy from the request.</remarks>
	/// <param name="context">The request and how it arrived.</param>
	/// <param name="cancellationToken">The token used to cancel the handling, such as when the server stops.</param>
	/// <returns>A value task whose result is the response to send, or <see langword="null" /> to send none.</returns>
	ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default);
}
