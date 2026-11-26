namespace Dns.Net.Abstractions;

/// <summary>
/// Provides queries built from a question, or from a name and a type, for any <see cref="IDnsTransport" />.
/// </summary>
public static class DnsTransportExtensions
{
	/// <param name="transport">The transport that sends the query.</param>
	extension(IDnsTransport transport)
	{
		/// <summary>
		/// Asynchronously asks <paramref name="question" /> in a query that <see cref="DnsMessage.CreateQuery" /> creates, and returns the response.
		/// </summary>
		/// <param name="question">The question to ask.</param>
		/// <param name="cancellationToken">The token used to cancel the exchange.</param>
		/// <returns>A value task whose result is the response, whatever its response code.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="transport" /> is <see langword="null" />.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask<DnsMessage> QueryAsync(DnsQuestion question, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(transport);

			return transport.SendAsync(DnsMessage.CreateQuery(question), cancellationToken);
		}

		/// <summary>
		/// Asynchronously asks for the records of <paramref name="type" /> and class IN at <paramref name="name" />, in a query that <see cref="DnsMessage.CreateQuery" /> creates, and returns the response.
		/// </summary>
		/// <param name="name">The name in presentation format, as <see cref="DnsName.Parse(string)" /> accepts it.</param>
		/// <param name="type">The type of the records asked for.</param>
		/// <param name="cancellationToken">The token used to cancel the exchange.</param>
		/// <returns>A value task whose result is the response, whatever its response code.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="transport" /> or <paramref name="name" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="name" /> is not a valid name in presentation format.</exception>
		/// <exception cref="OperationCanceledException"><paramref name="cancellationToken" /> was canceled.</exception>
		public ValueTask<DnsMessage> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(transport);
			ArgumentNullException.ThrowIfNull(name);

			if (!DnsName.TryParse(name, out DnsName dnsName))
			{
				throw new ArgumentException("The name is not a valid domain name in presentation format.", nameof(name));
			}

			return transport.SendAsync(DnsMessage.CreateQuery(new DnsQuestion(dnsName, type)), cancellationToken);
		}
	}
}
