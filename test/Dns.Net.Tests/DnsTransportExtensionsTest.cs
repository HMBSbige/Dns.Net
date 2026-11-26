using Dns.Net.Abstractions;
using System.Net;

namespace Dns.Net.Tests;

public class DnsTransportExtensionsTest
{
	[Test]
	public async Task QueryAsyncSendsTheQueryThatCreateQueryBuilds(CancellationToken cancellationToken)
	{
		DnsQuestion question = new(DnsName.Parse("example.com"), DnsRecordType.Https);
		DnsMessage canned = new() { IsResponse = true, ResponseCode = DnsResponseCode.NxDomain };
		RecordingTransport transport = new(canned);

		DnsMessage byName = await transport.QueryAsync("Example.com.", DnsRecordType.Https, cancellationToken);
		DnsMessage byQuestion = await transport.QueryAsync(question, cancellationToken);

		// A DNS error comes back as the response, not as an exception.
		await Assert.That(byName).IsSameReferenceAs(canned);
		await Assert.That(byQuestion).IsSameReferenceAs(canned);
		await Assert.That(transport.Queries.Count).IsEqualTo(2);
		await Assert.That(transport.Queries[0]).IsEqualTo(DnsMessage.CreateQuery(question));
		await Assert.That(transport.Queries[0].Questions[0].Name.ToString()).IsEqualTo("Example.com");
		await Assert.That(transport.Queries[1]).IsEqualTo(DnsMessage.CreateQuery(question));
		await Assert.That(transport.Tokens).IsEquivalentTo([cancellationToken, cancellationToken]);
	}

	[Test]
	public async Task QueryAsyncRejectsAnInvalidNameBeforeSending()
	{
		RecordingTransport transport = new(new DnsMessage());

		await Assert.That(() => { _ = transport.QueryAsync("a..b", DnsRecordType.A); }).ThrowsExactly<ArgumentException>().WithParameterName("name");
		await Assert.That(transport.Queries).IsEmpty();
	}

	[Test]
	public async Task QueryAsyncRejectsNullArguments()
	{
		RecordingTransport transport = new(new DnsMessage());
		IDnsTransport? missing = null;

		await Assert.That(() => { _ = transport.QueryAsync(null!, DnsRecordType.A); }).Throws<ArgumentNullException>().WithParameterName("name");
		await Assert.That(() => { _ = missing!.QueryAsync("example.com", DnsRecordType.A); }).Throws<ArgumentNullException>().WithParameterName("transport");
		await Assert.That(() => { _ = missing!.QueryAsync(new DnsQuestion(DnsName.Root, DnsRecordType.Ns)); }).Throws<ArgumentNullException>().WithParameterName("transport");
	}

	// Records the queries and answers each with the same response.
	private sealed class RecordingTransport(DnsMessage response) : IDnsTransport
	{
		public List<DnsMessage> Queries { get; } = [];

		public List<CancellationToken> Tokens { get; } = [];

		public ValueTask<DnsMessage> SendAsync(DnsMessage query, CancellationToken cancellationToken = default)
		{
			Queries.Add(query);
			Tokens.Add(cancellationToken);
			return ValueTask.FromResult(response);
		}
	}
}
