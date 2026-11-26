using Dns.Net.Abstractions;
using System.Net;

namespace Dns.Net.Tests;

public class DnsRequestHandlerTest
{
	[Test]
	public async Task WithKeepsTheDerivedContextAndTheSigner()
	{
		DnsMessage request = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A)) with { Id = 7 };
		DnsRequestSigner signer = new(DnsRecordType.Tsig, DnsName.Parse("key.example"));
		DnsRequestContext context = new TenantRequestContext(request, "t1") { Signer = signer };

		DnsRequestContext changed = context with { Request = request with { Id = 42 } };

		await Assert.That(changed).IsEqualTo(new TenantRequestContext(request with { Id = 42 }, "t1") { Signer = signer });
		await Assert.That(() => new DnsRequestContext(null!, DnsProtocol.Udp)).Throws<ArgumentNullException>().WithParameterName("Request");
		await Assert.That(() => context with { Request = null! }).Throws<ArgumentNullException>().WithParameterName("Request");
	}

	[Test]
	public async Task ASignerIsATsigKeyOrASig0Signer()
	{
		DnsName key = DnsName.Parse("key.example");

		await Assert.That(new DnsRequestSigner(DnsRecordType.Tsig, key).Type).IsEqualTo(DnsRecordType.Tsig);
		await Assert.That(new DnsRequestSigner(DnsRecordType.Sig, key).Type).IsEqualTo(DnsRecordType.Sig);
		await Assert.That(() => new DnsRequestSigner(DnsRecordType.DnsKey, key)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("Type");
		await Assert.That(() => new DnsRequestSigner(DnsRecordType.Tsig, key) with { Type = DnsRecordType.A }).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("Type");
	}

	[Test]
	public async Task TheQueryOnlyHandlerOfTheReadmeAnswersAnUnknownEdnsVersionWithBadVers(CancellationToken cancellationToken)
	{
		// RFC 6891, Sec. 6.1.3: BADVERS with an OPT record of version 0.
		DnsMessage request = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A)) with { Id = 99, Edns = new DnsEdns { Version = 1, DnssecOk = true } };
		QueryOnlyHandler handler = new(new LoopbackHandler());

		DnsMessage? response = await handler.HandleAsync(new DnsRequestContext(request, DnsProtocol.Udp), cancellationToken);

		await Assert.That(response).IsEqualTo(request.CreateResponse() with { ResponseCode = (DnsResponseCode)16 });
		await Assert.That(response?.Edns).IsEqualTo(new DnsEdns { DnssecOk = true });

		// Version 0 goes on to the inner handler.
		DnsMessage? answered = await handler.HandleAsync(new DnsRequestContext(request with { Edns = new DnsEdns() }, DnsProtocol.Udp), cancellationToken);
		await Assert.That(answered?.ResponseCode).IsEqualTo(DnsResponseCode.NoError);
		await Assert.That(answered?.Answers).HasSingleItem();
	}

	[Test]
	public async Task TheQueryOnlyHandlerOfTheReadmeAnswersAQueryWithTwoQuestionsWithFormErrWhateverItsEdnsVersion(CancellationToken cancellationToken)
	{
		// RFC 9619, Sec. 4: FORMERR without the questions.
		DnsMessage request = new()
		{
			Id = 99,
			Questions = [new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A), new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.Aaaa)],
			Edns = new DnsEdns { Version = 1 }
		};

		DnsMessage? response = await new QueryOnlyHandler(new LoopbackHandler()).HandleAsync(new DnsRequestContext(request, DnsProtocol.Udp), cancellationToken);

		await Assert.That(response).IsEqualTo(request.CreateResponse() with { ResponseCode = DnsResponseCode.FormatError, Questions = [] });
	}

	[Test]
	public async Task TheQueryOnlyHandlerOfTheReadmeAnswersAnUnknownOpcodeWithNotImp(CancellationToken cancellationToken)
	{
		// RFC 8906, Sec. 8.1.4: a header-only request with opcode 15.
		DnsMessage request = DnsMessage.Decode((byte[])[0x12, 0x34, 0x78, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);

		DnsMessage? response = await new QueryOnlyHandler(new LoopbackHandler()).HandleAsync(new DnsRequestContext(request, DnsProtocol.Udp), cancellationToken);

		await Assert.That(response).IsEqualTo(new DnsMessage { Id = 0x1234, IsResponse = true, Opcode = (DnsOpcode)15, ResponseCode = DnsResponseCode.NotImplemented });
	}

	// The QueryOnlyHandler of the README.
	private sealed class QueryOnlyHandler(IDnsRequestHandler inner) : IDnsRequestHandler
	{
		// BADVERS, which DnsResponseCode does not name.
		private const DnsResponseCode BadVersion = (DnsResponseCode)16;

		public ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default)
		{
			DnsMessage request = context.Request;

			// FORMERR without the questions, even before BADVERS (RFC 9619, Sec. 4).
			if (request is { Opcode: DnsOpcode.Query, Questions.Count: > 1 })
			{
				return ValueTask.FromResult<DnsMessage?>(request.CreateResponse() with { ResponseCode = DnsResponseCode.FormatError, Questions = [] });
			}

			// BADVERS for any EDNS version above 0 (RFC 6891, Sec. 6.1.3).
			if (request.Edns is { Version: > 0 })
			{
				return ValueTask.FromResult<DnsMessage?>(request.CreateResponse() with { ResponseCode = BadVersion });
			}

			if (request.Opcode is not DnsOpcode.Query)
			{
				return ValueTask.FromResult<DnsMessage?>(request.CreateResponse() with { ResponseCode = DnsResponseCode.NotImplemented });
			}

			return inner.HandleAsync(context, cancellationToken);
		}
	}

	// The LoopbackHandler of the README.
	private sealed class LoopbackHandler : IDnsRequestHandler
	{
		public ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default)
		{
			DnsMessage request = context.Request;

			DnsMessage response = request.CreateResponse() with
			{
				Answers = [.. request.Questions.Where(static q => q is { Type: DnsRecordType.A, Class: DnsClass.Internet }).Select(static q => new DnsResourceRecord(q.Name, TimeSpan.FromMinutes(5), new DnsAddressData(IPAddress.Loopback)))]
			};

			return ValueTask.FromResult<DnsMessage?>(response);
		}
	}

	// Extra data a DoH server transport could add, such as a tenant.
	private sealed record TenantRequestContext(DnsMessage Request, string Tenant) : DnsRequestContext(Request, DnsProtocol.Https);
}
