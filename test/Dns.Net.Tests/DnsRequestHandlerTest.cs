using Dns.Net.Abstractions;
using System.Net;

namespace Dns.Net.Tests;

public class DnsRequestHandlerTest
{
	[Test]
	public async Task AHandlerBuildsItsResponseFromTheRequest(CancellationToken cancellationToken)
	{
		DnsMessage request = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A)) with { Id = 99 };
		DnsRequestContext context = new(request, DnsProtocol.Udp) { RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, 5353) };

		DnsMessage? response = await new LoopbackHandler().HandleAsync(context, cancellationToken);

		await Assert.That(response).IsNotNull();
		await Assert.That(response!.IsResponseTo(request)).IsTrue();
		await Assert.That(response.IsAuthoritativeAnswer).IsTrue();
		await Assert.That(response.Answers.Count).IsEqualTo(1);
		await Assert.That(response.Answers[0].ToString()).IsEqualTo("localhost. 300 IN A 127.0.0.1");
		await Assert.That(DnsMessage.Decode(response.Encode())).IsEqualTo(response);
	}

	[Test]
	public async Task AHandlerMaySendNoResponse(CancellationToken cancellationToken)
	{
		DnsMessage request = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A));
		BlockingHandler handler = new(new LoopbackHandler(), IPAddress.Parse("192.0.2.1"));

		DnsMessage? blocked = await handler.HandleAsync(new DnsRequestContext(request, DnsProtocol.Udp) { RemoteEndPoint = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 5353) }, cancellationToken);
		DnsMessage? answered = await handler.HandleAsync(new DnsRequestContext(request, DnsProtocol.Udp) { RemoteEndPoint = new IPEndPoint(IPAddress.Parse("192.0.2.2"), 5353) }, cancellationToken);

		await Assert.That(blocked).IsNull();
		await Assert.That(answered?.IsResponseTo(request)).IsTrue();
	}

	[Test]
	public async Task AServerTransportMayPassADerivedContextThatAWrappingHandlerKeepsWhenItChangesTheRequest(CancellationToken cancellationToken)
	{
		DnsMessage request = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A)) with { Id = 7 };
		RecordingHandler recorder = new();

		_ = await new IdStampingHandler(recorder).HandleAsync(new TenantRequestContext(request, "t1"), cancellationToken);

		await Assert.That(recorder.Context is TenantRequestContext { Tenant: "t1", Protocol: DnsProtocol.Https }).IsTrue();
		await Assert.That(recorder.Context?.Request.Id).IsEqualTo((ushort)42);
	}

	[Test]
	public async Task AWrappingHandlerThatChangesTheIdentifierRestoresItInTheResponse(CancellationToken cancellationToken)
	{
		DnsMessage request = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A)) with { Id = 7 };

		DnsMessage? response = await new IdStampingHandler(new LoopbackHandler()).HandleAsync(new DnsRequestContext(request, DnsProtocol.Udp), cancellationToken);

		await Assert.That(response).IsNotNull();
		await Assert.That(response!.Id).IsEqualTo((ushort)7);
		await Assert.That(response.IsResponseTo(request)).IsTrue();
	}

	[Test]
	public async Task AContextHasNoSignerUnlessTheServerTransportSetsOne()
	{
		DnsMessage request = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A));

		await Assert.That(new DnsRequestContext(request, DnsProtocol.Udp).Signer).IsNull();
		await Assert.That(new TenantRequestContext(request, "t1").Signer).IsNull();
	}

	[Test]
	public async Task AWrappingHandlerThatChangesTheRequestKeepsTheSigner(CancellationToken cancellationToken)
	{
		DnsMessage request = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A)) with { Id = 7 };
		DnsRequestSigner signer = new(DnsRecordType.Tsig, DnsName.Parse("key.example"));
		RecordingHandler recorder = new();
		IdStampingHandler handler = new(recorder);

		_ = await handler.HandleAsync(new DnsRequestContext(request, DnsProtocol.Tcp) { Signer = signer }, cancellationToken);
		await Assert.That(recorder.Context?.Signer).IsEqualTo(signer);
		await Assert.That(recorder.Context?.Request.Id).IsEqualTo((ushort)42);

		_ = await handler.HandleAsync(new TenantRequestContext(request, "t1") { Signer = signer }, cancellationToken);
		await Assert.That(recorder.Context is TenantRequestContext { Tenant: "t1" }).IsTrue();
		await Assert.That(recorder.Context?.Signer).IsEqualTo(signer);
	}

	[Test]
	public async Task ContextsThatDifferOnlyInTheSignerAreNotEqual()
	{
		DnsMessage request = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("localhost"), DnsRecordType.A));
		DnsName key = DnsName.Parse("key.example");
		DnsRequestContext context = new(request, DnsProtocol.Tcp) { Signer = new DnsRequestSigner(DnsRecordType.Tsig, key) };

		await Assert.That(context with { Signer = null }).IsNotEqualTo(context);
		await Assert.That(context with { Signer = new DnsRequestSigner(DnsRecordType.Sig, key) }).IsNotEqualTo(context);
		await Assert.That(context with { Signer = new DnsRequestSigner(DnsRecordType.Tsig, DnsName.Parse("other.example")) }).IsNotEqualTo(context);
		await Assert.That(context with { Signer = new DnsRequestSigner(DnsRecordType.Tsig, DnsName.Parse("KEY.example")) }).IsEqualTo(context);
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

		DnsMessage badVers = request.CreateResponse() with { ResponseCode = (DnsResponseCode)16 };
		await Assert.That(response).IsEqualTo(badVers);
		await Assert.That(badVers.Edns).IsEqualTo(new DnsEdns { DnssecOk = true });
		await Assert.That(badVers.IsResponseTo(request)).IsTrue();
		await Assert.That(DnsMessage.Decode(badVers.Encode())).IsEqualTo(badVers);

		// Version 0 goes on to the inner handler.
		DnsMessage? answered = await handler.HandleAsync(new DnsRequestContext(request with { Edns = new DnsEdns() }, DnsProtocol.Udp), cancellationToken);
		await Assert.That(answered?.ResponseCode).IsEqualTo(DnsResponseCode.NoError);
		await Assert.That(answered?.Answers.Count).IsEqualTo(1);
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

		await Assert.That(response).IsNotNull();
		await Assert.That(response!.ResponseCode).IsEqualTo(DnsResponseCode.NotImplemented);
		await Assert.That(response.Opcode).IsEqualTo((DnsOpcode)15);
		await Assert.That(response.Questions).IsEmpty();
		await Assert.That(response.Answers).IsEmpty();
		await Assert.That(response.Authorities).IsEmpty();
		await Assert.That(response.Additionals).IsEmpty();
		await Assert.That(response.IsAuthoritativeAnswer).IsFalse();
		await Assert.That(response.IsRecursionDesired).IsFalse();
		await Assert.That(response.Edns).IsNull();
		await Assert.That(response.IsResponseTo(request)).IsTrue();
		await Assert.That(DnsMessage.Decode(response.Encode())).IsEqualTo(response);
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

	// Answers every A question with the loopback address.
	private sealed class LoopbackHandler : IDnsRequestHandler
	{
		public ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default)
		{
			DnsMessage request = context.Request;

			DnsMessage response = request.CreateResponse() with
			{
				IsAuthoritativeAnswer = true,
				Answers = [.. request.Questions.Where(static q => q.Type is DnsRecordType.A).Select(static q => new DnsResourceRecord(q.Name, TimeSpan.FromMinutes(5), new DnsAddressData(IPAddress.Loopback)))]
			};

			return ValueTask.FromResult<DnsMessage?>(response);
		}
	}

	// Sends no response to requests from one address, and passes the others on.
	private sealed class BlockingHandler(IDnsRequestHandler inner, IPAddress blocked) : IDnsRequestHandler
	{
		public ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default)
		{
			return context.RemoteEndPoint is IPEndPoint { Address: var address } && address.Equals(blocked) ? ValueTask.FromResult<DnsMessage?>(null) : inner.HandleAsync(context, cancellationToken);
		}
	}

	// Changes the ID of each request it passes on, and restores it in the response.
	private sealed class IdStampingHandler(IDnsRequestHandler inner) : IDnsRequestHandler
	{
		public async ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default)
		{
			DnsMessage? response = await inner.HandleAsync(context with { Request = context.Request with { Id = 42 } }, cancellationToken);
			return response is null ? null : response with { Id = context.Request.Id };
		}
	}

	// Keeps the context of the last request, and sends no response.
	private sealed class RecordingHandler : IDnsRequestHandler
	{
		public DnsRequestContext? Context { get; private set; }

		public ValueTask<DnsMessage?> HandleAsync(DnsRequestContext context, CancellationToken cancellationToken = default)
		{
			Context = context;
			return ValueTask.FromResult<DnsMessage?>(null);
		}
	}

	// Extra data a DoH server transport could add, such as a tenant.
	private sealed record TenantRequestContext(DnsMessage Request, string Tenant) : DnsRequestContext(Request, DnsProtocol.Https);
}
