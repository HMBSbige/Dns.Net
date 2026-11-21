using Dns.Net.Abstractions;
using System.Net;
using static Dns.Net.Tests.Wire;

namespace Dns.Net.Tests;

public class DnsErrorResponseTest
{
	private static readonly DnsQuestion ExampleA = new(DnsName.Parse("example.com"), DnsRecordType.A);

	private static readonly byte[] Opt = Record([0], 41, [], ttl: 0, @class: 1232);

	[Test]
	public async Task ASecondOptRecordGetsFormErrWithEdns()
	{
		// RFC 6891, Sec. 6.1.1. Flags: NOTIFY, RD, CD.
		byte[] request = Concat(Header(0x4242, 0x2110, 1, 0, 0, 2), Question, Opt, Opt);

		await AssertFormErr(request, new DnsMessage
		{
			Id = 0x4242,
			Opcode = DnsOpcode.Notify,
			IsRecursionDesired = true,
			IsCheckingDisabled = true,
			Questions = [ExampleA],
			Edns = new DnsEdns()
		});
	}

	[Test]
	public async Task AMalformedEdnsOptionGetsFormErrWithEdns()
	{
		// The option claims 8 bytes, of which the OPT record holds 1.
		byte[] request = Concat(Header(7, 0x0100, 1, 0, 0, 1), Question, Record([0], 41, [0x00, 0x0A, 0x00, 0x08, 1], ttl: 0, @class: 4096));

		await AssertFormErr(request, new DnsMessage { Id = 7, IsRecursionDesired = true, Questions = [ExampleA], Edns = new DnsEdns() });
	}

	[Test]
	[Arguments(0x0000_8000u, true)]
	[Arguments(0x0101_C001u, true)]
	[Arguments(0x0000_7FFFu, false)]
	public async Task OnlyTheDoBitOfTheRequestIsCopied(uint optTtl, bool dnssecOk)
	{
		// RFC 3225, Sec. 3. The OPT TTL holds the extended code, the version and the flags, DO first.
		byte[] request = Concat(Header(7, 0x0100, 1, 0, 0, 1), Question, Record([0], 41, [0x00, 0x0A, 0x00, 0x08, 1], ttl: optTtl, @class: 4096));

		await AssertFormErr(request, new DnsMessage { Id = 7, IsRecursionDesired = true, Questions = [ExampleA], Edns = new DnsEdns { DnssecOk = dnssecOk } });
	}

	[Test]
	public async Task AnOptRecordAfterTheFailureStillGivesEdns()
	{
		// Decoding rejects the 3-byte A record; the OPT record comes after it.
		byte[] request = Concat(Header(8, 0x0000, 1, 0, 0, 2), Question, Record([0], 1, [192, 0, 2]), Opt);

		await AssertFormErr(request, new DnsMessage { Id = 8, Questions = [ExampleA], Edns = new DnsEdns() });
	}

	[Test]
	public async Task ATruncatedQuestionGetsFormErrWithoutTheQuestionOrEdns()
	{
		byte[] request = Concat(Header(9, 0x0100, 1, 0, 0, 0), Name("example", "com"), [0x00]);

		await AssertFormErr(request, new DnsMessage { Id = 9, IsRecursionDesired = true });
	}

	[Test]
	public async Task OnlyASingleQuestionIsCopied()
	{
		// RFC 9619: a QUERY has at most one question.
		byte[] request = Concat(Header(10, 0x0100, 2, 0, 0, 2), Question, Question, Opt, Opt);

		await AssertFormErr(request, new DnsMessage { Id = 10, IsRecursionDesired = true, Edns = new DnsEdns() });
	}

	[Test]
	public async Task CountsBeyondTheMessageStillGiveTheQuestion()
	{
		byte[] request = Concat(Header(11, 0x0100, 1, 5, 0, 0), Question);

		await AssertFormErr(request, new DnsMessage { Id = 11, IsRecursionDesired = true, Questions = [ExampleA] });
	}

	[Test]
	public async Task AMalformedUpdateGetsFormErr()
	{
		// example.com SOA IN, the zone section, then a byte that no section counts.
		byte[] request = Concat(Header(13, 0x2800, 1, 0, 0, 0), Name("example", "com"), [0x00, 0x06, 0x00, 0x01, 0xFF]);

		await AssertFormErr(request, new DnsMessage { Id = 13, Opcode = DnsOpcode.Update, Questions = [new DnsQuestion(DnsName.Parse("example.com"), DnsRecordType.Soa)] });
	}

	[Test]
	public async Task ADsoKeepaliveGetsNotImpWithTheHeaderOnly()
	{
		// RFC 8490: a DSO Keepalive TLV after a header with zero counts.
		byte[] request = Concat(Header(0x4D2, 0x3000, 0, 0, 0, 0), [0x00, 0x01, 0x00, 0x08, .. U32(15_000), .. U32(60_000)]);

		await AssertNotImp(request, new DnsMessage { Id = 0x4D2, Opcode = (DnsOpcode)6 });
	}

	[Test]
	[Arguments(1)]
	[Arguments(2)]
	[Arguments(15)]
	public async Task AnyOtherOpcodeGetsNotImpWithTheHeaderOnly(int opcode)
	{
		// The question and OPT record it seems to hold are left out. Flags: RD, CD.
		byte[] request = Concat(Header(14, opcode << 11 | 0x0110, 1, 0, 0, 1), Question, Opt, [0xDE, 0xAD]);

		await AssertNotImp(request, new DnsMessage { Id = 14, Opcode = (DnsOpcode)opcode, IsRecursionDesired = true, IsCheckingDisabled = true });
	}

	[Test]
	public async Task AMessageOfTheMaximumLengthGetsFormErrWithTheQuestionAndEdns()
	{
		byte[] request = MaximumLengthQuery(0x0000);

		await Assert.That(request.Length).IsEqualTo(DnsMessage.MaxEncodedLength);
		await AssertFormErr(request, new DnsMessage { Id = 15, IsRecursionDesired = true, IsCheckingDisabled = true, Questions = [ExampleA], Edns = new DnsEdns { DnssecOk = true } });
	}

	[Test]
	public async Task ALongerQueryGetsFormErrWithTheHeaderOnly()
	{
		// Nothing past the header is read from a message over 65535 bytes.
		byte[] request = [.. MaximumLengthQuery(0x0000), 0x00];

		await AssertFormErr(request, new DnsMessage { Id = 15, IsRecursionDesired = true, IsCheckingDisabled = true });
	}

	[Test]
	public async Task ALongerMessageOfAnotherOpcodeGetsNotImpWithTheHeaderOnly()
	{
		byte[] request = [.. MaximumLengthQuery(6 << 11), 0x00];

		await AssertNotImp(request, new DnsMessage { Id = 15, Opcode = (DnsOpcode)6, IsRecursionDesired = true, IsCheckingDisabled = true });
	}

	[Test]
	public async Task ALongerResponseGetsNoResponse()
	{
		await Assert.That(DnsMessage.CreateErrorResponse([.. MaximumLengthQuery(0x8000), 0x00])).IsNull();
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(4)]
	[Arguments(11)]
	public async Task FewerBytesThanAHeaderGetNoResponse(int length)
	{
		await Assert.That(DnsMessage.CreateErrorResponse(Header(1, 0x0100, 1, 0, 0, 0).AsSpan(0, length))).IsNull();
	}

	[Test]
	public async Task AResponseGetsNoResponse()
	{
		await Assert.That(DnsMessage.CreateErrorResponse(Concat(Header(12, 0x8100, 1, 0, 0, 2), Question, Opt, Opt))).IsNull();
		await Assert.That(DnsMessage.CreateErrorResponse(Header(12, 0x8000, 0, 0, 0, 0))).IsNull();
	}

	// MaxEncodedLength bytes: the question, an A record that decoding rejects, then an OPT record with DO set.
	private static byte[] MaximumLengthQuery(int flags)
	{
		byte[] opt = Record([0], 41, [], ttl: 0x0000_8000, @class: 1232);
		int fill = DnsMessage.MaxEncodedLength - (12 + Question.Length + 11 + opt.Length);
		return Concat(Header(15, flags | 0x0110, 1, 0, 0, 2), Question, Record([0], 1, new byte[fill]), opt);
	}

	// Asserts that decoding rejects request and that its FORMERR response is expected.
	private static async Task AssertFormErr(byte[] request, DnsMessage expected)
	{
		DnsMessage formErr = expected with { IsResponse = true, ResponseCode = DnsResponseCode.FormatError };

		await Assert.That(DnsMessage.TryDecode(request, out _)).IsFalse();
		await Assert.That(DnsMessage.CreateErrorResponse(request)).IsEqualTo(formErr);
		await Assert.That(DnsMessage.Decode(formErr.Encode())).IsEqualTo(formErr);
	}

	// Asserts that decoding rejects request and that its NOTIMP response is expected.
	private static async Task AssertNotImp(byte[] request, DnsMessage expected)
	{
		DnsMessage notImp = expected with { IsResponse = true, ResponseCode = DnsResponseCode.NotImplemented };

		await Assert.That(DnsMessage.TryDecode(request, out _)).IsFalse();
		await Assert.That(DnsMessage.CreateErrorResponse(request)).IsEqualTo(notImp);
		await Assert.That(DnsMessage.Decode(notImp.Encode())).IsEqualTo(notImp);
	}
}
