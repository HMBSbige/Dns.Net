using Dns.Net.Abstractions;
using System.Collections;
using System.Net;

namespace Dns.Net.Tests;

public class DnsMessageTest
{
	private static readonly DnsQuestion ExampleA = new(DnsName.Parse("example.com"), DnsRecordType.A);

	private static readonly DnsAddressData Address = new(IPAddress.Parse("192.0.2.1"));

	[Test]
	public async Task CreateQueryAsksOneQuestionWithRecursionAndEdns()
	{
		DnsMessage query = DnsMessage.CreateQuery(ExampleA);

		await Assert.That(query.Id).IsEqualTo((ushort)0);
		await Assert.That(query.IsResponse).IsFalse();
		await Assert.That(query.Opcode).IsEqualTo(DnsOpcode.Query);
		await Assert.That(query.IsRecursionDesired).IsTrue();
		await Assert.That(query.IsCheckingDisabled).IsFalse();
		await Assert.That(query.ResponseCode).IsEqualTo(DnsResponseCode.NoError);
		await Assert.That(query.Questions.Count).IsEqualTo(1);
		await Assert.That(query.Questions[0]).IsEqualTo(ExampleA);
		await Assert.That(query.Answers.Count + query.Authorities.Count + query.Additionals.Count).IsEqualTo(0);
		await Assert.That(query.Edns).IsEqualTo(new DnsEdns());
		await Assert.That(query.Edns!.UdpPayloadSize).IsEqualTo(DnsEdns.DefaultUdpPayloadSize);
	}

	[Test]
	public async Task CreateResponseCopiesWhatTheResponderMustEcho()
	{
		DnsMessage request = new()
		{
			Id = 0x4242,
			Opcode = DnsOpcode.Notify,
			IsAuthoritativeAnswer = true,
			IsRecursionDesired = true,
			IsAuthenticData = true,
			IsCheckingDisabled = true,
			Questions = [ExampleA],
			Answers = [new DnsResourceRecord(ExampleA.Name, TimeSpan.Zero, Address)],
			Edns = new DnsEdns { UdpPayloadSize = 4096, DnssecOk = true, Options = [new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[1, 2, 3, 4, 5, 6, 7, 8])] }
		};

		DnsMessage response = request.CreateResponse();

		await Assert.That(response).IsEqualTo(new DnsMessage
		{
			Id = 0x4242,
			IsResponse = true,
			Opcode = DnsOpcode.Notify,
			IsRecursionDesired = true,
			IsCheckingDisabled = true,
			Questions = [ExampleA],
			Edns = new DnsEdns { DnssecOk = true }
		});
		await Assert.That(response.IsResponseTo(request)).IsTrue();
	}

	[Test]
	[Arguments(false, false)]
	[Arguments(true, false)]
	[Arguments(true, true)]
	public async Task CreateResponseHasEdnsOnlyIfTheRequestHasIt(bool requestHasEdns, bool dnssecOk)
	{
		DnsMessage request = DnsMessage.CreateQuery(ExampleA) with { Edns = requestHasEdns ? new DnsEdns { DnssecOk = dnssecOk, Version = 0 } : null };

		DnsEdns? edns = request.CreateResponse().Edns;

		await Assert.That(edns).IsEqualTo(requestHasEdns ? new DnsEdns { DnssecOk = dnssecOk } : null);
	}

	[Test]
	public async Task IsResponseToChecksIdOpcodeAndQuestions()
	{
		DnsMessage query = DnsMessage.CreateQuery(ExampleA) with { Id = 7 };
		DnsMessage response = query.CreateResponse() with { Answers = [new DnsResourceRecord(ExampleA.Name, TimeSpan.Zero, Address)] };

		await Assert.That(response.IsResponseTo(query)).IsTrue();
		await Assert.That((response with { Id = 8 }).IsResponseTo(query)).IsFalse();
		await Assert.That((response with { IsResponse = false }).IsResponseTo(query)).IsFalse();
		await Assert.That((response with { Opcode = DnsOpcode.Status }).IsResponseTo(query)).IsFalse();
		await Assert.That((response with { Questions = [ExampleA with { Type = DnsRecordType.Aaaa }] }).IsResponseTo(query)).IsFalse();
		await Assert.That((response with { Questions = [ExampleA with { Class = DnsClass.Chaos }] }).IsResponseTo(query)).IsFalse();
		await Assert.That((response with { Questions = [ExampleA with { Name = DnsName.Parse("example.org") }] }).IsResponseTo(query)).IsFalse();
		await Assert.That((response with { Questions = [ExampleA, ExampleA] }).IsResponseTo(query)).IsFalse();

		// Names compare regardless of the case of ASCII letters.
		await Assert.That((response with { Questions = [ExampleA with { Name = DnsName.Parse("EXAMPLE.com") }] }).IsResponseTo(query)).IsTrue();

		// A query answers nothing, and no response answers itself.
		await Assert.That(query.IsResponseTo(response)).IsFalse();
		await Assert.That(response.IsResponseTo(response)).IsFalse();
	}

	[Test]
	[Arguments(DnsResponseCode.NoError)]
	[Arguments(DnsResponseCode.Refused)]
	[Arguments((DnsResponseCode)8)]
	public async Task IsResponseToAcceptsAnUpdateResponseWithOrWithoutTheZone(DnsResponseCode responseCode)
	{
		// RFC 2136, Sec. 3.8: an UPDATE response may have all counts zero. 8 is NXRRSET.
		DnsQuestion zone = new(DnsName.Parse("example.com"), DnsRecordType.Soa);
		DnsMessage update = new()
		{
			Id = 0x1234,
			Opcode = DnsOpcode.Update,
			Questions = [zone],
			Authorities = [new DnsResourceRecord(DnsName.Parse("host.example.com"), TimeSpan.FromMinutes(5), Address)]
		};
		DnsMessage withoutZone = DnsMessage.Decode([0x12, 0x34, 0xA8, (byte)responseCode, 0, 0, 0, 0, 0, 0, 0, 0]);

		await Assert.That(withoutZone.IsResponseTo(update)).IsTrue();
		await Assert.That((update.CreateResponse() with { ResponseCode = responseCode }).IsResponseTo(update)).IsTrue();
		await Assert.That((withoutZone with { Questions = [zone with { Name = DnsName.Parse("example.net") }] }).IsResponseTo(update)).IsFalse();
		await Assert.That((withoutZone with { Id = 0x1235 }).IsResponseTo(update)).IsFalse();
		await Assert.That(withoutZone.IsResponseTo(withoutZone)).IsFalse();
		await Assert.That(update.CreateResponse().IsResponseTo(update.CreateResponse())).IsFalse();

		// A QUERY response must still have the question.
		DnsMessage query = DnsMessage.CreateQuery(ExampleA) with { Id = 0x1234 };
		await Assert.That((withoutZone with { Opcode = DnsOpcode.Query }).IsResponseTo(query)).IsFalse();
	}

	[Test]
	[Arguments(DnsResponseCode.FormatError, true)]
	[Arguments(DnsResponseCode.NotImplemented, true)]
	[Arguments(DnsResponseCode.NoError, false)]
	[Arguments(DnsResponseCode.NxDomain, false)]
	[Arguments(DnsResponseCode.ServerFailure, false)]
	[Arguments(DnsResponseCode.Refused, false)]
	[Arguments((DnsResponseCode)16, false)]
	[Arguments((DnsResponseCode)17, false)]
	public async Task IsResponseToAcceptsOnlyFormErrAndNotImpWithoutTheQuestion(DnsResponseCode responseCode, bool accepted)
	{
		// 17 has the FORMERR bits in the header only.
		DnsMessage query = DnsMessage.CreateQuery(ExampleA) with { Id = 7 };
		DnsMessage withoutQuestion = new() { Id = 7, IsResponse = true, ResponseCode = responseCode };

		await Assert.That(withoutQuestion.IsResponseTo(query)).IsEqualTo(accepted);

		// With a question, it must be the one asked.
		await Assert.That((withoutQuestion with { Questions = [ExampleA] }).IsResponseTo(query)).IsTrue();
		await Assert.That((withoutQuestion with { Questions = [ExampleA with { Type = DnsRecordType.Mx }] }).IsResponseTo(query)).IsFalse();
		await Assert.That((withoutQuestion with { Id = 8 }).IsResponseTo(query)).IsFalse();
		await Assert.That(() => withoutQuestion.IsResponseTo(null!)).Throws<ArgumentNullException>();
	}

	[Test]
	public async Task EqualityComparesTheContentsOfTheSections()
	{
		DnsResourceRecord record = new(DnsName.Parse("example.com"), TimeSpan.FromMinutes(1), new DnsTxtData(["a"u8.ToArray()]));
		DnsMessage first = new()
		{
			Questions = new List<DnsQuestion> { ExampleA },
			Answers = [record],
			Edns = new DnsEdns { Options = [new DnsEdnsOption(DnsEdnsOptionCode.Nsid, "x"u8.ToArray())] }
		};
		DnsMessage second = new()
		{
			Questions = [new DnsQuestion(DnsName.Parse("EXAMPLE.COM"), DnsRecordType.A)],
			Answers = new List<DnsResourceRecord> { record with { Name = DnsName.Parse("Example.Com"), Data = new DnsTxtData(["a"u8.ToArray()]) } },
			Edns = new DnsEdns { Options = new List<DnsEdnsOption> { new(DnsEdnsOptionCode.Nsid, "x"u8.ToArray()) } }
		};

		await Assert.That(first).IsEqualTo(second);
		await Assert.That(first == second).IsTrue();
		await Assert.That(first.GetHashCode()).IsEqualTo(second.GetHashCode());
		await Assert.That(first).IsNotEqualTo(second with { Answers = [] });
		await Assert.That(first).IsNotEqualTo(second with { Answers = [record with { Ttl = TimeSpan.FromMinutes(2) }] });
		await Assert.That(first).IsNotEqualTo(second with { Additionals = [record] });
		await Assert.That(first).IsNotEqualTo(second with { Edns = null });
		await Assert.That(first).IsNotEqualTo(second with { IsTruncated = true });
		await Assert.That(first).IsNotEqualTo(second with { ResponseCode = (DnsResponseCode)16 });
	}

	[Test]
	public async Task SectionsRejectNull()
	{
		await Assert.That(() => new DnsMessage { Questions = null! }).Throws<ArgumentNullException>();
		await Assert.That(() => new DnsMessage { Answers = null! }).Throws<ArgumentNullException>();
		await Assert.That(() => new DnsMessage { Authorities = null! }).Throws<ArgumentNullException>();
		await Assert.That(() => new DnsMessage { Additionals = null! }).Throws<ArgumentNullException>();
		await Assert.That(() => new DnsEdns { Options = null! }).Throws<ArgumentNullException>();
	}

	[Test]
	public async Task SectionsRejectNullRecords()
	{
		DnsResourceRecord record = new(ExampleA.Name, TimeSpan.Zero, Address);
		DnsResourceRecord[] withNull = [record, null!];
		DnsMessage message = new() { Answers = [record] };

		await Assert.That(() => new DnsMessage { Answers = withNull }).ThrowsExactly<ArgumentException>().WithParameterName("Answers");
		await Assert.That(() => new DnsMessage { Authorities = withNull }).ThrowsExactly<ArgumentException>().WithParameterName("Authorities");
		await Assert.That(() => new DnsMessage { Additionals = withNull }).ThrowsExactly<ArgumentException>().WithParameterName("Additionals");
		await Assert.That(() => message with { Answers = withNull }).ThrowsExactly<ArgumentException>().WithParameterName("Answers");
	}

	[Test]
	public async Task SectionsAreCopiesOfTheListsGiven()
	{
		DnsResourceRecord record = new(ExampleA.Name, TimeSpan.Zero, Address);
		List<DnsQuestion> questions = [ExampleA];
		List<DnsResourceRecord> answers = [record];
		List<DnsResourceRecord> authorities = [record];
		List<DnsResourceRecord> additionals = [record];
		List<DnsEdnsOption> options = [new(DnsEdnsOptionCode.Nsid, "x"u8.ToArray())];
		DnsMessage message = new() { Questions = questions, Answers = answers, Authorities = authorities, Additionals = additionals, Edns = new DnsEdns { Options = options } };
		string encoded = Convert.ToHexString(message.Encode());
		int hashCode = message.GetHashCode();

		questions.Clear();
		answers.Clear();
		authorities.Clear();
		additionals.Clear();
		options.Clear();

		await Assert.That(message.Questions.Count).IsEqualTo(1);
		await Assert.That(message.Answers.Count).IsEqualTo(1);
		await Assert.That(message.Authorities.Count).IsEqualTo(1);
		await Assert.That(message.Additionals.Count).IsEqualTo(1);
		await Assert.That(message.Edns.Options.Count).IsEqualTo(1);
		await Assert.That(Convert.ToHexString(message.Encode())).IsEqualTo(encoded);
		await Assert.That(message.GetHashCode()).IsEqualTo(hashCode);

		// A with expression copies too.
		List<DnsResourceRecord> replaced = [record];
		DnsMessage derived = message with { Answers = replaced };
		replaced.Add(record);

		await Assert.That(derived.Answers.Count).IsEqualTo(1);
	}

	[Test]
	public async Task ToStringShowsTheMessageAsDigDoes()
	{
		DnsMessage response = new()
		{
			Id = 4660,
			IsResponse = true,
			IsRecursionDesired = true,
			IsRecursionAvailable = true,
			ResponseCode = DnsResponseCode.NxDomain,
			Questions = [ExampleA],
			Authorities = [new DnsResourceRecord(DnsName.Parse("example.com"), TimeSpan.FromSeconds(300), new DnsSoaData(DnsName.Parse("ns.example.com"), DnsName.Parse("admin.example.com"), 1, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(5)))],
			Edns = new DnsEdns { DnssecOk = true, Options = [new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[0x01, 0x23])] }
		};
		string[] expected =
		[
			";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 4660",
			";; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1",
			string.Empty,
			";; OPT PSEUDOSECTION:",
			"; EDNS: version: 0, flags: do; udp: 1232",
			"; COOKIE: 0123",
			string.Empty,
			";; QUESTION SECTION:",
			";example.com. IN A",
			string.Empty,
			";; AUTHORITY SECTION:",
			"example.com. 300 IN SOA ns.example.com. admin.example.com. 1 2 3 4 5"
		];

		await Assert.That(response.ToString()).IsEqualTo(string.Join(Environment.NewLine, expected));
	}

	[Test]
	public async Task ToStringNamesTheSectionsOfAnUpdateAsDigDoes()
	{
		// RFC 2136, Sec. 2: a zone, a prerequisite, an update and an additional record.
		DnsMessage update = new()
		{
			Id = 7,
			Opcode = DnsOpcode.Update,
			Questions = [new DnsQuestion(DnsName.Parse("example.com"), DnsRecordType.Soa)],
			Answers = [new DnsResourceRecord(DnsName.Parse("www.example.com"), TimeSpan.Zero, Address)],
			Authorities = [new DnsResourceRecord(DnsName.Parse("mail.example.com"), TimeSpan.FromSeconds(300), new DnsAddressData(IPAddress.Parse("192.0.2.2")))],
			Additionals = [new DnsResourceRecord(DnsName.Parse("ns.example.com"), TimeSpan.FromSeconds(60), new DnsAddressData(IPAddress.Parse("192.0.2.3")))]
		};
		string[] expected =
		[
			";; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id: 7",
			";; flags:; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1",
			string.Empty,
			";; ZONE SECTION:",
			";example.com. IN SOA",
			string.Empty,
			";; PREREQUISITE SECTION:",
			"www.example.com. 0 IN A 192.0.2.1",
			string.Empty,
			";; UPDATE SECTION:",
			"mail.example.com. 300 IN A 192.0.2.2",
			string.Empty,
			";; ADDITIONAL SECTION:",
			"ns.example.com. 60 IN A 192.0.2.3"
		];

		await Assert.That(update.ToString()).IsEqualTo(string.Join(Environment.NewLine, expected));
	}

	[Test]
	public async Task TryEncodeReturnsFalseAndLeavesTheDestinationWhenItIsShort()
	{
		DnsMessage query = DnsMessage.CreateQuery(ExampleA);
		byte[] encoded = query.Encode();
		byte[] destination = new byte[encoded.Length - 1];
		destination.AsSpan().Fill(0xAA);

		await Assert.That(query.TryEncode(destination, out int bytesWritten)).IsFalse();
		await Assert.That(bytesWritten).IsEqualTo(0);
		await Assert.That(destination.All(value => value is 0xAA)).IsTrue();
		await Assert.That(query.TryEncode(Span<byte>.Empty, out bytesWritten)).IsFalse();
		await Assert.That(bytesWritten).IsEqualTo(0);
	}

	[Test]
	public async Task EncodesMessagesOfUpTo65535Bytes()
	{
		// The header takes 12 bytes and a record owned by the root 11 before its data.
		DnsMessage longest = new() { Answers = [new DnsResourceRecord(DnsName.Root, TimeSpan.Zero, new DnsUnknownData((DnsRecordType)65280, new byte[65535 - 12 - 11]))] };
		DnsMessage tooLong = new() { Answers = [new DnsResourceRecord(DnsName.Root, TimeSpan.Zero, new DnsUnknownData((DnsRecordType)65280, new byte[65535 - 12 - 11 + 1]))] };

		await Assert.That(longest.Encode().Length).IsEqualTo(DnsMessage.MaxEncodedLength);
		await AssertNotEncodable(tooLong);
	}

	[Test]
	public async Task RefusesOpcodesThatDoNotFitIn4Bits()
	{
		await Assert.That(new DnsMessage { Opcode = (DnsOpcode)15 }.Encode()[2]).IsEqualTo((byte)0x78);
		await AssertNotEncodable(new DnsMessage { Opcode = (DnsOpcode)16 });
	}

	[Test]
	public async Task RefusesResponseCodesThatDoNotFit()
	{
		await AssertNotEncodable(new DnsMessage { ResponseCode = (DnsResponseCode)16 });
		await AssertNotEncodable(new DnsMessage { ResponseCode = (DnsResponseCode)4096, Edns = new DnsEdns() });
		await Assert.That(new DnsMessage { ResponseCode = (DnsResponseCode)15 }.Encode()[3]).IsEqualTo((byte)0x0F);
		await Assert.That(new DnsMessage { ResponseCode = (DnsResponseCode)4095, Edns = new DnsEdns() }.Encode().Length).IsEqualTo(23);
	}

	[Test]
	public async Task RefusesSectionsWithMoreThan65535Entries()
	{
		DnsResourceRecord record = new(DnsName.Root, TimeSpan.Zero, Address);

		await AssertNotEncodable(new DnsMessage { Questions = new RepeatedList<DnsQuestion>(ExampleA, 65536) });
		await AssertNotEncodable(new DnsMessage { Answers = new RepeatedList<DnsResourceRecord>(record, 65536) });
		await AssertNotEncodable(new DnsMessage { Authorities = new RepeatedList<DnsResourceRecord>(record, 65536) });

		// The OPT record counts in the additional section.
		await AssertNotEncodable(new DnsMessage { Additionals = new RepeatedList<DnsResourceRecord>(record, 65535), Edns = new DnsEdns() });
	}

	[Test]
	public async Task RefusesEdnsOptionsLongerThanAMessage()
	{
		await AssertNotEncodable(new DnsMessage { Edns = new DnsEdns { Options = [new DnsEdnsOption(DnsEdnsOptionCode.Padding, new byte[65536])] } });
	}

	private static async Task AssertNotEncodable(DnsMessage message)
	{
		// Refused even when the destination is short.
		await Assert.That(() => message.Encode()).Throws<InvalidOperationException>();
		await Assert.That(() => message.TryEncode(new byte[512], out _)).Throws<InvalidOperationException>();
		await Assert.That(() => message.TryEncode(new byte[DnsMessage.MaxEncodedLength], out _)).Throws<InvalidOperationException>();
	}

	// Reports a count without holding the entries.
	private sealed class RepeatedList<T>(T item, int count) : IReadOnlyList<T>
	{
		public int Count => count;

		public T this[int index] => item;

		public IEnumerator<T> GetEnumerator()
		{
			for (int i = 0; i < count; ++i)
			{
				yield return item;
			}
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return GetEnumerator();
		}
	}
}
