using Dns.Net.Abstractions;
using System.Net;
using TUnit.Assertions.Enums;

namespace Dns.Net.Tests;

// Expected messages are written out byte by byte, with offsets in comments; decoding must give the message back.
public class DnsMessageEncodingTest
{
	[Test]
	public async Task EncodesAnAQueryByteForByte()
	{
		DnsMessage query = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("example.com"), DnsRecordType.A)) with { Id = 0x1234 };
		byte[] expected =
		[
			0x12, 0x34, // ID
			0x01, 0x00, // QR 0, OPCODE QUERY, AA 0, TC 0, RD 1; RA 0, Z 0, AD 0, CD 0, RCODE NOERROR
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // QDCOUNT 1, ANCOUNT 0, NSCOUNT 0, ARCOUNT 1
			7, .. "example"u8, 3, .. "com"u8, 0, // 12: QNAME
			0x00, 0x01, 0x00, 0x01, // QTYPE A, QCLASS IN
			0, // 29: OPT, owned by the root
			0x00, 0x29, // TYPE OPT
			0x04, 0xD0, // CLASS: UDP payload size 1232
			0x00, 0x00, 0x00, 0x00, // TTL: extended RCODE 0, version 0, DO 0
			0x00, 0x00 // RDLENGTH 0
		];

		await AssertEncodesTo(query, expected);
	}

	[Test]
	public async Task EncodesAQueryWithoutEdnsByteForByte()
	{
		DnsMessage query = DnsMessage.CreateQuery(new DnsQuestion(DnsName.Parse("example.com"), DnsRecordType.Aaaa)) with { Id = 0xABCD, Edns = null };
		byte[] expected =
		[
			0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header: RD, QDCOUNT 1
			7, .. "example"u8, 3, .. "com"u8, 0, 0x00, 0x1C, 0x00, 0x01 // 12: example.com AAAA IN
		];

		await AssertEncodesTo(query, expected);
	}

	[Test]
	public async Task CompressesTheExampleOfRfc1035()
	{
		// RFC 1035, Sec. 4.1.4, with F.ISI.ARPA at 12 instead of 20.
		DnsMessage message = new()
		{
			Questions =
			[
				new DnsQuestion(DnsName.Parse("F.ISI.ARPA"), DnsRecordType.A),
				new DnsQuestion(DnsName.Parse("FOO.F.ISI.ARPA"), DnsRecordType.A),
				new DnsQuestion(DnsName.Parse("ARPA"), DnsRecordType.Ns),
				new DnsQuestion(DnsName.Root, DnsRecordType.Ns)
			]
		};
		byte[] expected =
		[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // header: QDCOUNT 4
			1, (byte)'F', 3, .. "ISI"u8, 4, .. "ARPA"u8, 0, 0x00, 0x01, 0x00, 0x01, // 12: F.ISI.ARPA, with ARPA at 18
			3, .. "FOO"u8, 0xC0, 12, 0x00, 0x01, 0x00, 0x01, // 28: FOO.F.ISI.ARPA
			0xC0, 18, 0x00, 0x02, 0x00, 0x01, // 38: ARPA
			0, 0x00, 0x02, 0x00, 0x01 // 44: the root
		];

		await AssertEncodesTo(message, expected);
	}

	[Test]
	public async Task EncodesEveryRecordDataTypeByteForByte()
	{
		DnsName example = DnsName.Parse("example.com");
		TimeSpan fiveMinutes = TimeSpan.FromMinutes(5);
		TimeSpan hour = TimeSpan.FromHours(1);
		DnsMessage response = new()
		{
			Id = 0xBEEF,
			IsResponse = true,
			IsAuthoritativeAnswer = true,
			IsRecursionDesired = true,
			IsRecursionAvailable = true,
			Questions = [new DnsQuestion(example, DnsRecordType.A)],
			Answers =
			[
				new DnsResourceRecord(example, fiveMinutes, new DnsAddressData(IPAddress.Parse("192.0.2.1"))),
				new DnsResourceRecord(example, fiveMinutes, new DnsAddressData(IPAddress.Parse("2001:db8::1"))),
				new DnsResourceRecord(DnsName.Parse("www.example.com"), hour, new DnsCNameData(example)),
				new DnsResourceRecord(example, hour, new DnsMxData(10, DnsName.Parse("mail.example.com"))),
				new DnsResourceRecord(example, hour, new DnsNsData(DnsName.Parse("ns1.example.com"))),
				new DnsResourceRecord(DnsName.Parse("1.2.0.192.in-addr.arpa"), hour, new DnsPtrData(example)),
				new DnsResourceRecord(DnsName.Parse("_sip._tcp.example.com"), hour, new DnsSrvData(10, 60, 5060, DnsName.Parse("sip.example.com"))),
				new DnsResourceRecord(example, hour, new DnsTxtData(["v=spf1 -all"u8.ToArray(), "x"u8.ToArray()])),
				new DnsResourceRecord(example, hour, new DnsUnknownData(DnsRecordType.Caa, (byte[])[0, 5, .. "issue"u8, .. "ca.example"u8]))
			],
			Authorities =
			[
				new DnsResourceRecord(example, hour, new DnsSoaData(DnsName.Parse("ns1.example.com"), DnsName.Parse("hostmaster.example.com"), 2024010101, TimeSpan.FromHours(2), hour, TimeSpan.FromDays(14), fiveMinutes))
			]
		};
		byte[] expected =
		[
			0xBE, 0xEF, 0x85, 0x80, 0x00, 0x01, 0x00, 0x09, 0x00, 0x01, 0x00, 0x00, // header: QR AA RD RA, QDCOUNT 1, ANCOUNT 9, NSCOUNT 1
			7, .. "example"u8, 3, .. "com"u8, 0, 0x00, 0x01, 0x00, 0x01, // 12: example.com A IN
			0xC0, 12, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 192, 0, 2, 1, // 29: A, TTL 300
			0xC0, 12, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x10, 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // 45: AAAA
			3, .. "www"u8, 0xC0, 12, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x02, 0xC0, 12, // 73: CNAME, TTL 3600, the data compressed
			0xC0, 12, 0x00, 0x0F, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x09, 0x00, 0x0A, 4, .. "mail"u8, 0xC0, 12, // 91: MX 10, the exchange at 105
			0xC0, 12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x06, 3, .. "ns1"u8, 0xC0, 12, // 112: NS, the name at 124
			1, (byte)'1', 1, (byte)'2', 1, (byte)'0', 3, .. "192"u8, 7, .. "in-addr"u8, 4, .. "arpa"u8, 0, // 130: an owner without a known suffix
			0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x02, 0xC0, 12, // PTR
			4, .. "_sip"u8, 4, .. "_tcp"u8, 0xC0, 12, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x17, // 166: SRV
			0x00, 0x0A, 0x00, 0x3C, 0x13, 0xC4, 3, .. "sip"u8, 7, .. "example"u8, 3, .. "com"u8, 0, // 188: priority 10, weight 60, port 5060, the target in full
			0xC0, 12, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x0E, 11, .. "v=spf1 -all"u8, 1, (byte)'x', // 211: TXT
			0xC0, 12, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x11, 0, 5, .. "issue"u8, .. "ca.example"u8, // 237: CAA, kept as is
			0xC0, 12, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x23, // 266: SOA
			0xC0, 124, 10, .. "hostmaster"u8, 0xC0, 12, // 278: MNAME points into the NS data, RNAME to the question
			0x78, 0xA3, 0xF1, 0x75, 0x00, 0x00, 0x1C, 0x20, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x01, 0x2C // SERIAL 2024010101, REFRESH 7200, RETRY 3600, EXPIRE 1209600, MINIMUM 300
		];

		await AssertEncodesTo(response, expected);
	}

	[Test]
	public async Task CompressionMatchesSuffixesRegardlessOfCase()
	{
		DnsMessage message = new()
		{
			Questions = [new DnsQuestion(DnsName.Parse("Example.COM"), DnsRecordType.A)],
			Answers = [new DnsResourceRecord(DnsName.Parse("WWW.example.com"), TimeSpan.Zero, new DnsAddressData(IPAddress.Parse("192.0.2.1")))]
		};
		byte[] expected =
		[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			7, .. "Example"u8, 3, .. "COM"u8, 0, 0x00, 0x01, 0x00, 0x01, // 12
			3, .. "WWW"u8, 0xC0, 12, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 192, 0, 2, 1 // 29: WWW keeps its case
		];

		await AssertEncodesTo(message, expected);

		// The decoded suffix takes the case of the name that it points to.
		await Assert.That(DnsMessage.Decode(expected).Answers[0].Name.ToString()).IsEqualTo("WWW.Example.COM");
	}

	[Test]
	public async Task SrvTargetIsNeitherCompressedNorACompressionTarget()
	{
		DnsMessage message = new()
		{
			Questions = [new DnsQuestion(DnsName.Parse("example.com"), DnsRecordType.Srv)],
			Answers =
			[
				new DnsResourceRecord(DnsName.Parse("_sip._tcp.example.com"), TimeSpan.Zero, new DnsSrvData(0, 0, 5060, DnsName.Parse("sip.example.com"))),
				new DnsResourceRecord(DnsName.Parse("sip.example.com"), TimeSpan.Zero, new DnsAddressData(IPAddress.Parse("192.0.2.1")))
			]
		};
		byte[] expected =
		[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
			7, .. "example"u8, 3, .. "com"u8, 0, 0x00, 0x21, 0x00, 0x01, // 12: example.com SRV IN
			4, .. "_sip"u8, 4, .. "_tcp"u8, 0xC0, 12, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, // 29: the owner is compressed
			0x00, 0x00, 0x00, 0x00, 0x13, 0xC4, 3, .. "sip"u8, 7, .. "example"u8, 3, .. "com"u8, 0, // 51: the target is not, though example.com is at 12
			3, .. "sip"u8, 0xC0, 12, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 192, 0, 2, 1 // 74: nor does this name point into the target at 57
		];

		await AssertEncodesTo(message, expected);
	}

	[Test]
	[Arguments(0x3FFF, true)]
	[Arguments(0x4000, false)]
	public async Task PointersReachOnlyNamesThatStartWithin14Bits(int ownerOffset, bool compressed)
	{
		// The question takes offsets 12 to 26 and the fields of the first record 27 to 38, so its data fills the message up to ownerOffset.
		byte[] filler = new byte[ownerOffset - 39];
		DnsName name = DnsName.Parse("b.test");
		DnsAddressData address = new(IPAddress.Parse("192.0.2.1"));
		DnsMessage message = new()
		{
			Questions = [new DnsQuestion(DnsName.Parse("a.example"), DnsRecordType.A)],
			Answers =
			[
				new DnsResourceRecord(DnsName.Parse("a.example"), TimeSpan.Zero, new DnsUnknownData((DnsRecordType)65280, filler)),
				new DnsResourceRecord(name, TimeSpan.Zero, address),
				new DnsResourceRecord(name, TimeSpan.Zero, address),
				new DnsResourceRecord(DnsName.Parse("c.test"), TimeSpan.Zero, address)
			]
		};
		byte[] fields = [0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 192, 0, 2, 1];
		byte[] fullName = [1, (byte)'b', 4, .. "test"u8, 0];
		byte[] expected =
		[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
			1, (byte)'a', 7, .. "example"u8, 0, 0x00, 0x01, 0x00, 0x01, // 12: a.example A IN
			0xC0, 12, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, (byte)(filler.Length >> 8), (byte)filler.Length, .. filler, // 27: TYPE65280
			.. fullName, .. fields, // ownerOffset: b.test, with test at ownerOffset + 2, beyond 0x3FFF either way
			.. compressed ? [0xFF, 0xFF] : fullName, .. fields, // a pointer to 0x3FFF is 0xFFFF; no pointer reaches 0x4000
			1, (byte)'c', 4, .. "test"u8, 0, .. fields // test, beyond 0x3FFF, is no target
		];

		await AssertEncodesTo(message, expected);
	}

	[Test]
	[MatrixDataSource]
	public async Task NoNameFollowsMoreThan10Pointers([Matrix] bool nestOwners)
	{
		// Each name extends the one before it; past 10 pointers, the encoder writes labels instead.
		DnsName example = DnsName.Parse("example");
		DnsAddressData address = new(IPAddress.Parse("192.0.2.1"));
		List<DnsResourceRecord> answers = [];
		string nested = "example";

		for (int i = 1; i <= 20; ++i)
		{
			nested = $"l{i}.{nested}";
			DnsName name = DnsName.Parse(nested);
			answers.Add(nestOwners ? new DnsResourceRecord(name, TimeSpan.Zero, address) : new DnsResourceRecord(example, TimeSpan.Zero, new DnsMxData(10, name)));
		}

		DnsMessage message = new()
		{
			Questions = [new DnsQuestion(example, nestOwners ? DnsRecordType.A : DnsRecordType.Mx)],
			Answers = answers
		};
		byte[] wire = message.Encode();
		int[] hops = [.. NameOffsets(wire).Select(offset => Wire.PointerHops(wire, offset))];

		// The chains are capped at 10 pointers, not left uncompressed.
		await Assert.That(hops.Length).IsEqualTo(nestOwners ? 21 : 41);
		await Assert.That(hops.Max()).IsEqualTo(10);
		await Assert.That(DnsMessage.Decode(wire)).IsEqualTo(message);
	}

	[Test]
	[Arguments(16, 0x0, 0x01)]
	[Arguments(23, 0x7, 0x01)]
	[Arguments(4095, 0xF, 0xFF)]
	[Arguments(3, 0x3, 0x00)]
	public async Task SplitsTheExtendedResponseCodeBetweenHeaderAndOptRecord(int code, int headerBits, int optBits)
	{
		DnsMessage response = new()
		{
			Id = 7,
			IsResponse = true,
			ResponseCode = (DnsResponseCode)code,
			Edns = new DnsEdns { UdpPayloadSize = 512, Version = 1, DnssecOk = true }
		};
		byte[] expected =
		[
			0x00, 0x07, 0x80, (byte)headerBits, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // the lower 4 bits of the code in the header
			0, 0x00, 0x29, 0x02, 0x00, (byte)optBits, 0x01, 0x80, 0x00, 0x00, 0x00 // OPT: CLASS 512; TTL: the upper 8 bits, version 1, DO
		];

		await AssertEncodesTo(response, expected);
	}

	[Test]
	public async Task EncodesEdnsOptionsInOrder()
	{
		DnsMessage query = new()
		{
			Id = 1,
			Edns = new DnsEdns
			{
				UdpPayloadSize = 4096,
				Options =
				[
					new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[1, 2, 3, 4, 5, 6, 7, 8]),
					new DnsEdnsOption(DnsEdnsOptionCode.Padding, ReadOnlyMemory<byte>.Empty),
					new DnsEdnsOption((DnsEdnsOptionCode)65001, (byte[])[0xAB, 0xCD, 0xEF])
				]
			}
		};
		byte[] expected =
		[
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			0, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, // OPT: CLASS 4096, TTL 0, RDLENGTH 23
			0x00, 0x0A, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, // COOKIE
			0x00, 0x0C, 0x00, 0x00, // PADDING, empty
			0xFD, 0xE9, 0x00, 0x03, 0xAB, 0xCD, 0xEF // option 65001
		];

		await AssertEncodesTo(query, expected);
	}

	[Test]
	public async Task WritesTtlsInWholeSeconds()
	{
		DnsAddressData address = new(IPAddress.Parse("192.0.2.1"));
		DnsMessage message = new()
		{
			Answers =
			[
				new DnsResourceRecord(DnsName.Root, TimeSpan.FromSeconds(300.9), address),
				new DnsResourceRecord(DnsName.Root, TimeSpan.FromSeconds(int.MaxValue), address),
				new DnsResourceRecord(DnsName.Root, TimeSpan.FromSeconds(2147483648L), address),
				new DnsResourceRecord(DnsName.Root, TimeSpan.FromSeconds(uint.MaxValue), address)
			]
		};
		byte[] expected =
		[
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
			0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 192, 0, 2, 1, // 300.9 seconds: 300
			0, 0x00, 0x01, 0x00, 0x01, 0x7F, 0xFF, 0xFF, 0xFF, 0x00, 0x04, 192, 0, 2, 1, // 2^31 − 1 seconds
			0, 0x00, 0x01, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x04, 192, 0, 2, 1, // 2^31 seconds
			0, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x04, 192, 0, 2, 1 // 2^32 − 1 seconds
		];

		await Assert.That(Convert.ToHexString(message.Encode())).IsEqualTo(Convert.ToHexString(expected));
	}

	[Test]
	[Arguments(DnsRecordType.Tsig)]
	[Arguments(DnsRecordType.Sig)]
	public async Task TheOptRecordGoesBeforeASignatureThatEndsTheAdditionalSection(DnsRecordType signatureType)
	{
		// SIG(0) covers type 0, with the signer after 18 bytes of fixed fields (RFC 2931, Sec. 3); TSIG data is opaque.
		byte[] data = signatureType is DnsRecordType.Sig ? [0, 0, 5, 0, .. Wire.U32(0), .. Wire.U32(2), .. Wire.U32(1), 0x12, 0x34, .. Wire.Name("key", "example"), 0xAA] : [1, 2, 3];
		DnsResourceRecord address = new(DnsName.Parse("example.com"), TimeSpan.Zero, new DnsAddressData(IPAddress.Parse("192.0.2.1")));
		DnsResourceRecord signature = new(DnsName.Parse("key.example"), TimeSpan.Zero, new DnsUnknownData(signatureType, data)) { Class = DnsClass.Any };
		DnsMessage signed = new() { Id = 1, Additionals = [address, signature], Edns = new DnsEdns() };

		// A TSIG or SIG(0) record must stay last (RFC 8945, Sec. 5.1; RFC 2931, Sec. 3.1).
		await Assert.That(AdditionalTypes(signed.Encode())).IsEquivalentTo([DnsRecordType.A, DnsRecordType.Opt, signatureType], CollectionOrdering.Matching);
		await Assert.That(DnsMessage.Decode(signed.Encode())).IsEqualTo(signed);

		// Elsewhere a signature is a record like any other, and the OPT record ends the section.
		DnsMessage reordered = signed with { Additionals = [signature, address] };
		await Assert.That(AdditionalTypes(reordered.Encode())).IsEquivalentTo([signatureType, DnsRecordType.A, DnsRecordType.Opt], CollectionOrdering.Matching);
		await Assert.That(AdditionalTypes((signed with { Additionals = [address] }).Encode())).IsEquivalentTo([DnsRecordType.A, DnsRecordType.Opt], CollectionOrdering.Matching);
	}

	[Test]
	public async Task TheOptRecordGoesBeforeASigRecordWhateverTypeItCovers()
	{
		// SIG serves only SIG(0) (RFC 4034, Sec. 7), so the type covered, here A, is not read.
		byte[] data = [0, 1, 5, 0, .. Wire.U32(0), .. Wire.U32(2), .. Wire.U32(1), 0x12, 0x34, .. Wire.Name("key", "example"), 0xAA];
		DnsResourceRecord address = new(DnsName.Parse("example.com"), TimeSpan.Zero, new DnsAddressData(IPAddress.Parse("192.0.2.1")));
		DnsResourceRecord signature = new(DnsName.Parse("key.example"), TimeSpan.Zero, new DnsUnknownData(DnsRecordType.Sig, data)) { Class = DnsClass.Any };
		DnsMessage signed = new() { Id = 1, Additionals = [address, signature], Edns = new DnsEdns() };

		await Assert.That(AdditionalTypes(signed.Encode())).IsEquivalentTo([DnsRecordType.A, DnsRecordType.Opt, DnsRecordType.Sig], CollectionOrdering.Matching);
	}

	[Test]
	public async Task AnOptRecordBeforeATrailingTsigRecordEncodesBackToItsBytes()
	{
		// A, OPT, then TSIG, as RFC 8945, Sec. 5.1, requires; three opaque bytes stand for the TSIG data.
		byte[] message = Wire.Concat(
			Wire.Header(1, 0x8000, 0, 0, 0, 3),
			Wire.Record(Wire.Name("example", "com"), 1, [192, 0, 2, 1]),
			Wire.Record([0], 41, [], ttl: 0x8000, @class: 1232),
			Wire.Record(Wire.Name("key", "example"), 250, [1, 2, 3], ttl: 0, @class: 255));

		await Assert.That(Convert.ToHexString(DnsMessage.Decode(message).Encode())).IsEqualTo(Convert.ToHexString(message));
	}

	// The additional record types in wire order, read without the decoder, which takes OPT out.
	private static DnsRecordType[] AdditionalTypes(byte[] message)
	{
		int[] counts = [message[4] << 8 | message[5], message[6] << 8 | message[7], message[8] << 8 | message[9], message[10] << 8 | message[11]];
		int offset = 12;

		for (int i = 0; i < counts[0]; ++i)
		{
			offset = Wire.SkipName(message, offset) + 4;
		}

		List<DnsRecordType> additionalTypes = [];

		for (int i = 0; i < counts[1] + counts[2] + counts[3]; ++i)
		{
			offset = Wire.SkipName(message, offset);

			if (i >= counts[1] + counts[2])
			{
				additionalTypes.Add((DnsRecordType)(message[offset] << 8 | message[offset + 1]));
			}

			offset += 10 + (message[offset + 8] << 8 | message[offset + 9]);
		}

		return [.. additionalTypes];
	}

	// The offsets of question names, owners and MX exchanges, found without the decoder.
	private static List<int> NameOffsets(byte[] message)
	{
		int questions = message[4] << 8 | message[5];
		int records = (message[6] << 8 | message[7]) + (message[8] << 8 | message[9]) + (message[10] << 8 | message[11]);
		int offset = 12;
		List<int> names = [];

		for (int i = 0; i < questions; ++i)
		{
			names.Add(offset);
			offset = Wire.SkipName(message, offset) + 4;
		}

		for (int i = 0; i < records; ++i)
		{
			names.Add(offset);
			offset = Wire.SkipName(message, offset);
			int type = message[offset] << 8 | message[offset + 1];
			int dataLength = message[offset + 8] << 8 | message[offset + 9];
			offset += 10;

			if (type is 15)
			{
				names.Add(offset + 2);
			}

			offset += dataLength;
		}

		return names;
	}

	// Checks Encode, TryEncode into a destination of the exact length and into one of the greatest length, then decodes the expected bytes.
	internal static async Task AssertEncodesTo(DnsMessage message, byte[] expected)
	{
		string expectedHex = Convert.ToHexString(expected);
		byte[] exact = new byte[expected.Length];
		byte[] large = new byte[DnsMessage.MaxEncodedLength + 1];

		await Assert.That(Convert.ToHexString(message.Encode())).IsEqualTo(expectedHex);
		await Assert.That(message.TryEncode(exact, out int bytesWritten)).IsTrue();
		await Assert.That(bytesWritten).IsEqualTo(expected.Length);
		await Assert.That(Convert.ToHexString(exact)).IsEqualTo(expectedHex);
		await Assert.That(message.TryEncode(large, out bytesWritten)).IsTrue();
		await Assert.That(Convert.ToHexString(large.AsSpan(0, bytesWritten))).IsEqualTo(expectedHex);
		await Assert.That(DnsMessage.Decode(expected)).IsEqualTo(message);
	}
}
