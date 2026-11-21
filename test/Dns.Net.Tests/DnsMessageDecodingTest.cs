using Dns.Net.Abstractions;
using System.Net;
using System.Runtime.InteropServices;
using static Dns.Net.Tests.Wire;

namespace Dns.Net.Tests;

public class DnsMessageDecodingTest
{
	[Test]
	[Arguments(0x7FFFFFFFu, 2147483647L)]
	[Arguments(0x80000000u, 2147483648L)]
	[Arguments(0xFFFFFFFFu, 4294967295L)]
	[Arguments(0u, 0L)]
	[Arguments(300u, 300L)]
	public async Task ReadsTtlsAsUnsigned32BitSeconds(uint ttl, long seconds)
	{
		// RFC 8767, Sec. 4.
		byte[] message = Concat(Header(0, 0x8000, 0, 1, 0, 0), Record([0], 1, [192, 0, 2, 1], ttl));
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded.Answers[0].Ttl).IsEqualTo(TimeSpan.FromSeconds(seconds));
		await Assert.That(Convert.ToHexString(decoded.Encode())).IsEqualTo(Convert.ToHexString(message));
	}

	[Test]
	public async Task ReadsTheOptRecordIntoEdnsWhereverItIsInTheAdditionalSection()
	{
		byte[] message =
		[
			0x00, 0x01, 0x80, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // RCODE 3 in the header, ARCOUNT 2
			0, 0x00, 0x29, 0x05, 0xDC, 0x01, 0x02, 0x80, 0x00, 0x00, 0x0C, // OPT: CLASS 1500; TTL: upper RCODE bits 1, version 2, DO; RDLENGTH 12
			0x00, 0x03, 0x00, 0x03, .. "ns1"u8, // NSID
			0x00, 0x0C, 0x00, 0x01, 0x00, // PADDING
			0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 192, 0, 2, 1 // an A record after the OPT record
		];
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded.ResponseCode).IsEqualTo((DnsResponseCode)(1 << 4 | 3));
		DnsResourceRecord additional = await Assert.That(decoded.Additionals).HasSingleItem();
		await Assert.That(additional.Data).IsEqualTo(new DnsAddressData(IPAddress.Parse("192.0.2.1")));
		await Assert.That(decoded.Edns).IsEqualTo(new DnsEdns
		{
			UdpPayloadSize = 1500,
			Version = 2,
			DnssecOk = true,
			Options = [new DnsEdnsOption(DnsEdnsOptionCode.Nsid, "ns1"u8.ToArray()), new DnsEdnsOption(DnsEdnsOptionCode.Padding, (byte[])[0])]
		});
	}

	[Test]
	public async Task ReadsTheHeaderFlags()
	{
		// QR, OPCODE UPDATE, AA, TC, RD; RA, Z, AD, CD, RCODE REFUSED. Z has no property and is ignored.
		byte[] message = Header(0xFFFF, 0b1_0101_1_1_1_1_1_1_1_0101, 0, 0, 0, 0);
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded).IsEqualTo(new DnsMessage
		{
			Id = 0xFFFF,
			IsResponse = true,
			Opcode = DnsOpcode.Update,
			IsAuthoritativeAnswer = true,
			IsTruncated = true,
			IsRecursionDesired = true,
			IsRecursionAvailable = true,
			IsAuthenticData = true,
			IsCheckingDisabled = true,
			ResponseCode = DnsResponseCode.Refused
		});
	}

	[Test]
	public async Task KeepsTheEmptyDataOfDynamicUpdatesAsUnknownData()
	{
		// RFC 2136: the zone, then deletions of an RRset (class ANY) and of one record (class NONE).
		byte[] message = Concat(
			Header(9, 0x2800, 1, 0, 2, 0),
			Name("example", "com"), U16(6), U16(1),
			Record(CompressedName(12, "a"), 1, [], ttl: 0, @class: 255),
			Record(CompressedName(12, "b"), 1, [192, 0, 2, 1], ttl: 0, @class: 254));
		DnsMessage update = DnsMessage.Decode(message);

		await Assert.That(update.Opcode).IsEqualTo(DnsOpcode.Update);
		await Assert.That(update.Authorities[0].Class).IsEqualTo(DnsClass.Any);
		await Assert.That(update.Authorities[0].Data).IsEqualTo(new DnsUnknownData(DnsRecordType.A, ReadOnlyMemory<byte>.Empty));
		await Assert.That(update.Authorities[1].Class).IsEqualTo(DnsClass.None);
		await Assert.That(update.Authorities[1].Data).IsEqualTo(new DnsAddressData(IPAddress.Parse("192.0.2.1")));
		await Assert.That(Convert.ToHexString(update.Encode())).IsEqualTo(Convert.ToHexString(message));

		// Without class ANY or NONE, an A record still needs its 4 bytes.
		await Assert.That(DnsMessage.TryDecode(Concat(Header(0, 0x8000, 0, 1, 0, 0), Record([0], 1, [])), out _)).IsFalse();
	}

	[Test]
	public async Task ReadsTheDataOfClassNoneInTheClassOfTheZone()
	{
		// RFC 2136, Sec. 2.5.4: with class NONE, the data is in the class of the zone.
		// A Chaosnet A record holds a name and a 16-bit address.
		byte[] chaosAddress = [.. Name("chaos", "example"), 0x12, 0x34];
		byte[] chaosZone = Concat(
			Header(9, 0x2800, 1, 0, 1, 0),
			Name("example"), U16(6), U16(3),
			Record(CompressedName(12, "host"), 1, chaosAddress, ttl: 0, @class: 254));
		byte[] internetZone = Concat(
			Header(9, 0x2800, 1, 0, 1, 0),
			Name("example"), U16(6), U16(1),
			Record(CompressedName(12, "host"), 1, [192, 0, 2, 1], ttl: 0, @class: 254));

		DnsMessage chaos = DnsMessage.Decode(chaosZone);
		DnsMessage internet = DnsMessage.Decode(internetZone);

		await Assert.That(chaos.Authorities[0].Class).IsEqualTo(DnsClass.None);
		await Assert.That(chaos.Authorities[0].Data).IsEqualTo(new DnsUnknownData(DnsRecordType.A, chaosAddress));
		await Assert.That(Convert.ToHexString(chaos.Encode())).IsEqualTo(Convert.ToHexString(chaosZone));
		await Assert.That(internet.Authorities[0].Class).IsEqualTo(DnsClass.None);
		await Assert.That(internet.Authorities[0].Data).IsEqualTo(new DnsAddressData(IPAddress.Parse("192.0.2.1")));
		await Assert.That(Convert.ToHexString(internet.Encode())).IsEqualTo(Convert.ToHexString(internetZone));
	}

	[Test]
	public async Task ReadsSrvDataOfClassInOnly()
	{
		// RFC 2782: SRV is a class IN type; in another class, its data is kept as it is.
		byte[] chaos = Concat(Header(0, 0x8000, 1, 1, 0, 0), Question, Record(Pointer(12), 33, [1, 2, 3], @class: 3));
		DnsMessage decoded = DnsMessage.Decode(chaos);

		await Assert.That(decoded.Answers[0].Data).IsEqualTo(new DnsUnknownData(DnsRecordType.Srv, (byte[])[1, 2, 3]));
		await Assert.That(Convert.ToHexString(decoded.Encode())).IsEqualTo(Convert.ToHexString(chaos));

		// In class IN, and in class NONE in an UPDATE of a zone of class IN.
		byte[] srv = [0x00, 0x01, 0x00, 0x02, 0x13, 0xC4, .. Pointer(12)];
		DnsSrvData expected = new(1, 2, 5060, DnsName.Parse("example.com"));
		byte[] internet = Concat(Header(0, 0x8000, 1, 1, 0, 0), Question, Record(Pointer(12), 33, srv));
		byte[] deletion = Concat(Header(0, 0x2800, 1, 0, 1, 0), Name("example", "com"), U16(6), U16(1), Record(Pointer(12), 33, srv, ttl: 0, @class: 254));

		await Assert.That(DnsMessage.Decode(internet).Answers[0].Data).IsEqualTo(expected);
		await Assert.That(DnsMessage.Decode(deletion).Authorities[0].Data).IsEqualTo(expected);
	}

	[Test]
	public async Task AcceptsACompressedSrvTargetAndWritesItInFull()
	{
		// RFC 3597, Sec. 4, asks receivers to accept compression in SRV data.
		byte[] message = Concat(
			Header(0, 0x8000, 1, 1, 0, 0),
			Question,
			Record(CompressedName(12, "_sip", "_tcp"), 33, [0x00, 0x01, 0x00, 0x02, 0x13, 0xC4, .. Pointer(12)]));
		DnsMessage decoded = DnsMessage.Decode(message);
		byte[] reencoded = decoded.Encode();

		await Assert.That(decoded.Answers[0].Data).IsEqualTo(new DnsSrvData(1, 2, 5060, DnsName.Parse("example.com")));
		await Assert.That(Convert.ToHexString(reencoded.AsSpan(reencoded.Length - 13))).IsEqualTo(Convert.ToHexString(Name("example", "com")));
	}

	[Test]
	public async Task KeepsTheDataOfOtherTypesAsIs()
	{
		// The data happens to look like a pointer; for a type without a class it is only bytes.
		byte[] message = Concat(Header(0, 0x8000, 1, 1, 0, 0), Question, Record(Pointer(12), 0xFF00, [0xC0, 0x0C, 0x00]));
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded.Answers[0].Data).IsEqualTo(new DnsUnknownData((DnsRecordType)0xFF00, (byte[])[0xC0, 0x0C, 0x00]));
		await Assert.That(Convert.ToHexString(decoded.Encode())).IsEqualTo(Convert.ToHexString(message));
	}

	[Test]
	public async Task KeepsTxtDataWithoutAStringAsUnknownData()
	{
		// TXT data without any string is kept rather than refused (RFC 1035, Sec. 3.3.14).
		byte[] message = Concat(Header(0, 0x8000, 0, 1, 0, 0), Record([0], 16, []));
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded.Answers[0].Data).IsEqualTo(new DnsUnknownData(DnsRecordType.Txt, ReadOnlyMemory<byte>.Empty));
		await Assert.That(Convert.ToHexString(decoded.Encode())).IsEqualTo(Convert.ToHexString(message));

		// A single empty string is a string.
		await Assert.That(DnsMessage.Decode(Concat(Header(0, 0x8000, 0, 1, 0, 0), Record([0], 16, [0]))).Answers[0].Data).IsEqualTo(new DnsTxtData([ReadOnlyMemory<byte>.Empty]));
	}

	[Test]
	public async Task ReadsAddressesOfClassInOnly()
	{
		// A Chaosnet A record holds a name and a 16-bit address. The second owner points to the first.
		byte[] chaosAddress = [.. Name("ch-host", "example"), 0x01, 0x23];
		byte[] message = Concat(
			Header(0, 0x8000, 0, 3, 0, 0),
			Record(Name("host", "example"), 1, chaosAddress, @class: 3),
			Record(Pointer(12), 28, [1, 2, 3], @class: 4),
			Record(Pointer(12), 1, [192, 0, 2, 1]));
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded.Answers[0].Data).IsEqualTo(new DnsUnknownData(DnsRecordType.A, chaosAddress));
		await Assert.That(decoded.Answers[1].Data).IsEqualTo(new DnsUnknownData(DnsRecordType.Aaaa, (byte[])[1, 2, 3]));
		await Assert.That(decoded.Answers[2].Data).IsEqualTo(new DnsAddressData(IPAddress.Parse("192.0.2.1")));
		await Assert.That(Convert.ToHexString(decoded.Encode())).IsEqualTo(Convert.ToHexString(message));
	}

	[Test]
	public async Task ExpandsTheNamesInMinfoData()
	{
		// RFC 1035, Sec. 3.3.7: both mailboxes point to the question.
		byte[] message = Concat(Header(0, 0x8000, 1, 1, 0, 0), Question, Record(Pointer(12), 14, [.. Pointer(12), .. Pointer(12)]));
		DnsUnknownData expanded = new((DnsRecordType)14, (byte[])[.. Name("example", "com"), .. Name("example", "com")]);
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded.Answers[0].Data).IsEqualTo(expanded);

		// Another question takes the place that the pointers led to.
		DnsMessage moved = decoded with { Questions = [new DnsQuestion(DnsName.Parse("other.example.net"), DnsRecordType.A)] };
		await Assert.That(DnsMessage.Decode(moved.Encode()).Answers[0].Data).IsEqualTo(expanded);
	}

	[Test]
	public async Task ExpandsTheNamesInTheDataOfEachOlderType()
	{
		byte[] example = Name("example", "com");
		byte[] afs = CompressedName(12, "afs");
		byte[] afsExpanded = Name("afs", "example", "com");

		// MD, MF, MB, MG and MR: a name (RFC 1035, Sec. 3.3).
		foreach (int type in (int[])[3, 4, 7, 8, 9])
		{
			await AssertExpanded(type, Pointer(12), example);
		}

		// MINFO and RP: two names (RFC 1035, Sec. 3.3.7; RFC 1183, Sec. 2.2).
		foreach (int type in (int[])[14, 17])
		{
			await AssertExpanded(type, [.. afs, .. Pointer(12)], [.. afsExpanded, .. example]);
		}

		// AFSDB and RT: a 16-bit field, then a name (RFC 1183, Sec. 1 and 3.3).
		foreach (int type in (int[])[18, 21])
		{
			await AssertExpanded(type, [0x00, 0x01, .. afs], [0x00, 0x01, .. afsExpanded]);
		}

		// PX: a 16-bit preference, then two names (RFC 2163).
		await AssertExpanded(26, [0x00, 0x0A, .. Pointer(12), .. afs], [0x00, 0x0A, .. example, .. afsExpanded]);

		// NAPTR: order, preference, and the strings flags, services and regexp, then the replacement (RFC 3403, Sec. 4.1).
		byte[] naptrFields = [0x00, 0x64, 0x00, 0x0A, 1, (byte)'u', 7, .. "E2U+sip"u8, 0];
		await AssertExpanded(35, [.. naptrFields, .. Pointer(12)], [.. naptrFields, .. example]);

		// SIG: 18 bytes of fixed fields, the signer, then the signature (RFC 2535, Sec. 4.1).
		byte[] sigFields = [0x00, 0x01, 5, 2, .. U32(3600), .. U32(2), .. U32(1), 0x12, 0x34];
		await AssertExpanded(24, [.. sigFields, .. Pointer(12), 0xAA, 0xBB], [.. sigFields, .. example, 0xAA, 0xBB]);

		// NXT: the next name, then the type bitmap (RFC 2535, Sec. 5.2).
		await AssertExpanded(30, [.. afs, 0x40, 0x01], [.. afsExpanded, 0x40, 0x01]);
	}

	[Test]
	public async Task ExpandedDataTakesAnArrayOfItsOwnLength()
	{
		byte[] example = Name("example", "com");
		byte[] sip = Name("sip", "example", "com");
		byte[] naptrFields = [0x00, 0x64, 0x00, 0x0A, 1, (byte)'u', 7, .. "E2U+sip"u8, 0];
		byte[] sigFields = [0x00, 0x01, 5, 2, .. U32(3600), .. U32(2), .. U32(1), 0x12, 0x34];

		(int Type, byte[] Data, byte[] Expected)[] cases =
		[
			// NAPTR, with the replacement uncompressed and as a pointer to the question.
			(35, [.. naptrFields, .. sip], [.. naptrFields, .. sip]),
			(35, [.. naptrFields, .. Pointer(12)], [.. naptrFields, .. example]),
			// RP: two names.
			(17, [.. CompressedName(12, "afs"), .. Pointer(12)], [.. Name("afs", "example", "com"), .. example]),
			// SIG: the signer between the fixed fields and the signature.
			(24, [.. sigFields, .. Pointer(12), 0xAA, 0xBB], [.. sigFields, .. example, 0xAA, 0xBB])
		];

		foreach ((int type, byte[] data, byte[] expected) in cases)
		{
			byte[] message = Concat(Header(0, 0x8000, 1, 1, 0, 0), Question, Record(Pointer(12), type, data));
			ReadOnlyMemory<byte> rawData = DnsMessage.Decode(message).Answers[0].Data is DnsUnknownData unknown ? unknown.RawData : default;
			bool isArray = MemoryMarshal.TryGetArray(rawData, out ArraySegment<byte> segment);

			await Assert.That(Convert.ToHexString(rawData.Span)).IsEqualTo(Convert.ToHexString(expected));
			await Assert.That(isArray).IsTrue();
			await Assert.That(segment.Offset).IsEqualTo(0);
			await Assert.That(segment.Array?.Length).IsEqualTo(expected.Length);
		}
	}

	[Test]
	public async Task KeepsPxDataOfOtherClassesAsIs()
	{
		// PX is a type of class IN, so in another class its data holds no names.
		byte[] message = Concat(Header(0, 0x8000, 1, 1, 0, 0), Question, Record(Pointer(12), 26, [0xC0], @class: 3));
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded.Answers[0].Data).IsEqualTo(new DnsUnknownData((DnsRecordType)26, (byte[])[0xC0]));
		await Assert.That(Convert.ToHexString(decoded.Encode())).IsEqualTo(Convert.ToHexString(message));
	}

	[Test]
	public async Task KeepsTheDataOfTypesThatItDoesNotParseUnchecked()
	{
		// SVCB data without its target name (RFC 9460, Sec. 2.2); the decoder does not parse SVCB.
		byte[] message = Concat(Header(0, 0x8000, 1, 1, 0, 0), Question, Record(Pointer(12), 64, [0x00, 0x01]));

		bool decoded = DnsMessage.TryDecode(message, out DnsMessage? response);

		await Assert.That(decoded).IsTrue();
		await Assert.That(response?.Answers[0].Data).IsEqualTo(new DnsUnknownData(DnsRecordType.Svcb, (byte[])[0x00, 0x01]));
	}

	[Test]
	public async Task FollowsPointersToPointers()
	{
		// The second answer's owner points to the first answer's owner, which points to the question.
		byte[] message = Concat(
			Header(0, 0x8000, 1, 2, 0, 0),
			Question,
			Record(Pointer(12), 1, [192, 0, 2, 1]),
			Record(Pointer(29), 1, [192, 0, 2, 2]));
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded.Answers[1].Name).IsEqualTo(DnsName.Parse("example.com"));
	}

	[Test]
	public async Task DecodesNamesInDataThatPointIntoEarlierData()
	{
		// Both names in the SOA data point to the name in the data of the CNAME record before it, at 41.
		byte[] message = Concat(
			Header(0, 0x8000, 1, 2, 0, 0),
			Question,
			Record(Pointer(12), 5, [.. CompressedName(12, "alias")]),
			Record(Pointer(12), 6, [.. Pointer(41), .. Pointer(41), .. U32(1), .. U32(2), .. U32(3), .. U32(4), .. U32(5)]));
		DnsMessage decoded = DnsMessage.Decode(message);
		DnsName alias = DnsName.Parse("alias.example.com");

		await Assert.That(decoded.Answers[0].Data).IsEqualTo(new DnsCNameData(alias));
		await Assert.That(decoded.Answers[1].Data).IsEqualTo(new DnsSoaData(alias, alias, 1, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(5)));
	}

	// Decodes a record of type with data and expects its names expanded, also after the question changes.
	private static async Task AssertExpanded(int type, byte[] data, byte[] expected)
	{
		byte[] message = Concat(Header(0, 0x8000, 1, 1, 0, 0), Question, Record(Pointer(12), type, data));
		DnsUnknownData expanded = new((DnsRecordType)type, expected);
		DnsMessage decoded = DnsMessage.Decode(message);
		DnsMessage moved = decoded with { Questions = [new DnsQuestion(DnsName.Parse("other.example.net"), DnsRecordType.A)] };

		await Assert.That(decoded.Answers[0].Data).IsEqualTo(expanded);
		await Assert.That(DnsMessage.Decode(moved.Encode()).Answers[0].Data).IsEqualTo(expanded);
	}
}
