using Dns.Net.Abstractions;
using static Dns.Net.Tests.Wire;

namespace Dns.Net.Tests;

// Each case breaks one rule; a control just within a limit must still decode.
public class DnsMessageMalformedInputTest
{
	// example.com A IN, at offsets 12 to 28.
	private static readonly byte[] Question = [.. Name("example", "com"), 0x00, 0x01, 0x00, 0x01];

	private static readonly byte[] Address = [192, 0, 2, 1];

	[Test]
	public async Task AcceptsTheResponseThatTheCasesBreak()
	{
		await AssertAccepted(Response(Record(Pointer(12), 1, Address)));
	}

	[Test]
	public async Task RejectsTruncatedHeaders()
	{
		byte[] header = Header(1, 0x8180, 0, 0, 0, 0);

		await AssertRejected([]);
		await AssertRejected(header.AsSpan(0, 11).ToArray());
		await AssertAccepted(header);
	}

	[Test]
	public async Task RejectsMessagesLongerThan65535Bytes()
	{
		// The header takes 12 bytes and a record owned by the root 11 before its data.
		byte[] longest = Concat(Header(1, 0x8000, 0, 1, 0, 0), Record([0], 0xFF00, new byte[DnsMessage.MaxEncodedLength - 12 - 11]));
		byte[] tooLong = Concat(Header(1, 0x8000, 0, 1, 0, 0), Record([0], 0xFF00, new byte[DnsMessage.MaxEncodedLength - 12 - 11 + 1]));

		await Assert.That(longest.Length).IsEqualTo(DnsMessage.MaxEncodedLength);
		DnsMessage decoded = await AssertAccepted(longest);
		await Assert.That(decoded.Encode().Length).IsEqualTo(DnsMessage.MaxEncodedLength);

		await Assert.That(tooLong.Length).IsEqualTo(DnsMessage.MaxEncodedLength + 1);
		await AssertRejected(tooLong);

		// Records that each fit, but not together: 12 + 2 × (11 + 32751) = 65536 bytes.
		byte[] half = new byte[32751];
		await AssertRejected(Concat(Header(1, 0x8000, 0, 2, 0, 0), Record([0], 0xFF00, half), Record([0], 0xFF00, half)));
	}

	[Test]
	public async Task RejectsPointersBeyondTheMessage()
	{
		await AssertRejected(Response(Record(Pointer(0x3FF0), 1, Address)));
	}

	[Test]
	public async Task RejectsPointersCutOffByTheEndOfTheMessage()
	{
		await AssertRejected([.. Header(1, 0x8180, 1, 1, 0, 0), .. Question, 0xC0]);
	}

	[Test]
	public async Task RejectsForwardPointers()
	{
		// The owner at 29 points to 33, inside the record's own TTL.
		await AssertRejected(Response(Record(Pointer(33), 1, Address)));
	}

	[Test]
	public async Task RejectsPointersToThemselves()
	{
		await AssertRejected(Response(Record(Pointer(29), 1, Address)));
	}

	[Test]
	public async Task RejectsPointerLoops()
	{
		// The first answer's data, at 41, points to the second answer's owner at 43, which points back to 41.
		byte[] message = Response(
			Record(Pointer(12), 0xFF00, Pointer(43)),
			Record(Pointer(41), 1, Address));

		await AssertRejected(message);
	}

	[Test]
	public async Task RejectsPointersWhoseLabelsRunIntoTheReferringName()
	{
		// The owner at 45 points to the label at 43, of length 3 but holding only "a".
		byte[] message = Response(
			Record(Pointer(12), 0xFF00, [0, 0, 3, (byte)'a']),
			Record(Pointer(43), 1, Address));

		await AssertRejected(message);
	}

	[Test]
	public async Task RejectsPointersIntoTheLabelsThatLeadToThem()
	{
		// The owner at 29 is a label of length 3 that holds "a", 0 and "b", then a pointer to the 0 at 31, inside that label.
		await AssertRejected(Response(Record([3, (byte)'a', 0, (byte)'b', .. Pointer(31)], 1, Address)));
	}

	[Test]
	public async Task RejectsPointersIntoTheHeader()
	{
		await AssertRejected(Response(Record(Pointer(4), 1, Address)));
	}

	[Test]
	[Arguments(0x40)]
	[Arguments(0x80)]
	public async Task RejectsExtendedLabelTypes(int labelType)
	{
		byte[] message = [.. Header(1, 0, 1, 0, 0, 0), (byte)(labelType | 1), (byte)'a', 0, 0x00, 0x01, 0x00, 0x01];

		await AssertRejected(message);
		await AssertAccepted([.. Header(1, 0, 1, 0, 0, 0), 1, (byte)'a', 0, 0x00, 0x01, 0x00, 0x01]);

		// Read as a pointer, this owner would lead back to the question's name at 12.
		await AssertRejected(Response(Record([(byte)labelType, 12], 1, Address)));
	}

	[Test]
	public async Task RejectsNamesThatPointersMakeLongerThan255Bytes()
	{
		// The question is a name of exactly 255 bytes; the owner adds the label x to it.
		string label63 = new('a', 63);
		byte[] question = [.. Name(label63, label63, label63, new string('b', 61)), 0x00, 0x01, 0x00, 0x01];
		byte[] header = Header(1, 0x8180, 1, 1, 0, 0);

		await AssertRejected(Concat(header, question, Record(CompressedName(12, "x"), 1, Address)));
		await AssertAccepted(Concat(header, question, Record(Pointer(12), 1, Address)));
	}

	[Test]
	public async Task RejectsNamesLongerThan255Bytes()
	{
		string label63 = new('a', 63);

		await AssertRejected([.. Header(1, 0, 1, 0, 0, 0), .. Name(label63, label63, label63, new string('b', 62)), 0x00, 0x01, 0x00, 0x01]);
	}

	[Test]
	[Arguments(126, true)]
	[Arguments(127, false)]
	public async Task LimitsTheNumberOfPointersInAName(int chainLength, bool accepted)
	{
		// The first answer's data, from 41, is a chain of pointers back to the question; the second owner follows chainLength + 1 pointers.
		byte[] chain = [.. Enumerable.Range(0, chainLength).SelectMany(i => Pointer(i is 0 ? 12 : 41 + 2 * (i - 1)))];
		byte[] message = Response(
			Record(Pointer(12), 0xFF00, chain),
			Record(Pointer(41 + 2 * (chainLength - 1)), 1, Address));

		if (accepted)
		{
			DnsMessage decoded = await AssertAccepted(message);
			await Assert.That(decoded.Answers[1].Name).IsEqualTo(DnsName.Parse("example.com"));
		}
		else
		{
			await AssertRejected(message);
		}
	}

	[Test]
	public async Task RejectsTruncatedNamesAndQuestions()
	{
		byte[] header = Header(1, 0, 1, 0, 0, 0);

		// Long enough for a question, so that the name itself runs out.
		await AssertRejected([.. header, 7, .. "exa"u8, 0, 0]);
		await AssertRejected([.. header, .. Name("example", "com"), 0x00, 0x01, 0x00]);
	}

	[Test]
	public async Task RejectsDataLengthsBeyondTheMessage()
	{
		// The RDATA length, at 39 and 40, says 5 where 4 bytes remain.
		byte[] message = Response(Record(Pointer(12), 1, Address));
		message[40] = 5;

		await AssertRejected(message);
	}

	[Test]
	public async Task RejectsCountsThatTheMessageCannotHoldWithoutAllocatingForThem()
	{
		byte[] forged = Header(1, 0x8180, 0, 0xFFFF, 0xFFFF, 0xFFFF);

		// The first call warms up anything that runs once.
		_ = DnsMessage.TryDecode(forged, out _);
		long before = GC.GetAllocatedBytesForCurrentThread();
		bool decoded = DnsMessage.TryDecode(forged, out DnsMessage? message);
		long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

		await Assert.That(decoded).IsFalse();
		await Assert.That(message).IsNull();
		await Assert.That(allocated).IsLessThan(1024);
		await AssertRejected(forged);
		await AssertRejected(Concat(Header(1, 0x8180, 1, 2, 0, 0), Question, Record(Pointer(12), 1, Address)));
	}

	[Test]
	public async Task RejectsOptRecordsOutsideTheAdditionalSection()
	{
		byte[] opt = Record([0], 41, [], ttl: 0, @class: 1232);

		await AssertRejected(Concat(Header(1, 0x8180, 1, 1, 0, 0), Question, opt));
		await AssertRejected(Concat(Header(1, 0x8180, 1, 0, 1, 0), Question, opt));
		await AssertAccepted(Concat(Header(1, 0x8180, 1, 0, 0, 1), Question, opt));
	}

	[Test]
	public async Task RejectsASecondOptRecord()
	{
		byte[] opt = Record([0], 41, [], ttl: 0, @class: 1232);

		await AssertRejected(Concat(Header(1, 0x8180, 1, 0, 0, 2), Question, opt, opt));
	}

	[Test]
	public async Task RejectsOptRecordsNotOwnedByTheRoot()
	{
		await AssertRejected(Concat(Header(1, 0x8180, 1, 0, 0, 1), Question, Record(Pointer(12), 41, [], ttl: 0, @class: 1232)));
	}

	[Test]
	public async Task RejectsEdnsOptionsThatRunPastTheOptRecord()
	{
		await AssertRejected(Concat(Header(1, 0x8180, 1, 0, 0, 1), Question, Record([0], 41, [0x00, 0x0A, 0x00, 0x08, 1], ttl: 0, @class: 1232)));
		await AssertRejected(Concat(Header(1, 0x8180, 1, 0, 0, 1), Question, Record([0], 41, [0x00, 0x0A, 0x00], ttl: 0, @class: 1232)));
	}

	[Test]
	public async Task RejectsBytesAfterTheLastSection()
	{
		await AssertRejected([.. Response(Record(Pointer(12), 1, Address)), 0]);
	}

	[Test]
	[Arguments(1, 3)]
	[Arguments(1, 5)]
	[Arguments(28, 4)]
	[Arguments(28, 15)]
	[Arguments(28, 17)]
	public async Task RejectsAddressesOfTheWrongLength(int type, int length)
	{
		await AssertRejected(Response(Record(Pointer(12), type, new byte[length])));
	}

	[Test]
	public async Task RejectsNamesThatRunPastTheirData()
	{
		// The CNAME data holds 3 bytes of a label of 3, whose last byte and the root label follow outside it.
		await AssertRejected([.. Response(Record(Pointer(12), 5, [3, (byte)'w', (byte)'w'])), (byte)'w', 0]);
	}

	[Test]
	public async Task RejectsDataLongerThanItsType()
	{
		await AssertRejected(Response(Record(Pointer(12), 15, [0x00, 0x0A, .. Pointer(12), 0])));
		await AssertRejected(Response(Record(Pointer(12), 2, [.. Pointer(12), 0])));
		await AssertRejected(Response(Record(Pointer(12), 6, [.. Pointer(12), .. Pointer(12), .. new byte[21]])));
		await AssertAccepted(Response(Record(Pointer(12), 6, [.. Pointer(12), .. Pointer(12), .. new byte[20]])));
	}

	[Test]
	public async Task RejectsDataShorterThanItsType()
	{
		await AssertRejected(Response(Record(Pointer(12), 15, [0x00])));
		await AssertRejected(Response(Record(Pointer(12), 33, [0x00, 0x01, 0x00, 0x02, 0x13])));
		await AssertRejected(Response(Record(Pointer(12), 6, [.. Pointer(12), .. Pointer(12), .. new byte[19]])));
	}

	[Test]
	public async Task RejectsTxtStringsThatRunPastTheirData()
	{
		await AssertRejected(Response(Record(Pointer(12), 16, [5, (byte)'a', (byte)'b'])));
		await AssertRejected(Response(Record(Pointer(12), 16, [1, (byte)'a', 1])));
		await AssertAccepted(Response(Record(Pointer(12), 16, [1, (byte)'a', 0])));
	}

	[Test]
	public async Task RejectsMalformedDataOfOlderTypesWithNames()
	{
		// MINFO: a pointer beyond the message, a missing second name, and a byte after the second name.
		await AssertRejected(Response(Record(Pointer(12), 14, [.. Pointer(12), .. Pointer(0x3FF0)])));
		await AssertRejected(Response(Record(Pointer(12), 14, Pointer(12))));
		await AssertRejected(Response(Record(Pointer(12), 14, [.. Pointer(12), .. Pointer(12), 0])));
		await AssertAccepted(Response(Record(Pointer(12), 14, [.. Pointer(12), .. Pointer(12)])));

		// AFSDB with its 16-bit subtype cut short, NAPTR with a string that runs past the data, and SIG with 17 of its 18 bytes of fixed fields.
		await AssertRejected(Response(Record(Pointer(12), 18, [0x00])));
		await AssertRejected(Response(Record(Pointer(12), 35, [0x00, 0x0A, 0x00, 0x64, 5, (byte)'u'])));
		await AssertRejected(Response(Record(Pointer(12), 24, new byte[17])));
	}

	[Test]
	public async Task RejectsDataThatItsNamesMakeLongerThan65535Bytes()
	{
		// A message of 65532 bytes gives data of exactly 65535 bytes once its names are expanded; one of 65535 bytes, 3 more.
		DnsMessage longest = await AssertAccepted(ExpandingSig(65532));
		await Assert.That(longest.Answers[0].Data).IsTypeOf<DnsUnknownData>();
		await Assert.That(((DnsUnknownData)longest.Answers[0].Data).RawData.Length).IsEqualTo(65535);

		byte[] tooLong = ExpandingSig(65535);
		await AssertRejected(tooLong);
		await Assert.That(() => DnsMessage.Decode(tooLong)).Throws<InvalidDataException>().WithMessageContaining("names expanded");
	}

	// A response of length bytes whose SIG signer, a 2-byte pointer into the owner and fields, expands to 90 bytes.
	private static byte[] ExpandingSig(int length)
	{
		byte[] message = new byte[length];
		Header(0, 0x8000, 0, 1, 0, 0).CopyTo(message, 0);
		// The owner: one label of 61 bytes, at 12 to 74, whose first byte is the first label of the signer, of 63 bytes, at 13 to 76.
		message[12] = 61;
		message[13] = 63;
		message.AsSpan(14, 60).Fill((byte)'a');
		// Type SIG, at 75. The upper class byte starts the signer's second label, of 7 bytes, at 77 to 84.
		U16(24).CopyTo(message, 75);
		U16(0x0701).CopyTo(message, 77);
		U32(60).CopyTo(message, 79);
		U16(length - 85).CopyTo(message, 83);
		// The 18 bytes of fixed fields, at 85 to 102, are the third label of the signer, of 16 bytes, and the root label that ends it.
		message[85] = 16;
		message.AsSpan(86, 16).Fill((byte)'b');
		// The signer, a pointer to 13, then the signature, of zeros.
		Pointer(13).CopyTo(message, 103);
		return message;
	}

	// A response to the question, with the records as its answers.
	private static byte[] Response(params ReadOnlySpan<byte[]> answers)
	{
		return Concat([Header(1, 0x8180, 1, answers.Length, 0, 0), Question, .. answers]);
	}

	private static async Task<DnsMessage> AssertAccepted(byte[] message)
	{
		await Assert.That(DnsMessage.TryDecode(message, out DnsMessage? decoded)).IsTrue();
		await Assert.That(decoded).IsNotNull();
		return DnsMessage.Decode(message);
	}

	private static async Task AssertRejected(byte[] message)
	{
		await Assert.That(DnsMessage.TryDecode(message, out DnsMessage? decoded)).IsFalse();
		await Assert.That(decoded).IsNull();
		await Assert.That(() => DnsMessage.Decode(message)).Throws<InvalidDataException>();
	}
}
