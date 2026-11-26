using Dns.Net.Abstractions;
using System.Globalization;
using static Dns.Net.Tests.Equality;

namespace Dns.Net.Tests;

public class DnsNameTest
{
	[Test]
	[Arguments(@".")]
	[Arguments(@"\000\a\.\ aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
	[Arguments(@"\!.com")]
	[Arguments(@"\x23.com")]
	[Arguments(@"xn--fiq228c.xn--eqrt2g")]
	public async Task ParseAcceptsValidNames(string name)
	{
		await Assert.That(DnsName.TryParse(name, out DnsName result)).IsTrue();
		await Assert.That(DnsName.Parse(name)).IsEqualTo(result);
	}

	[Test]
	public async Task ParseRejectsNull()
	{
		await Assert.That(DnsName.TryParse(null, out _)).IsFalse();
		await Assert.That(() => DnsName.Parse(null!)).ThrowsExactly<ArgumentNullException>().WithParameterName("s");
	}

	[Test]
	public async Task TryEncodeWritesTheUncompressedWireFormat()
	{
		byte[] microsoft = [3, .. "www"u8, 9, .. "microsoft"u8, 3, .. "com"u8, 0];

		await AssertEncoding("www.microsoft.com", microsoft);
		await AssertEncoding("www.microsoft.com.", microsoft);
		await AssertEncoding(@"Donald\032E\.\032Eastlake\0323rd.example.", [22, .. "Donald"u8, 32, .. "E."u8, 32, .. "Eastlake"u8, 32, .. "3rd"u8, 7, .. "example"u8, 0]);
		await AssertEncoding(@"a\000\\\255z.example.", [5, (byte)'a', 0, (byte)'\\', 255, (byte)'z', 7, .. "example"u8, 0]);
	}

	[Test]
	[Arguments(@"a\.b", "03 61 2E 62 00")]
	[Arguments(@"a\\\.b", "04 61 5C 2E 62 00")]
	[Arguments(@"\065\097\126", "03 41 61 7E 00")]
	[Arguments(@"a\009b", "03 61 09 62 00")]
	[Arguments(@"\ x", "02 20 78 00")]
	[Arguments(@"\a\(\)", "03 61 28 29 00")]
	[Arguments(@"\.", "01 2E 00")]
	[Arguments(@"\\", "01 5C 00")]
	[Arguments(@"\..", "01 2E 00")]
	[Arguments(@"a\\.b", "02 61 5C 01 62 00")]
	[Arguments("a\\\tb", "03 61 09 62 00")]
	public async Task ParseTurnsEscapesIntoBytes(string name, string expected)
	{
		await AssertEncoding(name, Convert.FromHexString(expected.Replace(" ", string.Empty)));
	}

	[Test]
	[Arguments(63, true)]
	[Arguments(64, false)]
	public async Task LabelsHoldAtMost63Bytes(int length, bool valid)
	{
		string plain = new('x', length);
		string escaped = string.Concat(Enumerable.Repeat(@"\255", length));

		foreach (string name in (string[])[plain, $"{plain}.", $"{plain}.com", escaped, $"a.{escaped}.b"])
		{
			await Assert.That(DnsName.TryParse(name, out _)).IsEqualTo(valid);
		}
	}

	[Test]
	[Arguments(61, true)]
	[Arguments(62, false)]
	public async Task NamesHoldAtMost255Bytes(int lastLabelLength, bool valid)
	{
		// 3 × 64 + (lastLabelLength + 1) + 1 bytes: 255 for 61, 256 for 62.
		string label63 = new('a', 63);
		string name = $"{label63}.{label63}.{label63}.{new string('b', lastLabelLength)}";
		string escaped = string.Concat(name.Select(static c => c is '.' ? "." : $@"\{(int)c:D3}"));

		await Assert.That(DnsName.TryParse(name, out DnsName result)).IsEqualTo(valid);
		await Assert.That(DnsName.TryParse($"{name}.", out _)).IsEqualTo(valid);
		await Assert.That(DnsName.TryParse(escaped, out _)).IsEqualTo(valid);

		if (valid)
		{
			await Assert.That(result.EncodedLength).IsEqualTo(DnsName.MaxEncodedLength);
			await Assert.That(result.LabelCount).IsEqualTo(4);
		}
	}

	[Test]
	[Arguments(" example.com")]
	[Arguments("exa mple.com")]
	[Arguments("example.com ")]
	[Arguments("example\t.com")]
	[Arguments("example\n.com")]
	[Arguments("exa\u0000mple.com")]
	[Arguments("exa\u007Fmple.com")]
	[Arguments("exa\u00A0mple.com")]
	[Arguments("exémple.com")]
	[Arguments("例子.测试")]
	[Arguments(@"ex\ämple.com")]
	[Arguments("")]
	[Arguments("..")]
	[Arguments(".com")]
	[Arguments("a..com")]
	[Arguments("a..")]
	[Arguments(@"\")]
	[Arguments(@"a\")]
	[Arguments(@"\1")]
	[Arguments(@"\12")]
	[Arguments(@"\1x3")]
	[Arguments(@"\12x.com")]
	[Arguments(@"\256")]
	[Arguments(@"\999")]
	public async Task ParseRejectsInvalidNames(string name)
	{
		await Assert.That(DnsName.TryParse(name, out _)).IsFalse();
		await Assert.That(() => DnsName.Parse(name)).Throws<FormatException>();
	}

	[Test]
	public async Task RootHasNoLabels()
	{
		foreach (DnsName root in (DnsName[])[DnsName.Root, default, DnsName.Parse(".")])
		{
			await Assert.That(root.IsRoot).IsTrue();
			await Assert.That(root.LabelCount).IsEqualTo(0);
			await Assert.That(root.ToString()).IsEqualTo(".");
			await Assert.That(root).IsEqualTo(DnsName.Root);
			await AssertEncoding(root, [0]);
		}

		await Assert.That(DnsName.Parse("com").IsRoot).IsFalse();
	}

	[Test]
	[Arguments("www.Example.COM.", "www.Example.COM")]
	[Arguments(@"Donald\032E\.\032Eastlake\0323rd.example.", @"Donald\032E\.\032Eastlake\0323rd.example")]
	[Arguments(@"a\000\\\255z.example.", @"a\000\\\255z.example")]
	[Arguments(@"\a\(\033\126", @"a\(!~")]
	[Arguments(@"\127\128\032\009", @"\127\128\032\009")]
	[Arguments(@"a\\.b", @"a\\.b")]
	[Arguments(@"acct\.\\\""\(\)\;\@\$prod.example", @"acct\.\\\""\(\)\;\@\$prod.example")]
	public async Task ToStringEscapesSpecialCharactersAndNonPrintableBytes(DnsName name, string expected)
	{
		await Assert.That(name.ToString()).IsEqualTo(expected);
		await Assert.That($"{name}").IsEqualTo(expected);
	}

	[Test]
	public async Task TryFormatNeedsRoomForTheWholeName()
	{
		// a\.b.c takes 6 characters.
		DnsName name = DnsName.Parse(@"a\.b.c");
		char[] buffer = new char[6];

		await Assert.That(name.TryFormat(buffer.AsSpan(0, 5), out int charsWritten)).IsFalse();
		await Assert.That(charsWritten).IsEqualTo(0);
		await Assert.That(name.TryFormat(buffer, out charsWritten)).IsTrue();
		await Assert.That(new string(buffer, 0, charsWritten)).IsEqualTo(@"a\.b.c");
	}

	[Test]
	[Arguments(0)]
	[Arguments(128)]
	public async Task ParseOfToStringReturnsTheSameBytes(int start)
	{
		// Every byte value, in labels of up to 63 bytes, in two names that each stay within 255 bytes.
		string text = string.Join('.', Enumerable.Range(start, 128).Chunk(43).Select(static label => string.Concat(label.Select(static value => $@"\{value:D3}"))));
		DnsName name = DnsName.Parse(text);
		byte[] encoded = Encode(name);
		byte[] reparsed = Encode(DnsName.Parse(name.ToString()));

		await Assert.That(encoded.Length).IsEqualTo(128 + 3 + 1);
		await Assert.That(Convert.ToHexString(reparsed)).IsEqualTo(Convert.ToHexString(encoded));
	}

	[Test]
	public async Task EqualityIgnoresTheCaseOfAsciiLettersOnly()
	{
		DnsName lower = DnsName.Parse("www.example.com");
		DnsName mixed = DnsName.Parse("WWW.Example.COM.");

		await AssertEqual(lower, mixed);
		await Assert.That(lower == mixed).IsTrue();
		await Assert.That(lower != mixed).IsFalse();
		await Assert.That(lower.Equals((object)mixed)).IsTrue();

		// Folding every byte with 0x20 would equate these pairs; \192 and \224 are À and à.
		await Assert.That(DnsName.Parse("@")).IsNotEqualTo(DnsName.Parse("`"));
		await Assert.That(DnsName.Parse("[")).IsNotEqualTo(DnsName.Parse("{"));
		await Assert.That(DnsName.Parse(@"\192")).IsNotEqualTo(DnsName.Parse(@"\224"));

		await Assert.That(DnsName.Parse("a.b")).IsNotEqualTo(DnsName.Parse("ab"));
		await Assert.That(DnsName.Parse("a.b")).IsNotEqualTo(DnsName.Parse(@"a\.b"));
		await Assert.That(lower).IsNotEqualTo(DnsName.Root);
		// ReSharper disable once SuspiciousTypeConversion.Global
		await Assert.That(lower.Equals("www.example.com")).IsFalse();

		// The case survives the comparison.
		await Assert.That(mixed.ToString()).IsEqualTo("WWW.Example.COM");
	}

	[Test]
	[Arguments("www.example.com", "example.com", true)]
	[Arguments("example.com", "example.com", true)]
	[Arguments("WWW.EXAMPLE.com", "example.COM", true)]
	[Arguments("example.com", "www.example.com", false)]
	[Arguments("badexample.com", "example.com", false)]
	[Arguments("a.example.com", "b.example.com", false)]
	[Arguments("example.com", ".", true)]
	[Arguments(".", ".", true)]
	[Arguments(".", "com", false)]
	// The encoded name ends with the bytes of example.com, inside a label.
	[Arguments(@"www\007example.com", "example.com", false)]
	public async Task IsSubdomainOfComparesWholeTrailingLabels(DnsName name, DnsName ancestor, bool expected)
	{
		await Assert.That(name.IsSubdomainOf(ancestor)).IsEqualTo(expected);
	}

	[Test]
	public async Task GenericParsingUsesThePresentationFormat()
	{
		await Assert.That(ParseGeneric<DnsName>("Example.com.").ToString()).IsEqualTo("Example.com");
		await Assert.That(TryParseSpanGeneric<DnsName>("a..b")).IsFalse();
	}

	[Test]
	public async Task TryEncodeLeavesShortDestinationsAlone()
	{
		DnsName name = DnsName.Parse("example.com");
		byte[] buffer = [0xAA, 0xAA, 0xAA];

		await Assert.That(name.TryEncode(buffer, out int bytesWritten)).IsFalse();
		await Assert.That(bytesWritten).IsEqualTo(0);
		await Assert.That(Convert.ToHexString(buffer)).IsEqualTo("AAAAAA");
	}

	[Test]
	[Arguments(@".")]
	[Arguments(@"Www.Example.COM")]
	[Arguments(@"a\.b.example")]
	[Arguments(@"a\032b.\255\255.example")]
	public async Task TryDecodeReadsWhatTryEncodeWrites(DnsName name)
	{
		await AssertDecoding(name);
	}

	[Test]
	public async Task TryDecodeReadsLabelsAndNamesOfTheMaximumLength()
	{
		await AssertDecoding(DnsName.Parse($"{new string('a', DnsName.MaxLabelLength)}.example"));

		// 3 × 64 + 62 + 1 = 255 bytes.
		DnsName longest = DnsName.Parse($"{new string('a', 63)}.{new string('b', 63)}.{new string('c', 63)}.{new string('d', 61)}");
		await Assert.That(longest.EncodedLength).IsEqualTo(DnsName.MaxEncodedLength);
		await AssertDecoding(longest);
	}

	[Test]
	public async Task TryDecodeStopsAtTheEndOfTheName()
	{
		// SVCB RDATA (RFC 9460): priority 1, target dns.example.net, then alpn=h2.
		byte[] rdata = [0x00, 0x01, 3, .. "dns"u8, 7, .. "example"u8, 3, .. "net"u8, 0, 0x00, 0x01, 0x00, 0x03, 2, .. "h2"u8];

		bool decoded = DnsName.TryDecode(rdata.AsSpan(2), out DnsName target, out int bytesConsumed);

		await Assert.That(decoded).IsTrue();
		await Assert.That(target.ToString()).IsEqualTo("dns.example.net");
		await Assert.That(bytesConsumed).IsEqualTo(17);
		await Assert.That(Convert.ToHexString(rdata.AsSpan(2 + bytesConsumed))).IsEqualTo("00010003026832");
	}

	[Test]
	public async Task TryDecodeRejectsWhatIsNotAnUncompressedName()
	{
		await AssertNotDecoded([]);
		// A compression pointer, cut short and whole.
		await AssertNotDecoded([0xC0]);
		await AssertNotDecoded([0xC0, 0x0C]);
		await AssertNotDecoded([3, .. "www"u8, 0xC0, 0x00]);
		// A pointer back to offset 12, the 0 inside the label of 20 bytes that leads to it.
		await AssertNotDecoded([20, .. "xxxxxxxxxxx"u8, 0, .. "xxxxxxxx"u8, 0xC0, 0x0C]);
		// The extended label types 01 and 10.
		await AssertNotDecoded([0x40, 0]);
		await AssertNotDecoded([0x80, 0]);
		// A label that runs past the input, and labels without the root label.
		await AssertNotDecoded([5, .. "abc"u8, 0]);
		await AssertNotDecoded([3, .. "abc"u8]);
		await AssertNotDecoded([3, .. "abc"u8, 3, .. "com"u8]);

		// Three labels of 63 bytes and one of 62: 256 bytes, even with bytes after the name.
		byte[] tooLong = [.. Encode(DnsName.Parse($"{new string('a', 63)}.{new string('b', 63)}.{new string('c', 63)}")).AsSpan(0, 192), 62, .. new byte[62], 0];
		await Assert.That(tooLong.Length).IsEqualTo(DnsName.MaxEncodedLength + 1);
		await AssertNotDecoded(tooLong);
		await AssertNotDecoded([.. tooLong, 0]);
	}

	private static byte[] Encode(DnsName name)
	{
		byte[] encoded = new byte[name.EncodedLength];
		name.TryEncode(encoded, out _);
		return encoded;
	}

	private static async Task AssertEncoding(string name, byte[] expected)
	{
		await AssertEncoding(DnsName.Parse(name), expected);
	}

	private static async Task AssertEncoding(DnsName name, byte[] expected)
	{
		byte[] buffer = new byte[expected.Length];

		await Assert.That(name.EncodedLength).IsEqualTo(expected.Length);
		await Assert.That(name.TryEncode(buffer, out int bytesWritten)).IsTrue();
		await Assert.That(bytesWritten).IsEqualTo(expected.Length);
		await Assert.That(Convert.ToHexString(buffer)).IsEqualTo(Convert.ToHexString(expected));
	}

	// Decodes name alone and followed by other bytes.
	private static async Task AssertDecoding(DnsName name)
	{
		byte[] encoded = Encode(name);

		foreach (byte[] source in (byte[][])[encoded, [.. encoded, 0xC0, 0x0C, 0xFF]])
		{
			bool decoded = DnsName.TryDecode(source, out DnsName result, out int bytesConsumed);

			await Assert.That(decoded).IsTrue();
			await Assert.That(bytesConsumed).IsEqualTo(encoded.Length);
			await Assert.That(Convert.ToHexString(Encode(result))).IsEqualTo(Convert.ToHexString(encoded));
			await Assert.That(result.ToString()).IsEqualTo(name.ToString());
		}
	}

	private static async Task AssertNotDecoded(byte[] source)
	{
		bool decoded = DnsName.TryDecode(source, out DnsName result, out int bytesConsumed);

		await Assert.That(decoded).IsFalse();
		await Assert.That(result.IsRoot).IsTrue();
		await Assert.That(bytesConsumed).IsEqualTo(0);
	}

	private static T ParseGeneric<T>(string s) where T : IParsable<T>
	{
		return T.Parse(s, CultureInfo.InvariantCulture);
	}

	private static bool TryParseSpanGeneric<T>(ReadOnlySpan<char> s) where T : ISpanParsable<T>
	{
		return T.TryParse(s, CultureInfo.InvariantCulture, out _);
	}
}
