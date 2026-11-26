using Dns.Net.Abstractions;
using static Dns.Net.Tests.Equality;
using static Dns.Net.Tests.Wire;

namespace Dns.Net.Tests;

public class DnsEdnsTest
{
	private const DnsEdnsFlags Unnamed = (DnsEdnsFlags)0x0005;

	[Test]
	[Arguments(0x0000)]
	[Arguments(0x0001)]
	[Arguments(0x4000)]
	[Arguments(0x8000)]
	[Arguments(0xC000)]
	[Arguments(0xFFFF)]
	public async Task KeepsEveryFlagThroughTheWireFormat(int flags)
	{
		// Extended response code 1 sits beside the flags.
		byte[] message = Concat(Header(1, 0x8000, 0, 0, 0, 1), Record([0], 41, [], ttl: 0x01000000u | (uint)flags, @class: 1232));
		DnsMessage decoded = DnsMessage.Decode(message);

		await Assert.That(decoded.Edns!.Flags).IsEqualTo((DnsEdnsFlags)flags);
		await Assert.That(decoded.Edns.DnssecOk).IsEqualTo((flags & 0x8000) is not 0);
		await Assert.That(Convert.ToHexString(decoded.Encode())).IsEqualTo(Convert.ToHexString(message));
	}

	[Test]
	public async Task EqualityComparesEveryFlag()
	{
		DnsEdns dnssecOk = new() { Flags = DnsEdnsFlags.DnssecOk };
		DnsEdns both = new() { Flags = DnsEdnsFlags.DnssecOk | DnsEdnsFlags.CompactAnswersOk };

		await Assert.That(dnssecOk).IsNotEqualTo(both);
		await AssertEqual(both, new DnsEdns { Flags = DnsEdnsFlags.CompactAnswersOk, DnssecOk = true });
		await Assert.That(new DnsEdns { Flags = Unnamed }).IsNotEqualTo(new DnsEdns());
	}

	[Test]
	public async Task DnssecOkChangesOnlyTheDoBit()
	{
		DnsEdns edns = new() { Flags = DnsEdnsFlags.DnssecOk | DnsEdnsFlags.CompactAnswersOk | Unnamed };

		await Assert.That((edns with { DnssecOk = false }).Flags).IsEqualTo(DnsEdnsFlags.CompactAnswersOk | Unnamed);
		await Assert.That((edns with { DnssecOk = false } with { DnssecOk = true }).Flags).IsEqualTo(edns.Flags);
		await Assert.That(new DnsEdns { DnssecOk = true }.Flags).IsEqualTo(DnsEdnsFlags.DnssecOk);
	}

	[Test]
	public async Task CreateResponseCopiesTheDoBitOnly()
	{
		// Only DO is copied (RFC 3225, Sec. 3).
		DnsMessage request = new() { Edns = new DnsEdns { Flags = DnsEdnsFlags.DnssecOk | DnsEdnsFlags.CompactAnswersOk | Unnamed } };
		DnsMessage withoutDo = new() { Edns = new DnsEdns { Flags = DnsEdnsFlags.CompactAnswersOk } };

		await Assert.That(request.CreateResponse().Edns!.Flags).IsEqualTo(DnsEdnsFlags.DnssecOk);
		await Assert.That(withoutDo.CreateResponse().Edns!.Flags).IsEqualTo(DnsEdnsFlags.None);
	}

	[Test]
	public async Task ToStringShowsTheFlagsAsDigDoes()
	{
		await Assert.That(new DnsEdns().ToString()).IsEqualTo("; EDNS: version: 0, flags:; udp: 1232");
		await Assert.That(new DnsEdns { Flags = DnsEdnsFlags.DnssecOk | DnsEdnsFlags.CompactAnswersOk }.ToString()).IsEqualTo("; EDNS: version: 0, flags: do co; udp: 1232");
		await Assert.That(new DnsEdns { Flags = DnsEdnsFlags.CompactAnswersOk | Unnamed, UdpPayloadSize = 512 }.ToString()).IsEqualTo("; EDNS: version: 0, flags: co; MBZ: 0x0005, udp: 512");
	}

	[Test]
	public async Task OptionToStringShowsTheCodeAndHex()
	{
		await Assert.That(new DnsEdnsOption(DnsEdnsOptionCode.Nsid, "ns1"u8.ToArray()).ToString()).IsEqualTo("NSID: 6E7331");
		await Assert.That(new DnsEdnsOption((DnsEdnsOptionCode)65001, ReadOnlyMemory<byte>.Empty).ToString()).IsEqualTo("OPT=65001:");
	}

	[Test]
	public async Task OptionsCompareTheirBytes()
	{
		DnsEdnsOption option = new(DnsEdnsOptionCode.Cookie, (byte[])[1, 2, 3]);

		await AssertEqual(option, new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[1, 2, 3]));
		await Assert.That(option).IsNotEqualTo(new DnsEdnsOption(DnsEdnsOptionCode.Padding, (byte[])[1, 2, 3]));
		await Assert.That(option).IsNotEqualTo(new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[1, 2]));

		await AssertEqual(new DnsEdns { Options = [option] }, new DnsEdns { Options = [new DnsEdnsOption(DnsEdnsOptionCode.Cookie, (byte[])[1, 2, 3])] });
		await Assert.That(new DnsEdns { Options = [option] }).IsNotEqualTo(new DnsEdns());
		await Assert.That(new DnsEdns()).IsNotEqualTo(new DnsEdns { DnssecOk = true });
	}
}
