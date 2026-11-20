using Dns.Net.Abstractions;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Dns.Net.Tests;

// A test-only query record type for HINFO (RFC 1035, Sec. 3.3.2), read from DnsUnknownData.
internal readonly record struct HinfoRecord(string Cpu, string Os, TimeSpan Ttl) : IDnsQueryRecord<HinfoRecord>
{
	public const DnsRecordType HinfoType = (DnsRecordType)13;

	// Data that claims a string of 5 bytes but holds 1.
	public static DnsUnknownData Malformed { get; } = new(HinfoType, new byte[] { 5, (byte)'x' });

	public static DnsRecordType Type => HinfoType;

	public static HinfoRecord[] CreateRecords(ReadOnlySpan<DnsResourceRecord> answers, TimeSpan ttl, DnsMessage response)
	{
		List<HinfoRecord> records = [];

		foreach (DnsResourceRecord answer in answers)
		{
			if (answer.Data is DnsUnknownData { RawData: var data } && TryRead(data.Span, out string? cpu, out string? os))
			{
				records.Add(new HinfoRecord(cpu, os, ttl));
			}
		}

		return [.. records];
	}

	public static DnsUnknownData Data(string cpu, string os)
	{
		return new DnsUnknownData(HinfoType, (byte[])[(byte)cpu.Length, .. Encoding.ASCII.GetBytes(cpu), (byte)os.Length, .. Encoding.ASCII.GetBytes(os)]);
	}

	// Two character strings and nothing after them.
	private static bool TryRead(ReadOnlySpan<byte> data, [NotNullWhen(true)] out string? cpu, [NotNullWhen(true)] out string? os)
	{
		cpu = null;
		os = null;

		if (data.Length < 1 || data.Length < 1 + data[0])
		{
			return false;
		}

		ReadOnlySpan<byte> rest = data.Slice(1 + data[0]);

		if (rest.Length < 1 || rest.Length != 1 + rest[0])
		{
			return false;
		}

		cpu = Encoding.ASCII.GetString(data.Slice(1, data[0]));
		os = Encoding.ASCII.GetString(rest.Slice(1));
		return true;
	}
}
