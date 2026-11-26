namespace Dns.Net.Abstractions;

// TTLs and SOA intervals go on the wire as 32-bit seconds; encoding drops any fraction.
internal static class WireSeconds
{
	private static readonly TimeSpan Max = TimeSpan.FromSeconds(uint.MaxValue);

	public static TimeSpan Check(TimeSpan value, string paramName)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(value, TimeSpan.Zero, paramName);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(value, Max, paramName);
		return value;
	}

	public static uint Of(TimeSpan value)
	{
		return (uint)(value.Ticks / TimeSpan.TicksPerSecond);
	}
}
