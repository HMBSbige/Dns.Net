namespace Dns.Net.Tests;

internal static class Equality
{
	// Equal values must also have equal hash codes.
	public static async Task AssertEqual<T>(T left, T right) where T : notnull
	{
		await Assert.That(left).IsEqualTo(right);
		await Assert.That(left.GetHashCode()).IsEqualTo(right.GetHashCode());
	}
}
