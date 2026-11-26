using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Dns.Net.Abstractions;

[StackTraceHidden]
internal static class ThrowHelper
{
	[DoesNotReturn]
	public static void ThrowMessageTooLong()
	{
		throw new InvalidOperationException($"The message would be longer than {DnsMessage.MaxEncodedLength} bytes.");
	}
}
