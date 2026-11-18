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

	[DoesNotReturn]
	public static void ThrowNotEncodable(string message)
	{
		throw new InvalidOperationException(message);
	}

	[DoesNotReturn]
	public static T ThrowInvalidData<T>(string? message)
	{
		throw new InvalidDataException(message);
	}

	[DoesNotReturn]
	public static T ThrowFormat<T>(string? message)
	{
		throw new FormatException(message);
	}

	[DoesNotReturn]
	public static void ThrowTruncatedStream()
	{
		throw new EndOfStreamException("The stream ended inside a message.");
	}

	[DoesNotReturn]
	public static void ThrowInvalidName(string? message, string paramName)
	{
		throw new ArgumentException(message, paramName);
	}
}
