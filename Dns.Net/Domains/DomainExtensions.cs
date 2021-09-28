using Dns.Net.Extensions;
using System;

namespace Dns.Net.Domains
{
	public static class DomainExtensions
	{
		internal const char Dot = '.';
		internal const char BackSlash = '\\';

		public static bool IsDomain(this string? str)
		{
			return IsDomain((ReadOnlySpan<char>)str);
		}

		public static int DomainWriteTo(this string? str, Span<byte> target)
		{
			return DomainWriteTo((ReadOnlySpan<char>)str, target);
		}

		public static bool IsDomain(this ReadOnlySpan<char> str)
		{
			Span<byte> buffer = stackalloc byte[DnsConstants.MaxDomainSize];
			var length = DomainWriteTo(str, buffer);
			return length > 0;
		}

		/// <summary>
		/// https://datatracker.ietf.org/doc/html/rfc4343
		/// </summary>
		public static int DomainWriteTo(this ReadOnlySpan<char> str, in Span<byte> target)
		{
			if (str.IsEmpty || !str.IsAscii())
			{
				return default;
			}

			var buffer = target;
			var length = 0;
			while (!str.IsEmpty)
			{
				var indexOfDot = str.IndexOfDot();
				if (indexOfDot is 0 && str.Length > 1)
				{
					return default;
				}

				ReadOnlySpan<char> label;
				if (indexOfDot < 0)
				{
					label = str;
					str = ReadOnlySpan<char>.Empty;
				}
				else
				{
					label = str[..indexOfDot];
					str = str[(indexOfDot + 1)..];
				}

				var labelLength = label.LabelWriteTo(buffer);
				if (labelLength > 0)
				{
					length += labelLength;
					buffer = buffer[labelLength..];
				}
				else
				{
					return default;
				}
			}

			if (target[length - 1] is not byte.MinValue)
			{
				if (length >= target.Length)
				{
					return default;
				}

				target[length++] = byte.MinValue;
			}

			return length;
		}

		private static int LabelWriteTo(this ReadOnlySpan<char> label, Span<byte> target)
		{
			if (target.IsEmpty)
			{
				return default;
			}

			// label 一定全是 Ascii，且不含 “.”

			var i = 0;
			var j = 0;

			while (i < label.Length)
			{
				if (j + 1 >= target.Length || j >= DnsConstants.MaxLabelSize)
				{
					return default;
				}

				var c0 = label[i++];
				if (c0 is not BackSlash)
				{
					target[++j] = (byte)c0;
					continue;
				}

				if (i >= label.Length)
				{
					return default;
				}
				var c1 = label[i++];
				if (!c1.IsAsciiDigit())
				{
					target[++j] = (byte)c1;
					continue;
				}

				if (c1 is not ('0' or '1' or '2'))
				{
					return default;
				}

				if (i >= label.Length)
				{
					return default;
				}
				var c2 = label[i++];
				if (!c2.IsAsciiDigit())
				{
					return default;
				}

				if (i >= label.Length)
				{
					return default;
				}
				var c3 = label[i++];
				if (!c3.IsAsciiDigit())
				{
					return default;
				}

				var n = 100 * (c1 - '0') + 10 * (c2 - '0') + (c3 - '0');
				if (n is > byte.MaxValue or < byte.MinValue)
				{
					return default;
				}
				target[++j] = (byte)n;
			}

			target[0] = (byte)j;
			return j + 1;
		}

		internal static int IndexOfDot(this ReadOnlySpan<char> origin)
		{
			var baseIndex = 0;

			while (!origin.IsEmpty)
			{
				var i = origin.IndexOf(Dot);
				if (i < 0)
				{
					return i;
				}

				if (i == 0 || origin[i - 1] != BackSlash)
				{
					return baseIndex + i;
				}

				baseIndex += i + 1;
				origin = origin[(i + 1)..];
			}

			return -1;
		}
	}
}
