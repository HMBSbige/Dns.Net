using System;

namespace Dns.Net.Extensions
{
	public static class CharExtensions
	{
		public static bool IsAscii(this char ch)
		{
			return (uint)ch <= '\x007f';
		}

		public static bool IsAsciiDigit(this char ch)
		{
			return ch is >= '0' and <= '9';
		}

		public static bool IsAsciiLetter(this char ch)
		{
			return ch is >= 'a' and <= 'z' or >= 'A' and <= 'Z';
		}

		public static bool IsPrintable(this char ch)
		{
			return !char.IsControl(ch) && !char.IsWhiteSpace(ch);
		}

		public static bool IsAscii(this ReadOnlySpan<char> str)
		{
			foreach (var ch in str)
			{
				if (!ch.IsAscii())
				{
					return false;
				}
			}

			return true;
		}
	}
}
