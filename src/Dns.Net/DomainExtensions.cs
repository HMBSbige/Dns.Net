using System.Text;

namespace Dns.Net;

public static class DomainExtensions
{
	private const char Dot = '.';
	private const char BackSlash = '\\';

	extension(ReadOnlySpan<char> str)
	{
		private bool IsAscii()
		{
			foreach (Rune r in str.EnumerateRunes())
			{
				if (r.Value > 0x7F)
				{
					return false;
				}
			}

			return true;
		}

		public bool IsDomain()
		{
			Span<byte> buffer = stackalloc byte[DnsConstants.MaxDomainSize];
			int length = DomainWriteTo(str, buffer);
			return length > 0;
		}

		/// <summary>
		/// https://datatracker.ietf.org/doc/html/rfc4343
		/// </summary>
		public int DomainWriteTo(in Span<byte> target)
		{
			if (str.IsEmpty || !str.IsAscii())
			{
				return default;
			}

			Span<byte> buffer = target;
			int length = 0;

			while (!str.IsEmpty)
			{
				int indexOfDot = str.IndexOfDot();

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
					label = str.Slice(0, indexOfDot);
					str = str.Slice(indexOfDot + 1);
				}

				int labelLength = label.LabelWriteTo(buffer);

				if (labelLength > 0)
				{
					length += labelLength;
					buffer = buffer.Slice(labelLength);
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

		private int LabelWriteTo(Span<byte> target)
		{
			if (target.IsEmpty)
			{
				return default;
			}

			// label 一定全是 Ascii，且不含 “.”

			int i = 0;
			int j = 0;

			while (i < str.Length)
			{
				if (j + 1 >= target.Length || j >= DnsConstants.MaxLabelSize)
				{
					return default;
				}

				char c0 = str[i++];

				if (c0 is not BackSlash)
				{
					target[++j] = (byte)c0;
					continue;
				}

				if (i >= str.Length)
				{
					return default;
				}

				char c1 = str[i++];

				if (!char.IsAsciiDigit(c1))
				{
					target[++j] = (byte)c1;
					continue;
				}

				if (c1 is not ('0' or '1' or '2'))
				{
					return default;
				}

				if (i >= str.Length)
				{
					return default;
				}

				char c2 = str[i++];

				if (!char.IsAsciiDigit(c2))
				{
					return default;
				}

				if (i >= str.Length)
				{
					return default;
				}

				char c3 = str[i++];

				if (!char.IsAsciiDigit(c3))
				{
					return default;
				}

				int n = 100 * (c1 - '0') + 10 * (c2 - '0') + (c3 - '0');

				if (n is > byte.MaxValue or < byte.MinValue)
				{
					return default;
				}

				target[++j] = (byte)n;
			}

			target[0] = (byte)j;
			return j + 1;
		}

		internal int IndexOfDot()
		{
			int baseIndex = 0;

			while (!str.IsEmpty)
			{
				int i = str.IndexOf(Dot);

				if (i < 0)
				{
					return i;
				}

				if (i == 0 || str[i - 1] != BackSlash)
				{
					return baseIndex + i;
				}

				baseIndex += i + 1;
				str = str.Slice(i + 1);
			}

			return -1;
		}
	}
}
