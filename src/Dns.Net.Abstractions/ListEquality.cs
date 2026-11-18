namespace Dns.Net.Abstractions;

// Content equality for the lists that records hold, which their synthesized equality would compare by reference.
internal static class ListEquality
{
	public static bool SequenceEqual<T>(IReadOnlyList<T> left, IReadOnlyList<T> right)
	{
		if (ReferenceEquals(left, right))
		{
			return true;
		}

		if (left.Count != right.Count)
		{
			return false;
		}

		EqualityComparer<T> comparer = EqualityComparer<T>.Default;

		for (int i = 0; i < left.Count; ++i)
		{
			if (!comparer.Equals(left[i], right[i]))
			{
				return false;
			}
		}

		return true;
	}

	public static void AddTo<T>(ref HashCode hash, IReadOnlyList<T> list)
	{
		hash.Add(list.Count);

		for (int i = 0; i < list.Count; ++i)
		{
			hash.Add(list[i]);
		}
	}
}
