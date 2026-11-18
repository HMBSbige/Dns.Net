namespace Dns.Net.Abstractions;

// Copies the lists that messages keep, so that a caller who changes a list afterwards changes nothing that a message holds.
internal static class ListCopy
{
	// Returns a copy of list as a new array, failing on a null element; paramName names the property that the list is set to.
	public static T[] ToArray<T>(IReadOnlyList<T> list, string paramName)
	{
		ArgumentNullException.ThrowIfNull(list, paramName);

		if (list.Count is 0)
		{
			return [];
		}

		T[] copy = new T[list.Count];

		for (int i = 0; i < copy.Length; ++i)
		{
			copy[i] = list[i] ?? throw new ArgumentException("The list has a null element.", paramName);
		}

		return copy;
	}
}
