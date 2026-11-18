using System.Text;

namespace Dns.Net.Abstractions;

/// <summary>
/// Represents the data of a resource record, its RDATA.
/// </summary>
/// <remarks>
/// Only this library derives from the type, with a class for each type whose data it reads; <see cref="DnsUnknownData" /> holds any other data in wire format.
/// More classes may be added: code that switches on the class needs a default case.
/// </remarks>
public abstract record DnsRecordData
{
	private protected DnsRecordData()
	{
	}

	/// <summary>
	/// Gets the type of the record that the data belongs to.
	/// </summary>
	public abstract DnsRecordType Type { get; }

	/// <summary>
	/// Returns the data in the presentation format of master files, as it follows the type in a record.
	/// </summary>
	/// <returns>The data in presentation format, with names absolute and ending in a dot.</returns>
	public sealed override string ToString()
	{
		StringBuilder builder = new();
		AppendPresentation(builder);
		return builder.ToString();
	}

	internal abstract void AppendPresentation(StringBuilder builder);

	// Writes the RDATA, without its length.
	internal abstract void Write(ref DnsWireWriter writer);
}
