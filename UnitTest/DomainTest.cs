using Dns.Net;
using Dns.Net.Domains;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace UnitTest
{
	[TestClass]
	public class DomainTest
	{
		[TestMethod]
		[DataRow(null, false)]
		[DataRow(@"", false)]
		[DataRow(@".", true)]
		[DataRow(@"..", false)]
		[DataRow(@"a.b..com.", false)]
		[DataRow(@"Donald\032E\.\032Eastlake\0323rd.example.", true)]
		[DataRow(@"a\000\\\255z.example.", true)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.", true)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)]
		[DataRow(@"\000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
		[DataRow(@"\000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
		[DataRow(@"\000\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
		[DataRow(@"\000\a\.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
		[DataRow(@"\000\a\.\ aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)]
		[DataRow(@"\000.com", true)]
		[DataRow(@"\255.com", true)]
		[DataRow(@"\256.com", false)]
		[DataRow(@"\300.com", false)]
		[DataRow(@"\12.com", false)]
		[DataRow(@"\1.com", false)]
		[DataRow(@"\!.com", true)]
		[DataRow(@"\x23.com", true)]
		[DataRow(@"\1x3.com", false)]
		[DataRow(@"\12x.com", false)]
		[DataRow(@"\.", true)]
		[DataRow(@"中文.域名", false)]
		[DataRow(@"xn--fiq228c.xn--eqrt2g", true)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", false)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x", true)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\1", false)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\12", false)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\123", true)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.", true)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false)]
		[DataRow(@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.a", false)]
		public void IsDomainTest(string? domain, bool expected)
		{
			Assert.AreEqual(expected, domain.IsDomain());
		}

		[TestMethod]
		public void DomainWriteToTest()
		{
			const string rootDomain = @".";
			const string microsoftDomain1 = @"www.microsoft.com";
			const string microsoftDomain2 = @"www.microsoft.com.";
			const string rfc4343Domain1 = @"Donald\032E\.\032Eastlake\0323rd.example.";
			const string rfc4343Domain2 = @"a\000\\\255z.example.";

			ReadOnlySpan<byte> microsoftDomainBuffer = new byte[]
			{
				3, (byte)'w', (byte)'w', (byte)'w',
				9, (byte)'m', (byte)'i', (byte)'c', (byte)'r', (byte)'o', (byte)'s', (byte)'o', (byte)'f', (byte)'t',
				3, (byte)'c', (byte)'o', (byte)'m',
				0
			};
			ReadOnlySpan<byte> rfc4343Domain1Buffer = new byte[]
			{
				22, (byte)'D', (byte)'o', (byte)'n', (byte)'a', (byte)'l', (byte)'d', 32, (byte)'E', (byte)'.', 32,
				(byte)'E', (byte)'a', (byte)'s', (byte)'t', (byte)'l', (byte)'a', (byte)'k', (byte)'e', 32,
				(byte)'3', (byte)'r', (byte)'d',
				7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
				0
			};
			ReadOnlySpan<byte> rfc4343Domain2Buffer = new byte[]
			{
				5, (byte)'a', 0, (byte)'\\', 255, (byte)'z',
				7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
				0
			};

			Span<byte> buffer = stackalloc byte[DnsConstants.MaxDomainSize];

			var length = rootDomain.DomainWriteTo(buffer);
			Assert.AreEqual(1, length);
			Assert.AreEqual(0, buffer[0]);

			length = microsoftDomain1.DomainWriteTo(buffer);
			Assert.AreEqual(19, length);
			Assert.IsTrue(buffer[..length].SequenceEqual(microsoftDomainBuffer));

			length = microsoftDomain2.DomainWriteTo(buffer);
			Assert.AreEqual(19, length);
			Assert.IsTrue(buffer[..length].SequenceEqual(microsoftDomainBuffer));

			length = rfc4343Domain1.DomainWriteTo(buffer);
			Assert.AreEqual(rfc4343Domain1Buffer.Length, length);
			Assert.IsTrue(buffer[..length].SequenceEqual(rfc4343Domain1Buffer));

			length = rfc4343Domain2.DomainWriteTo(buffer);
			Assert.AreEqual(rfc4343Domain2Buffer.Length, length);
			Assert.IsTrue(buffer[..length].SequenceEqual(rfc4343Domain2Buffer));
		}
	}
}
