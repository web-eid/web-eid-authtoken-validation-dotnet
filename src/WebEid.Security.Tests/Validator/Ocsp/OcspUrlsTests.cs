/*
 * Copyright © 2020-2024 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
namespace WebEid.Security.Tests.Validator.Ocsp
{
    using System.Linq;
    using Moq;
    using NUnit.Framework;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.X509;
    using Security.Validator.Ocsp;

    [TestFixture]
    public class OcspUrlsTests
    {
        [Test]
        public void WhenExtensionValueIsNullThenReturnsNull()
        {
            var mockCertificate = new Mock<X509Certificate>();
            _ = mockCertificate.Setup(x => x.GetExtensionValue(It.IsAny<DerObjectIdentifier>())).Returns(() => null);
            Assert.That(OcspUrls.GetOcspUri(mockCertificate.Object), Is.Null);
        }

        [Test]
        public void WhenExtensionValueIsInvalidThenReturnsNull()
        {
            var mockCertificate = new Mock<X509Certificate>();
            _ = mockCertificate.Setup(x => x.GetExtensionValue(It.IsAny<DerObjectIdentifier>()))
                .Returns(() => new DerOctetString(ToByteArray(new sbyte[] { 1, 2, 3 })));
            Assert.That(OcspUrls.GetOcspUri(mockCertificate.Object), Is.Null);
        }

        private static byte ToByte(sbyte sb) => (byte)(sb & 0xFF);

        private static byte[] ToByteArray(sbyte[] sBytes) => sBytes.Select(ToByte).ToArray();
    }
}
