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
            var mockCertificate = new Moq.Mock<X509Certificate>();
            mockCertificate.Setup(x => x.GetExtensionValue(It.IsAny<DerObjectIdentifier>())).Returns(() => null);
            Assert.That(OcspUrls.GetOcspUri(mockCertificate.Object), Is.Null);
        }

        [Test]
        public void WhenExtensionValueIsInvalidThenReturnsNull()
        {
            var mockCertificate = new Moq.Mock<X509Certificate>();
            mockCertificate.Setup(x => x.GetExtensionValue(It.IsAny<DerObjectIdentifier>()))
                .Returns(() => new DerOctetString(ToByteArray(new sbyte[] { 1, 2, 3 })));
            Assert.That(OcspUrls.GetOcspUri(mockCertificate.Object), Is.Null);
        }

        private static byte ToByte(sbyte sb) => (byte)(sb & 0xFF);

        private static byte[] ToByteArray(sbyte[] sBytes) => sBytes.Select(ToByte).ToArray();
    }
}
