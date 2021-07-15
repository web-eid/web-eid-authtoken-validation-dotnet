namespace WebEid.Security.Tests.Validator.Ocsp
{
    using System;
    using NUnit.Framework;
    using Org.BouncyCastle.Asn1.Ocsp;
    using Org.BouncyCastle.Ocsp;
    using Org.BouncyCastle.Security;
    using Security.Validator.Ocsp;
    using TestUtils;

    [TestFixture]
    public class OcspRequestBuiderTests
    {
        [Test]
        public void BuildWithoutCertificateIdThrowsException()
        {
            Assert.Throws<ArgumentNullException>(() => new OcspRequestBuilder().Build());
        }

        [Test]
        public void BuildWithOcspNonceAddsNonceToRequest()
        {
            var certificate = DotNetUtilities.FromX509Certificate(CertificateLoader.LoadCertificateFromResource("ESTEID2018.cer"));
            var certificateId = new CertificateID(CertificateID.HashSha1, certificate, certificate.SerialNumber);

            var request = new OcspRequestBuilder()
                .WithCertificateId(certificateId)
                .EnableOcspNonce(true).Build();

            Assert.IsNotNull(request.RequestExtensions.GetExtension(OcspObjectIdentifiers.PkixOcspNonce));
        }
    }
}
