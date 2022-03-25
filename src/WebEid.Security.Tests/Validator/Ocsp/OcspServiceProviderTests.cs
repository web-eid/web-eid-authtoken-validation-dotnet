namespace WebEid.Security.Tests.Validator.Ocsp
{
    using System;
    using Exceptions;
    using NUnit.Framework;
    using Org.BouncyCastle.Security;
    using TestUtils;

    [TestFixture]
    public class OcspServiceProviderTests
    {
        private static readonly DateTime CheckMoment = new(2021, 08, 1);

        [Test]
        public void WhenDesignatedOcspServiceConfigurationProvidedThenCreatesDesignatedOcspService()
        {
            var ocspServiceProvider = OcspServiceMaker.GetDesignatedOcspServiceProvider();
            var service = ocspServiceProvider.GetService(DotNetUtilities.FromX509Certificate(Certificates.GetJaakKristjanEsteid2018Cert()));
            Assert.That(service.AccessLocation, Is.EqualTo(new Uri("http://demo.sk.ee/ocsp")));
            Assert.That(service.DoesSupportNonce, Is.True);
            Assert.DoesNotThrow(() =>
                service.ValidateResponderCertificate(
                    DotNetUtilities.FromX509Certificate(Certificates.GetTestSkOcspResponder2020()),
                    CheckMoment));
            Assert.Throws<OcspCertificateException>(() =>
                    service.ValidateResponderCertificate(
                        DotNetUtilities.FromX509Certificate(Certificates.GetTestEsteid2018Ca()),
                        CheckMoment))
                .HasMessage(
                    "Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate");
        }

        [Test]
        public void WhenAiaOcspServiceConfigurationProvidedThenCreatesAiaOcspService()
        {
            var ocspServiceProvider = OcspServiceMaker.GetAiaOcspServiceProvider();
            var service2018 = ocspServiceProvider.GetService(DotNetUtilities.FromX509Certificate(Certificates.GetJaakKristjanEsteid2018Cert()));
            Assert.That(service2018.AccessLocation, Is.EqualTo(new Uri("http://aia.demo.sk.ee/esteid2018")));
            Assert.That(service2018.DoesSupportNonce, Is.True);
            Assert.DoesNotThrow(() =>
                // Use the CA certificate instead of responder certificate for convenience.
                service2018.ValidateResponderCertificate(
                    DotNetUtilities.FromX509Certificate(Certificates.GetTestEsteid2018Ca()),
                    CheckMoment));

            var service2015 = ocspServiceProvider.GetService(DotNetUtilities.FromX509Certificate(Certificates.GetMariliisEsteid2015Cert()));
            Assert.That(service2015.AccessLocation, Is.EqualTo(new Uri("http://aia.demo.sk.ee/esteid2015")));
            Assert.That(service2015.DoesSupportNonce, Is.False);
            Assert.DoesNotThrow(() =>
                // Use the CA certificate instead of responder certificate for convenience.
                service2015.ValidateResponderCertificate(
                    DotNetUtilities.FromX509Certificate(Certificates.GetTestEsteid2015Ca()),
                    CheckMoment));
        }

        [Test]
        public void WhenAiaOcspServiceConfigurationDoesNotHaveResponderCertTrustedCaThenThrows()
        {
            var ocspServiceProvider = OcspServiceMaker.GetAiaOcspServiceProvider();
            var service2018 = ocspServiceProvider.GetService(DotNetUtilities.FromX509Certificate(Certificates.GetJaakKristjanEsteid2018Cert()));
            var wrongResponderCert = DotNetUtilities.FromX509Certificate(Certificates.GetMariliisEsteid2015Cert());
            Assert.Throws<OcspCertificateException>(() =>
                service2018.ValidateResponderCertificate(wrongResponderCert, CheckMoment));
        }
    }
}
