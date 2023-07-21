/*
 * Copyright © 2020-2023 Estonian Information System Authority
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
    using System;
    using Exceptions;
    using NUnit.Framework;
    using Org.BouncyCastle.Security;
    using TestUtils;

    [TestFixture]
    public class OcspServiceProviderTests
    {
        private static readonly DateTime CheckMoment = new(2023, 04, 9);

        [Test]
        public void WhenDesignatedOcspServiceConfigurationProvidedThenCreatesDesignatedOcspService()
        {
            var ocspServiceProvider = OcspServiceMaker.GetDesignatedOcspServiceProvider();
            var service = ocspServiceProvider.GetService(DotNetUtilities.FromX509Certificate(Certificates.GetJaakKristjanEsteid2018Cert()));
            Assert.That(service.AccessLocation, Is.EqualTo(new Uri("http://demo.sk.ee/ocsp")));
            Assert.That(service.DoesSupportNonce, Is.True);
            Assert.DoesNotThrow(() =>
                service.ValidateResponderCertificate(
                    DotNetUtilities.FromX509Certificate(Certificates.GetTestSkOcspResponder2023()),
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
