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
namespace WebEid.Security.Tests.Util
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using NUnit.Framework;
    using Org.BouncyCastle.Security;
    using Security.Util;
    using TestUtils;

    [TestFixture]
    public class X509CertificateExtensionsTests
    {
        private X509Certificate certificate;

        [OneTimeSetUp]
        public void SetUp() =>
            this.certificate = Certificates.CertificateLoader.LoadCertificateFromResource("Karl-Kristjan-Joeorg.cer");

        [Test]
        public void GetSubjectIdCodeReturnsCorrectValue() =>
            Assert.AreEqual("PNOEE-38001085718", this.certificate.GetSubjectIdCode());

        [Test]
        public void GetSubjectCnReturnsCorrectValue() =>
            Assert.AreEqual("JÕEORG,JAAK-KRISTJAN,38001085718", this.certificate.GetSubjectCn());

        [Test]
        public void GetSubjectGivenNameReturnsCorrectValue() =>
            Assert.AreEqual("JAAK-KRISTJAN", this.certificate.GetSubjectGivenName());

        [Test]
        public void GetSubjectSurnameReturnsCorrectValue() =>
            Assert.AreEqual("JÕEORG", this.certificate.GetSubjectSurname());

        [Test]
        public void GetSubjectCountryCodeReturnsCorrectValue() =>
            Assert.AreEqual("EE", this.certificate.GetSubjectCountryCode());

        [Test]
        public void ValidateBcNotYetValidCertificateExpiryThrowsException() =>
            Assert.Throws<CertificateNotYetValidException>(() =>
                DotNetUtilities.FromX509Certificate(this.certificate)
                    .ValidateCertificateExpiry(new DateTime(2000, 1, 1), "Test"));

        [Test]
        public void ValidateBcExpiredCertificateExpiryThrowsException() =>
            Assert.Throws<CertificateExpiredException>(() =>
                DotNetUtilities.FromX509Certificate(this.certificate)
                    .ValidateCertificateExpiry(new DateTime(2030, 1, 1), "Test"));

        [Test]
        public void ValidateBcValidCertificateExpiryDoesNotThrowException() => Assert.DoesNotThrow(() =>
                                                                                 DotNetUtilities.FromX509Certificate(this.certificate)
                                                                                     .ValidateCertificateExpiry(new DateTime(2021, 08, 1), "Test"));

        [Test]
        public void ValidateNotYetValidCertificateExpiryThrowsException() => Assert.Throws<CertificateNotYetValidException>(() =>
                                                                               new X509Certificate2(this.certificate)
                                                                                   .ValidateCertificateExpiry(new DateTime(2000, 1, 1), "Test"));

        [Test]
        public void ValidateExpiredCertificateExpiryThrowsException() => Assert.Throws<CertificateExpiredException>(() =>
                                                                           new X509Certificate2(this.certificate)
                                                                               .ValidateCertificateExpiry(new DateTime(2030, 1, 1), "Test"));

        [Test]
        public void ValidateValidCertificateExpiryDoesNotThrowException() => Assert.DoesNotThrow(() =>
                                                                               new X509Certificate2(this.certificate)
                                                                                   .ValidateCertificateExpiry(new DateTime(2021, 08, 1), "Test"));
    }
}
