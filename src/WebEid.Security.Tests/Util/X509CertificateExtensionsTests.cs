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
            certificate = Certificates.CertificateLoader.LoadCertificateFromResource("Karl-Kristjan-Joeorg.cer");

        [Test]
        public void GetSubjectIdCodeReturnsCorrectValue() =>
            Assert.That("PNOEE-38001085718", Is.EqualTo(certificate.GetSubjectIdCode()));

        [Test]
        public void GetSubjectCnReturnsCorrectValue() =>
            Assert.That("JÕEORG,JAAK-KRISTJAN,38001085718", Is.EqualTo(certificate.GetSubjectCn()));

        [Test]
        public void GetSubjectGivenNameReturnsCorrectValue() =>
            Assert.That("JAAK-KRISTJAN", Is.EqualTo(certificate.GetSubjectGivenName()));

        [Test]
        public void GetSubjectSurnameReturnsCorrectValue() =>
            Assert.That("JÕEORG", Is.EqualTo(certificate.GetSubjectSurname()));

        [Test]
        public void GetSubjectCountryCodeReturnsCorrectValue() =>
            Assert.That("EE", Is.EqualTo(certificate.GetSubjectCountryCode()));

        [Test]
        public void ParseCertificatesWithNullListReturnsEmptyList() =>
            Assert.That(X509CertificateExtensions.ParseCertificates(null, "unverifiedIntermediateCertificates"),
                Is.Empty);

        [Test]
        public void ParseCertificatesWithEmptyListReturnsEmptyList() =>
            Assert.That(X509CertificateExtensions.ParseCertificates([], "unverifiedIntermediateCertificates"),
                Is.Empty);

        [Test]
        public void ParseCertificatesDecodesAllCertificates()
        {
            var certificateInBase64 = Convert.ToBase64String(certificate.GetRawCertData());

            var result = X509CertificateExtensions.ParseCertificates(
                [certificateInBase64, certificateInBase64], "unverifiedIntermediateCertificates");

            Assert.That(result, Has.Count.EqualTo(2));
            Assert.That(result[0].RawData, Is.EqualTo(certificate.GetRawCertData()));
            Assert.That(result[1].RawData, Is.EqualTo(certificate.GetRawCertData()));
        }

        [Test]
        public void ParseCertificatesWithInvalidEntryThrows() =>
            Assert.Throws<AuthTokenParseException>(() =>
                    X509CertificateExtensions.ParseCertificates(["not a certificate"], "unverifiedIntermediateCertificates"))
                .WithMessage("'unverifiedIntermediateCertificates' field must contain a valid certificate");

        [Test]
        public void ValidateBcNotYetValidCertificateExpiryThrowsException() =>
            Assert.Throws<CertificateNotYetValidException>(() =>
                DotNetUtilities.FromX509Certificate(certificate)
                    .ValidateCertificateExpiry(new DateTime(2000, 1, 1), "Test"));

        [Test]
        public void ValidateBcExpiredCertificateExpiryThrowsException() =>
            Assert.Throws<CertificateExpiredException>(() =>
                DotNetUtilities.FromX509Certificate(certificate)
                    .ValidateCertificateExpiry(new DateTime(2030, 1, 1), "Test"));

        [Test]
        public void ValidateBcValidCertificateExpiryDoesNotThrowException() => Assert.DoesNotThrow(() =>
                                                                                 DotNetUtilities.FromX509Certificate(certificate)
                                                                                     .ValidateCertificateExpiry(new DateTime(2021, 08, 1), "Test"));

        [Test]
        public void ValidateNotYetValidCertificateExpiryThrowsException() => Assert.Throws<CertificateNotYetValidException>(() =>
                                                                               new X509Certificate2(certificate)
                                                                                   .ValidateCertificateExpiry(new DateTime(2000, 1, 1), "Test"));

        [Test]
        public void ValidateExpiredCertificateExpiryThrowsException() => Assert.Throws<CertificateExpiredException>(() =>
                                                                           new X509Certificate2(certificate)
                                                                               .ValidateCertificateExpiry(new DateTime(2030, 1, 1), "Test"));

        [Test]
        public void ValidateValidCertificateExpiryDoesNotThrowException() => Assert.DoesNotThrow(() =>
                                                                               new X509Certificate2(certificate)
                                                                                   .ValidateCertificateExpiry(new DateTime(2021, 08, 1), "Test"));
    }
}
