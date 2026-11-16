// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
