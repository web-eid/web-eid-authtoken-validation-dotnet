/*
 * Copyright © 2025-2025 Estonian Information System Authority
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
namespace WebEid.Security.Tests.Validator.VersionValidators
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Moq;
    using NUnit.Framework;
    using Security.Validator.CertValidators;
    using Security.Validator.Ocsp.Service;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Validator;
    using WebEid.Security.Validator.Ocsp;
    using WebEid.Security.Validator.VersionValidators;

    public class AuthTokenVersion11ValidatorTest : AbstractTestWithValidator
    {
        private SubjectCertificateValidatorBatch subjectValidators;
        private AuthTokenSignatureValidator signatureValidator;
        private AuthTokenValidationConfiguration configuration;
        private IOcspClient ocspClient;
        private OcspServiceProvider ocspServiceProvider;
        private AuthTokenVersion11Validator v11Validator;

        [SetUp]
        public new void SetUp()
        {
            base.SetUp();

            subjectValidators = SubjectCertificateValidatorBatch.CreateFrom();

            configuration = new AuthTokenValidationConfiguration
            {
                SiteOrigin = new Uri("https://example.com")
            };
#pragma warning disable SYSLIB0026
            configuration.TrustedCaCertificates.Add(new X509Certificate2());
#pragma warning disable SYSLIB0026

            signatureValidator = new Mock<AuthTokenSignatureValidator>(
                new Uri("https://ria.ee")
            ).Object;

            ocspClient = new Mock<IOcspClient>().Object;

            var aiaConfig = new AiaOcspServiceConfiguration(
                [],
                []
            );

            ocspServiceProvider = new OcspServiceProvider(
                designatedOcspServiceConfiguration: null,
                aiaOcspServiceConfiguration: aiaConfig
            );

            v11Validator = new AuthTokenVersion11Validator(
                            subjectValidators,
                            signatureValidator,
                            configuration,
                            ocspClient,
                            ocspServiceProvider,
                            Mock.Of<ILogger>()
                        );
        }

        [TestCase("web-eid:1.1")]
        [TestCase("web-eid:1.2")]
        [TestCase("web-eid:1.10")]
        [TestCase("web-eid:1.999")]
        public void WhenFormatIsV11OrHigherMinorVersionThenSupportsReturnsTrue(string format) =>
            Assert.That(v11Validator.Supports(format), Is.True);

        [TestCase(null)]
        [TestCase("")]
        [TestCase("web-eid:1")]
        [TestCase("web-eid:1.0")]
        [TestCase("web-eid:1.")]
        [TestCase("web-eid:1.0TEST")]
        [TestCase("web-eid:1.00")]
        [TestCase("web-eid:1.1.0")]
        [TestCase("web-eid:2")]
        [TestCase("web-eid:0.9")]
        [TestCase("webauthn:1.1")]
        public void WhenFormatIsNullEmptyMinorVersion0NonCanonicalOrMalformedThenSupportsReturnsFalse(string format) =>
            Assert.That(v11Validator.Supports(format), Is.False);

        [Test]
        public void WhenUnverifiedSigningCertificatesMissingThenValidationFails()
        {
            var token = Validator.Parse(ValidV11AuthTokenStr);
            token.UnverifiedSigningCertificates = null;

            var ex = Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce));
            Assert.That(ex!.Message, Is.EqualTo(
                "'unverifiedSigningCertificates' field is missing, null or empty for format 'web-eid:1.1'"));
        }

        [Test]
        public void WhenSupportedSignatureAlgorithmsMissingThenValidationFails()
        {
            var token = Validator.Parse(ValidV11AuthTokenStr);
            token.UnverifiedSigningCertificates[0].SupportedSignatureAlgorithms = null;

            var ex = Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce));
            Assert.That(ex!.Message, Is.EqualTo("'supportedSignatureAlgorithms' field is missing"));
        }

        [Test]
        public void WhenSigningCertificateChainValidationSucceedsThenValidationSucceeds()
        {
            var token = Validator.Parse(ValidV11AuthTokenStr);

            Assert.DoesNotThrowAsync(() =>
                Validator.Validate(token, ValidChallengeNonce));
        }

        [Test]
        public void WhenUnverifiedSigningCertificatesMissingButIntermediateCertificatesPresentThenValidationSucceeds()
        {
            var token = Validator.Parse(ValidV11AuthTokenStr);
            token.UnverifiedSigningCertificates = null;
            token.UnverifiedIntermediateCertificates = [GetTestEsteid2018CaInBase64()];

            Assert.DoesNotThrowAsync(() =>
                Validator.Validate(token, ValidChallengeNonce));
        }

        [Test]
        public void WhenUnverifiedSigningCertificatesEmptyThenValidationFails()
        {
            var token = Validator.Parse(ValidV11AuthTokenStr);
            token.UnverifiedSigningCertificates = [];
            token.UnverifiedIntermediateCertificates = [GetTestEsteid2018CaInBase64()];

            var ex = Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce));
            Assert.That(ex!.Message, Is.EqualTo(
                "'unverifiedSigningCertificates' field is missing, null or empty for format 'web-eid:1.1'"));
        }

        [Test]
        public void WhenSigningCertificateIntermediateCertificatesEmptyThenValidationFails()
        {
            var token = Validator.Parse(ValidV11AuthTokenStr);
            token.UnverifiedSigningCertificates[0].IntermediateCertificates = [];

            var ex = Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce));
            Assert.That(ex!.Message, Is.EqualTo(
                "'intermediateCertificates' must not be empty for format 'web-eid:1.1'"));
        }

        [Test]
        public void WhenSigningCertificateIntermediateCertificatesContainsEmptyEntryThenValidationFails()
        {
            var token = Validator.Parse(ValidV11AuthTokenStr);
            token.UnverifiedSigningCertificates[0].IntermediateCertificates = [""];

            var ex = Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce));
            Assert.That(ex!.Message, Is.EqualTo(
                "'intermediateCertificates' must not contain null or empty entries for format 'web-eid:1.1'"));
        }

        private static string GetTestEsteid2018CaInBase64() =>
            Convert.ToBase64String(Certificates.GetTestEsteid2018Ca().GetRawCertData());
    }
}
