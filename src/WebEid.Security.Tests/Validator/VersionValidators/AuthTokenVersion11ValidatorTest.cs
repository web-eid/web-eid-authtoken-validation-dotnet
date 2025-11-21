// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
    }
}
