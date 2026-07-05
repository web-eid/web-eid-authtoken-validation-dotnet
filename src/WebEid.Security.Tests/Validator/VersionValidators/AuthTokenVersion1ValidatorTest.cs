// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Tests.Validator.VersionValidators
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using AuthToken;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Moq;
    using NUnit.Framework;
    using WebEid.Security.Validator;
    using WebEid.Security.Validator.CertValidators;
    using WebEid.Security.Validator.Ocsp;
    using WebEid.Security.Validator.Ocsp.Service;
    using WebEid.Security.Validator.VersionValidators;

    public class AuthTokenVersion1ValidatorTest
    {
        private SubjectCertificateValidatorBatch subjectValidators;
        private AuthTokenSignatureValidator signatureValidator;
        private AuthTokenValidationConfiguration configuration;
        private IOcspClient ocspClient;
        private OcspServiceProvider ocspServiceProvider;
        private AuthTokenVersion1Validator validator;

        [SetUp]
        public void SetUp()
        {
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

            validator = new AuthTokenVersion1Validator(
                subjectValidators,
                signatureValidator,
                configuration,
                ocspClient,
                ocspServiceProvider,
                Mock.Of<ILogger>()
            );
        }

        [TestCase("web-eid:1")]
        [TestCase("web-eid:1.0")]
        [TestCase("web-eid:1.1")]
        [TestCase("web-eid:1.2")]
        [TestCase("web-eid:1.10")]
        [TestCase("web-eid:1.999")]
        public void WhenFormatIsValidMajorV1FormatThenSupportsReturnsTrue(string format) =>
            Assert.That(validator.Supports(format), Is.True);

        [TestCase(null)]
        [TestCase("")]
        [TestCase("web-eid")]
        [TestCase("web-eid:1.")]
        [TestCase("web-eid:1.0TEST")]
        [TestCase("web-eid:1.00")]
        [TestCase("web-eid:1.000")]
        [TestCase("web-eid:01")]
        [TestCase("web-eid:1.1.0")]
        [TestCase("web-eid:0.9")]
        [TestCase("web-eid:2")]
        [TestCase("webauthn:1")]
        public void WhenFormatIsNullEmptyMalformedOrNotV1ThenSupportsReturnsFalse(string format) =>
            Assert.That(validator.Supports(format), Is.False);

        [Test]
        public void WhenUnverifiedCertificateMissingThenValidationFails()
        {
            var token = new WebEidAuthToken
            {
                Format = "web-eid:1",
                UnverifiedSigningCertificates = null,
                UnverifiedCertificate = null
            };

            var ex = Assert.ThrowsAsync<AuthTokenParseException>(() =>
                validator.Validate(token, "nonce"));

            Assert.That(ex.Message, Does.Contain("'unverifiedCertificate' field is missing"));
        }

        [Test]
        public void WhenUnverifiedSigningCertificatesPresentForV1ThenValidationFails()
        {
            var token = new WebEidAuthToken
            {
                Format = "web-eid:1",
                UnverifiedSigningCertificates =
                [
                    new()
                ]
            };

            var ex = Assert.ThrowsAsync<AuthTokenParseException>(() =>
                validator.Validate(token, "nonce"));

            Assert.That(
                ex.Message,
                Does.Contain("'unverifiedSigningCertificates' field is not allowed for format 'web-eid:1'"));
        }

        [Test]
        public void WhenUnverifiedIntermediateCertificatesPresentForV1ThenValidationFails()
        {
            var token = new WebEidAuthToken
            {
                Format = "web-eid:1",
                UnverifiedSigningCertificates = null,
                UnverifiedIntermediateCertificates = ["intermediate"]
            };

            var ex = Assert.ThrowsAsync<AuthTokenParseException>(() =>
                validator.Validate(token, "nonce"));

            Assert.That(
                ex.Message,
                Does.Contain("'unverifiedIntermediateCertificates' field is not allowed for format 'web-eid:1'"));
        }
    }
}
