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
namespace WebEid.Security.Tests.Validator.VersionValidators
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using AuthToken;
    using NUnit.Framework;
    using Exceptions;
    using WebEid.Security.Validator;
    using WebEid.Security.Validator.VersionValidators;
    using WebEid.Security.Validator.CertValidators;
    using WebEid.Security.Validator.Ocsp;
    using WebEid.Security.Validator.Ocsp.Service;
    using Microsoft.Extensions.Logging;
    using Moq;

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
            configuration.TrustedCaCertificates.Add(new X509Certificate2());

            signatureValidator = new Mock<AuthTokenSignatureValidator>(
                new Uri("https://ria.ee")
            ).Object;

            ocspClient = new Mock<IOcspClient>().Object;

            var aiaConfig = new AiaOcspServiceConfiguration(
                new List<Uri>(),
                new List<X509Certificate2>()
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
        [TestCase("web-eid:1.10")]
        public void WhenFormatIsAnyMajorV1VariantThenSupportsReturnsTrue(string format)
        {
            Assert.That(validator.Supports(format), Is.True);
        }

        [TestCase(null)]
        [TestCase("")]
        [TestCase("web-eid")]
        [TestCase("web-eid:0.9")]
        [TestCase("web-eid:2")]
        [TestCase("webauthn:1")]
        public void WhenFormatIsNullEmptyOrNotV1ThenSupportsReturnsFalse(string format)
        {
            Assert.That(validator.Supports(format), Is.False);
        }

        [Test]
        public void WhenUnverifiedCertificateMissingThenValidationFails()
        {
            var token = new WebEidAuthToken
            {
                Format = "web-eid:1",
                UnverifiedCertificate = null
            };

            Assert.ThrowsAsync<AuthTokenParseException>(() =>
                validator.Validate(token, "nonce"));
        }
    }
}
