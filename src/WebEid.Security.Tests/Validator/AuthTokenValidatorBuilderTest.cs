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
namespace WebEid.Security.Tests.Validator
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Moq;
    using NUnit.Framework;
    using Microsoft.Extensions.Logging;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Validator;
    using WebEid.Security.Validator.Ocsp;
    using WebEid.Security.Validator.Ocsp.Service;

    public class AuthTokenValidatorBuilderTest
    {
        private AuthTokenValidatorBuilder builder;
        private Mock<ILogger> loggerMock;
        private AuthTokenValidatorBuilder builderWithLogger;

        [SetUp]
        public void SetUp()
        {
            builder = new AuthTokenValidatorBuilder();

            loggerMock = new Mock<ILogger>();
            loggerMock.Setup(x => x.IsEnabled(LogLevel.Debug)).Returns(true);

            builderWithLogger = new AuthTokenValidatorBuilder(loggerMock.Object);
        }

        [Test]
        public void WhenOriginMissingThenBuildingFails() =>
            Assert.Throws<ArgumentNullException>(() => builder.Build())
                .WithMessage("Value cannot be null. (Parameter 'siteOrigin')");

        [Test]
        public void WhenRootCertificateAuthorityMissingThenBuildingFails()
        {
            var authTokenValidatorBuilder = builder.WithSiteOrigin(new Uri("https://ria.ee"));
            Assert.Throws<ArgumentException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("At least one trusted certificate authority must be provided");
        }

        [Test]
        public void WhenOriginNotUrlThenBuildingFails()
        {
            var authTokenValidatorBuilder = builder.WithSiteOrigin(new Uri("c:/test"));
            Assert.Throws<UriFormatException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("Invalid URI: The hostname could not be parsed.");
        }

        [Test]
        public void WhenOriginExcessiveElementsThenBuildingFails()
        {
            var authTokenValidatorBuilder = builder.WithSiteOrigin(new Uri("https://ria.ee/excessive-element"));
            Assert.Throws<ArgumentException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("Origin URI must only contain the HTTPS scheme, host and optional port component");
        }

        [Test]
        public void WhenOriginProtocolHttpThenBuildingFails()
        {
            var authTokenValidatorBuilder = builder.WithSiteOrigin(new Uri("http://ria.ee"));
            Assert.Throws<ArgumentException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("Origin URI must only contain the HTTPS scheme, host and optional port component");
        }

        [Test]
        public void WhenOriginProtocolInvalidThenBuildingFails()
        {
            var authTokenValidatorBuilder = builder.WithSiteOrigin(new Uri("ria://ria.ee"));
            Assert.Throws<UriFormatException>(() => authTokenValidatorBuilder.Build())
                .WithMessage("Invalid URI: Invalid port specified."); // Bug in Uri.CreateThis()
        }

        [Test]
        public void WhenValidMandatoryConfigurationThenBuildingSucceeds()
        {
            var validator = builder
                .WithSiteOrigin(new Uri("https://ria.ee"))
                .WithTrustedCertificateAuthorities(CreateTestCertificate())
                .Build();

            Assert.That(validator, Is.Not.Null);
        }

        [Test]
        public void WhenWithSiteOriginCalledThenSameBuilderIsReturned()
        {
            var result = builder.WithSiteOrigin(new Uri("https://ria.ee"));

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenWithTrustedCertificateAuthoritiesCalledThenSameBuilderIsReturned()
        {
            var result = builder.WithTrustedCertificateAuthorities(CreateTestCertificate());

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenWithDisallowedCertificatePoliciesCalledThenSameBuilderIsReturned()
        {
            var result = builder.WithDisallowedCertificatePolicies("1.2.3.4.5");

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenWithoutUserCertificateRevocationCheckWithOcspCalledThenSameBuilderIsReturned()
        {
            var result = builder.WithoutUserCertificateRevocationCheckWithOcsp();

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenWithOcspRequestTimeoutCalledThenSameBuilderIsReturned()
        {
            var result = builder.WithOcspRequestTimeout(TimeSpan.FromSeconds(10));

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenWithAllowedOcspResponseTimeSkewCalledThenSameBuilderIsReturned()
        {
            var result = builder.WithAllowedOcspResponseTimeSkew(TimeSpan.FromMinutes(3));

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenWithMaxOcspResponseThisUpdateAgeCalledThenSameBuilderIsReturned()
        {
            var result = builder.WithMaxOcspResponseThisUpdateAge(TimeSpan.FromMinutes(1));

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenWithNonceDisabledOcspUrlsCalledThenSameBuilderIsReturned()
        {
            var result = builder.WithNonceDisabledOcspUrls(new Uri("https://ocsp.ria.ee"));

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenWithDesignatedOcspServiceConfigurationCalledThenSameBuilderIsReturned()
        {
            var serviceConfiguration = new DesignatedOcspServiceConfiguration(
                new Uri("https://ocsp.ria.ee"),
                CreateOcspResponderCertificate(),
                []);

            var result = builder.WithDesignatedOcspServiceConfiguration(serviceConfiguration);

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenWithOcspClientCalledThenSameBuilderIsReturned()
        {
            var ocspClient = new Mock<IOcspClient>().Object;

            var result = builder.WithOcspClient(ocspClient);

            Assert.That(result, Is.SameAs(builder));
        }

        [Test]
        public void WhenCustomOcspClientConfiguredThenBuildingSucceeds()
        {
            var ocspClient = new Mock<IOcspClient>().Object;

            var validator = builder
                .WithSiteOrigin(new Uri("https://ria.ee"))
                .WithTrustedCertificateAuthorities(CreateTestCertificate())
                .WithOcspClient(ocspClient)
                .Build();

            Assert.That(validator, Is.Not.Null);
        }

        [Test]
        public void WhenOcspRevocationCheckDisabledThenBuildingSucceedsWithoutCustomOcspClient()
        {
            var validator = builder
                .WithSiteOrigin(new Uri("https://ria.ee"))
                .WithTrustedCertificateAuthorities(CreateTestCertificate())
                .WithoutUserCertificateRevocationCheckWithOcsp()
                .Build();

            Assert.That(validator, Is.Not.Null);
        }

        [Test]
        public void WhenAllOptionalConfigurationMethodsUsedThenBuildingSucceeds()
        {
            var serviceConfiguration = new DesignatedOcspServiceConfiguration(
                new Uri("https://ocsp.ria.ee"),
                CreateOcspResponderCertificate(),
                []);

            var validator = builder
                .WithSiteOrigin(new Uri("https://ria.ee"))
                .WithTrustedCertificateAuthorities(CreateTestCertificate())
                .WithDisallowedCertificatePolicies("1.2.3.4.5", "1.3.6.1.4.1")
                .WithOcspRequestTimeout(TimeSpan.FromSeconds(7))
                .WithAllowedOcspResponseTimeSkew(TimeSpan.FromMinutes(2))
                .WithMaxOcspResponseThisUpdateAge(TimeSpan.FromMinutes(1))
                .WithNonceDisabledOcspUrls(
                    new Uri("https://ocsp.ria.ee"),
                    new Uri("https://aia.sk.ee/ocsp"))
                .WithDesignatedOcspServiceConfiguration(serviceConfiguration)
                .WithoutUserCertificateRevocationCheckWithOcsp()
                .Build();

            Assert.That(validator, Is.Not.Null);
        }

        [Test]
        public void WhenWithSiteOriginCalledWithDebugLoggerThenDebugLogIsWritten()
        {
            builderWithLogger.WithSiteOrigin(new Uri("https://ria.ee"));

            VerifyDebugLogWasWritten(Times.Once());
        }

        [Test]
        public void WhenWithTrustedCertificateAuthoritiesCalledWithDebugLoggerThenDebugLogIsWritten()
        {
            builderWithLogger.WithTrustedCertificateAuthorities(CreateTestCertificate());

            VerifyDebugLogWasWritten(Times.Once());
        }

        [Test]
        public void WhenWithDisallowedCertificatePoliciesCalledWithDebugLoggerThenDebugLogIsWritten()
        {
            builderWithLogger.WithDisallowedCertificatePolicies("1.2.3.4.5");

            VerifyDebugLogWasWritten(Times.Once());
        }

        [Test]
        public void WhenWithoutUserCertificateRevocationCheckWithOcspCalledWithLoggerThenDebugLogIsWritten()
        {
            builderWithLogger.WithoutUserCertificateRevocationCheckWithOcsp();

            VerifyDebugLogWasWritten(Times.Once());
        }

        [Test]
        public void WhenWithOcspRequestTimeoutCalledWithDebugLoggerThenDebugLogIsWritten()
        {
            builderWithLogger.WithOcspRequestTimeout(TimeSpan.FromSeconds(10));

            VerifyDebugLogWasWritten(Times.Once());
        }

        [Test]
        public void WhenWithAllowedOcspResponseTimeSkewCalledWithDebugLoggerThenDebugLogIsWritten()
        {
            builderWithLogger.WithAllowedOcspResponseTimeSkew(TimeSpan.FromMinutes(3));

            VerifyDebugLogWasWritten(Times.Once());
        }

        [Test]
        public void WhenWithMaxOcspResponseThisUpdateAgeCalledWithDebugLoggerThenDebugLogIsWritten()
        {
            builderWithLogger.WithMaxOcspResponseThisUpdateAge(TimeSpan.FromMinutes(1));

            VerifyDebugLogWasWritten(Times.Once());
        }

        [Test]
        public void WhenWithNonceDisabledOcspUrlsCalledWithDebugLoggerThenDebugLogIsWritten()
        {
            builderWithLogger.WithNonceDisabledOcspUrls(new Uri("https://ocsp.ria.ee"));

            VerifyDebugLogWasWritten(Times.Once());
        }

        [Test]
        public void WhenWithDesignatedOcspServiceConfigurationCalledWithLoggerThenDebugLogIsWritten()
        {
            var serviceConfiguration = new DesignatedOcspServiceConfiguration(
                new Uri("https://ocsp.ria.ee"),
                CreateOcspResponderCertificate(),
                []);

            builderWithLogger.WithDesignatedOcspServiceConfiguration(serviceConfiguration);

            VerifyDebugLogWasWritten(Times.Once());
        }

        [Test]
        public void WhenWithOcspClientCalledWithLoggerThenDebugLogIsWritten()
        {
            var ocspClient = new Mock<IOcspClient>().Object;

            builderWithLogger.WithOcspClient(ocspClient);

            VerifyDebugLogWasWritten(Times.Once());
        }

        private static X509Certificate2 CreateTestCertificate()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=Test Certificate",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            return request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(1));
        }

        private static Org.BouncyCastle.X509.X509Certificate CreateOcspResponderCertificate()
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                "CN=Test OCSP Responder",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            var enhancedKeyUsages = new OidCollection
            {
                new Oid("1.3.6.1.5.5.7.3.9"),
            };
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(enhancedKeyUsages, true));

            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

            using var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(1));

            return Org.BouncyCastle.Security.DotNetUtilities.FromX509Certificate(certificate);
        }

#pragma warning disable CA1873
        private void VerifyDebugLogWasWritten(Times times) => loggerMock.Verify(
                x => x.Log(
                    It.Is<LogLevel>(l => l == LogLevel.Debug),
                    It.IsAny<EventId>(),
                    It.IsAny<It.IsAnyType>(),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception, string>>()),
                times);
#pragma warning restore CA1873
    }
}
