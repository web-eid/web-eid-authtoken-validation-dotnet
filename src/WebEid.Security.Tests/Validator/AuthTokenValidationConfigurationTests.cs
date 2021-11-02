namespace WebEid.Security.Tests.Validator
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Cache;
    using NUnit.Framework;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Security;
    using Security.Validator;
    using Security.Validator.Ocsp;
    using Security.Validator.Ocsp.Service;
    using TestUtils;
    using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

    [TestFixture]
    public class AuthTokenValidationConfigurationTests
    {
        [Test]
        public void AuthTokenValidationConfigurationWithoutSiteOriginThrowsArgumentException()
        {
            var configuration = new AuthTokenValidationConfiguration();
            Assert.Throws<ArgumentNullException>(() => configuration.Validate())
                .WithMessage("Value cannot be null. (Parameter 'Origin URI')");
        }

        [Test]
        public void AuthTokenValidationConfigurationWithInvalidSiteOriginThrowsArgumentException()
        {
            var configuration =
                new AuthTokenValidationConfiguration { SiteOrigin = new Uri("invalid", UriKind.RelativeOrAbsolute) };
            Assert.Throws<ArgumentException>(() => configuration.Validate())
                .WithMessage("Provided URI is not a valid URL");
        }

        [Test]
        public void AuthTokenValidationConfigurationWithoutNonceCacheThrowsArgumentException()
        {
            var configuration =
                new AuthTokenValidationConfiguration
                {
                    SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute)
                };
            Assert.Throws<ArgumentNullException>(() => configuration.Validate())
                .WithMessage("Value cannot be null. (Parameter 'Nonce cache')");
        }

        [Test]
        public void AuthTokenValidationConfigurationWithoutTrustedCertificatesThrowsArgumentException()
        {
            using (var cache = new MemoryCache<DateTime>())
            {
                var configuration = new AuthTokenValidationConfiguration
                {
                    SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute),
                    NonceCache = cache
                };
                Assert.Throws<ArgumentException>(() => configuration.Validate())
                    .WithMessage("At least one trusted certificate authority must be provided");
            }
        }

        [Test]
        public void AuthTokenValidationConfigurationWithZeroOcspRequestTimeoutThrowsArgumentOutOfRangeException()
        {
            using (var cache = new MemoryCache<DateTime>())
            {
                var configuration = new AuthTokenValidationConfiguration
                {
                    SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute),
                    NonceCache = cache
                };
                configuration.TrustedCaCertificates.Add(new X509Certificate2());
                configuration.OcspRequestTimeout = TimeSpan.Zero;
                Assert.Throws<ArgumentOutOfRangeException>(() => configuration.Validate())
                    .WithMessage("OCSP request timeout must be greater than zero (Parameter 'duration')");
            }
        }

        [Test]
        public void AuthTokenValidationConfigurationWithCorrectDataDoesNotThrowException()
        {
            using (var cache = new MemoryCache<DateTime>())
            {
                var configuration = new AuthTokenValidationConfiguration
                {
                    SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute),
                    NonceCache = cache
                };
                configuration.SiteCertificateSha256Fingerprint = "fingerprint";
                configuration.TrustedCaCertificates.Add(new X509Certificate2());
                Assert.DoesNotThrow(() => configuration.Validate());
            }
        }

        [Test]
        public void AuthTokenValidationConfigurationCopyCopesAllData()
        {
            using (var cache = new MemoryCache<DateTime>())
            {
                var configuration = new AuthTokenValidationConfiguration
                {
                    SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute),
                    NonceCache = cache
                };
                configuration.OcspRequestTimeout = TimeSpan.FromMinutes(1);
                configuration.SiteCertificateSha256Fingerprint = "fingerprint";
                configuration.TrustedCaCertificates.Add(new X509Certificate2(Certificates.GetTestEsteid2015Ca()));
                configuration.TrustedCaCertificates.Add(new X509Certificate2(Certificates.GetTestEsteid2018Ca()));
                configuration.DesignatedOcspServiceConfiguration = new DesignatedOcspServiceConfiguration(
                    new Uri("http://ocsp.ee"),
                    DotNetUtilities.FromX509Certificate(Certificates.GetTestEsteid2018Ca()),
                    new List<X509Certificate>
                    {
                        DotNetUtilities.FromX509Certificate(Certificates.GetTestEsteid2015Ca()),
                        DotNetUtilities.FromX509Certificate(Certificates.GetTestEsteid2018Ca())
                    });

                var copyOfConfiguration = configuration.Copy();
                Assert.AreEqual(configuration, copyOfConfiguration);
            }
        }
    }
}
