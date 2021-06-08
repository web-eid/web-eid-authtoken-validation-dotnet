namespace WebEID.Security.Tests.Validator
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Cache;
    using NUnit.Framework;
    using Security.Validator;
    using TestUtils;

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
                configuration.TrustedCaCertificates.Add(new X509Certificate());
                configuration.OcspRequestTimeout = TimeSpan.Zero;
                Assert.Throws<ArgumentOutOfRangeException>(() => configuration.Validate())
                    .WithMessage("OCSP request timeout must be greater than zero (Parameter 'duration')");
            }
        }

        [Test]
        public void AuthTokenValidationConfigurationWithZeroAllowedClientClockSkewThrowsArgumentOutOfRangeException()
        {
            using (var cache = new MemoryCache<DateTime>())
            {
                var configuration = new AuthTokenValidationConfiguration
                {
                    SiteOrigin = new Uri("https://valid", UriKind.RelativeOrAbsolute),
                    NonceCache = cache
                };
                configuration.TrustedCaCertificates.Add(new X509Certificate());
                configuration.AllowedClientClockSkew = TimeSpan.Zero;
                Assert.Throws<ArgumentOutOfRangeException>(() => configuration.Validate())
                    .WithMessage("Allowed client clock skew must be greater than zero (Parameter 'duration')");
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
                configuration.TrustedCaCertificates.Add(new X509Certificate());
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
                configuration.AllowedClientClockSkew = TimeSpan.FromMinutes(1);
                configuration.SiteCertificateSha256Fingerprint = "fingerprint";
                configuration.TrustedCaCertificates.Add(new X509Certificate());

                var copyOfConfiguration = configuration.Copy();
                Assert.AreEqual(configuration, copyOfConfiguration);
            }
        }
    }
}
