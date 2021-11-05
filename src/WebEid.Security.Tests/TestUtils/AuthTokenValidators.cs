namespace WebEid.Security.Tests.TestUtils
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Security.Cache;
    using Security.Validator;

    public static class AuthTokenValidators
    {
        private const string TokenOriginUrl = "https://ria.ee";
        private const string EstIdemiaPolicy = "1.3.6.1.4.1.51361.1.2.1";

        public static IAuthTokenValidator GetAuthTokenValidator(ICache<DateTime> cache)
        {
            return GetAuthTokenValidator(TokenOriginUrl, cache);
        }

        public static IAuthTokenValidator GetAuthTokenValidator(string url, ICache<DateTime> cache)
        {
            return GetAuthTokenValidator(url, cache, GetCaCertificates());
        }

        public static IAuthTokenValidator GetAuthTokenValidator(string url, ICache<DateTime> cache, params X509Certificate[] certificates)
        {
            return GetAuthTokenValidatorBuilder(url, cache, certificates)
                // Assure that all builder methods are covered with tests.
                .WithOcspRequestTimeout(TimeSpan.FromSeconds(1))
                .WithNonceDisabledOcspUrls(new Uri("http://example.org"))
                .WithoutUserCertificateRevocationCheckWithOcsp()
                .Build();
        }

        public static IAuthTokenValidator GetAuthTokenValidator(ICache<DateTime> cache, string certFingerprint)
        {
            return GetAuthTokenValidatorBuilder(TokenOriginUrl, cache, GetCaCertificates())
                .WithSiteCertificateSha256Fingerprint(certFingerprint)
                .WithoutUserCertificateRevocationCheckWithOcsp()
                .Build();
        }

        public static IAuthTokenValidator GetAuthTokenValidatorWithOcspCheck(ICache<DateTime> cache)
        {
            return GetAuthTokenValidatorBuilder(TokenOriginUrl, cache, GetCaCertificates())
                .Build();
        }

        public static IAuthTokenValidator GetAuthTokenValidatorWithDesignatedOcspCheck(ICache<DateTime> cache)
        {
            return GetAuthTokenValidatorBuilder(TokenOriginUrl, cache, GetCaCertificates())
                .WithDesignatedOcspServiceConfiguration(OcspServiceMaker.GetDesignatedOcspServiceConfiguration())
                .Build();
        }

        public static IAuthTokenValidator GetAuthTokenValidatorWithWrongTrustedCa(ICache<DateTime> cache)
        {
            return GetAuthTokenValidator(TokenOriginUrl, cache,
                CertificateLoader.LoadCertificatesFromResources("ESTEID2018.cer"));
        }

        public static IAuthTokenValidator GetAuthTokenValidatorWithDisallowedEsteidPolicy(ICache<DateTime> cache)
        {
            return GetAuthTokenValidatorBuilder(TokenOriginUrl, cache, GetCaCertificates())
                .WithDisallowedCertificatePolicies(EstIdemiaPolicy)
                .Build();
        }

        private static AuthTokenValidatorBuilder GetAuthTokenValidatorBuilder(string uri, ICache<DateTime> cache, X509Certificate[] certificates)
        {
            return new AuthTokenValidatorBuilder()
                .WithSiteOrigin(new Uri(uri))
                .WithNonceCache(cache)
                .WithTrustedCertificateAuthorities(certificates);
        }

        private static X509Certificate[] GetCaCertificates()
        {
            return CertificateLoader.LoadCertificatesFromResources("TEST_of_ESTEID2018.cer");
        }
    }
}
