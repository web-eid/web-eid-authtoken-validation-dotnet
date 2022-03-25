namespace WebEid.Security.Tests.TestUtils
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Security.Validator;

    public static class AuthTokenValidators
    {
        private const string TokenOriginUrl = "https://ria.ee";
        private const string EstIdemiaPolicy = "1.3.6.1.4.1.51361.1.2.1";

        public static IAuthTokenValidator GetAuthTokenValidator() =>
            GetAuthTokenValidator(TokenOriginUrl);

        public static IAuthTokenValidator GetAuthTokenValidator(string url) =>
            GetAuthTokenValidator(url, GetCaCertificates());

        public static IAuthTokenValidator GetAuthTokenValidator(string url, params X509Certificate[] certificates) =>
            GetAuthTokenValidatorBuilder(url, certificates)
                // Assure that all builder methods are covered with tests.
                .WithOcspRequestTimeout(TimeSpan.FromSeconds(1))
                .WithNonceDisabledOcspUrls(new Uri("http://example.org"))
                .WithoutUserCertificateRevocationCheckWithOcsp()
                .Build();

        public static IAuthTokenValidator GetAuthTokenValidatorWithOcspCheck() =>
            GetAuthTokenValidatorBuilder(TokenOriginUrl, GetCaCertificates())
                .Build();

        public static IAuthTokenValidator GetAuthTokenValidatorWithDesignatedOcspCheck() =>
            GetAuthTokenValidatorBuilder(TokenOriginUrl, GetCaCertificates())
                .WithDesignatedOcspServiceConfiguration(OcspServiceMaker.GetDesignatedOcspServiceConfiguration())
                .Build();

        public static IAuthTokenValidator GetAuthTokenValidatorWithWrongTrustedCa() =>
            GetAuthTokenValidator(TokenOriginUrl,
                Certificates.CertificateLoader.LoadCertificatesFromResources("ESTEID2018.cer"));

        public static IAuthTokenValidator GetAuthTokenValidatorWithDisallowedEsteidPolicy() =>
            GetAuthTokenValidatorBuilder(TokenOriginUrl, GetCaCertificates())
                .WithDisallowedCertificatePolicies(EstIdemiaPolicy)
                .Build();

        private static AuthTokenValidatorBuilder GetAuthTokenValidatorBuilder(string uri, X509Certificate[] certificates) =>
            new AuthTokenValidatorBuilder()
                .WithSiteOrigin(new Uri(uri))
                .WithTrustedCertificateAuthorities(certificates);

        private static X509Certificate[] GetCaCertificates() =>
            Certificates.CertificateLoader.LoadCertificatesFromResources("TEST_of_ESTEID2018.cer");
    }
}
