/*
 * Copyright © 2020-2023 Estonian Information System Authority
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

        public static IAuthTokenValidator GetAuthTokenValidator(string url, params X509Certificate2[] certificates) =>
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

        private static AuthTokenValidatorBuilder GetAuthTokenValidatorBuilder(string uri, X509Certificate2[] certificates) =>
            new AuthTokenValidatorBuilder()
                .WithSiteOrigin(new Uri(uri))
                .WithTrustedCertificateAuthorities(certificates);

        private static X509Certificate2[] GetCaCertificates() =>
            Certificates.CertificateLoader.LoadCertificatesFromResources("TEST_of_ESTEID2018.cer");
    }
}
