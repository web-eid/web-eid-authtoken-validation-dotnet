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
namespace WebEid.Security.Validator
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Tokens;
    using Newtonsoft.Json;
    using Ocsp;
    using Ocsp.Service;
    using AuthToken;
    using Util;
    using WebEid.Security.Validator.CertValidators;

    /// <summary>
    /// Represents the configuration for validating authentication tokens (JWTs) in the Web eID system.
    /// </summary>
    public sealed class AuthTokenValidator : IAuthTokenValidator
    {
        private readonly ILogger logger;
        private readonly AuthTokenValidationConfiguration configuration;
        private readonly AuthTokenSignatureValidator authTokenSignatureValidator;
        private readonly SubjectCertificateValidatorBatch simpleSubjectCertificateValidators;
        private readonly OcspClient ocspClient;
        private readonly OcspServiceProvider ocspServiceProvider;

        private const int TokenMinLength = 100;
        private const int TokenMaxLength = 10000;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthTokenValidator"/> class.
        /// </summary>
        /// <param name="configuration">The configuration for token validation.</param>
        /// <param name="logger">The logger for capturing log messages (optional).</param>
        public AuthTokenValidator(AuthTokenValidationConfiguration configuration, ILogger logger = null)
        {
            this.logger = logger;
            this.configuration = configuration.Copy();
            this.authTokenSignatureValidator = new AuthTokenSignatureValidator(configuration.SiteOrigin);

            this.simpleSubjectCertificateValidators = SubjectCertificateValidatorBatch.CreateFrom(
                new SubjectCertificatePurposeValidator(this.logger),
                new SubjectCertificatePolicyValidator(configuration.DisallowedSubjectCertificatePolicies
                    .Select(policy => new Oid(policy))
                    .ToArray(), this.logger)
            );

            if (configuration.IsUserCertificateRevocationCheckWithOcspEnabled)
            {
                this.ocspClient = new OcspClient(TimeSpan.FromSeconds(5), this.logger);
                this.ocspServiceProvider =
                    new OcspServiceProvider(configuration.DesignatedOcspServiceConfiguration,
                        new AiaOcspServiceConfiguration(configuration.NonceDisabledOcspUrls,
                            configuration.TrustedCaCertificates));
            }

            // Turn off caching of signature providers
            CryptoProviderFactory.DefaultCacheSignatureProviders = false;
        }

        /// <summary>
        /// Parses the authentication token (JWT) and returns a <see cref="WebEidAuthToken"/> instance.
        /// </summary>
        /// <param name="authToken">The authentication token to parse.</param>
        /// <returns>A parsed <see cref="WebEidAuthToken"/> instance.</returns>
        public WebEidAuthToken Parse(string authToken)
        {
            this.logger?.LogInformation("Starting token parsing");

            try
            {
                ValidateTokenLength(authToken);
                return ParseToken(authToken);
            }
            catch (Exception ex)
            {
                // Generally "log and rethrow" is an anti-pattern, but it fits with the surrounding logging style.
                this.logger?.LogWarning("Token parsing was interrupted:", ex);
                throw;
            }
        }

        /// <summary>
        /// Validates the authentication token (JWT) and returns the user certificate.
        /// </summary>
        /// <param name="authToken">The authentication token to validate.</param>
        /// <param name="currentChallengeNonce">The current challenge nonce value.</param>
        /// <returns>A task representing the validation result with the user certificate.</returns>
        public Task<X509Certificate2> Validate(WebEidAuthToken authToken, string currentChallengeNonce)
        {
            this.logger?.LogInformation("Starting token validation");

            try
            {
                return this.ValidateToken(authToken, currentChallengeNonce);
            }
            catch (Exception ex)
            {
                // Generally "log and rethrow" is an anti-pattern, but it fits with the surrounding logging style.
                this.logger?.LogWarning("Token validation was interrupted:", ex);
                throw;
            }
        }

        private static void ValidateTokenLength(string authToken)
        {
            if (authToken == null || authToken.Length < TokenMinLength)
            {
                throw new AuthTokenParseException("Auth token is null or too short");
            }
            if (authToken.Length > TokenMaxLength)
            {
                throw new AuthTokenParseException("Auth token is too long");
            }
        }

        private static WebEidAuthToken ParseToken(string authToken)
        {
            try
            {
                var token = JsonConvert.DeserializeObject<WebEidAuthToken>(authToken);
                if (token == null)
                {
                    throw new AuthTokenParseException("Web eID authentication token deserialization failed");
                }
                return token;
            }
            catch (JsonException ex)
            {
                throw new AuthTokenParseException("Error parsing Web eID authentication token", ex);
            }
        }

        private async Task<X509Certificate2> ValidateToken(WebEidAuthToken token, string currentChallengeNonce)
        {
            if (token.Format == null || !token.Format.StartsWith(IAuthTokenValidator.CURRENT_TOKEN_FORMAT_VERSION))
            {
                throw new AuthTokenParseException($"Only token format version '{IAuthTokenValidator.CURRENT_TOKEN_FORMAT_VERSION}' is currently supported");
            }
            if (string.IsNullOrEmpty(token.UnverifiedCertificate))
            {
                throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
            }

            var subjectCertificate = X509CertificateExtensions.ParseCertificate(token.UnverifiedCertificate, "unverifiedCertificate");

            await this.simpleSubjectCertificateValidators.ExecuteFor(subjectCertificate);
            await this.GetCertTrustValidators().ExecuteFor(subjectCertificate);

            try
            {
                var publicKey = subjectCertificate
                    .GetAsymmetricPublicKey()
                    .CreateSecurityKeyWithoutCachingSignatureProviders();

                // It is guaranteed that if the signature verification succeeds, then the origin and challenge
                // have been implicitly and correctly verified without the need to implement any additional checks.
                this.authTokenSignatureValidator.Validate(token.Algorithm,
                        publicKey,
                        token.Signature,
                        currentChallengeNonce);

                return subjectCertificate;

            }
            catch (Exception ex) when (!(ex is AuthTokenException))
            {
                throw new AuthTokenSignatureValidationException(ex);
            }
        }

        /// <summary>
        /// Creates the certificate trust validator batch.
        /// As SubjectCertificateTrustedValidator has mutable state that SubjectCertificateNotRevokedValidator depends on,
        /// they cannot be reused/cached in an instance variable in a multi-threaded environment. Hence they are
        /// re-created for each validation run for thread safety.
        /// </summary>
        /// <returns>certificate trust validator batch</returns>
        private SubjectCertificateValidatorBatch GetCertTrustValidators()
        {
            var certTrustedValidator =
                new SubjectCertificateTrustedValidator(this.configuration.TrustedCaCertificates, this.logger);

            return SubjectCertificateValidatorBatch.CreateFrom(certTrustedValidator)
                .AddOptional(this.configuration.IsUserCertificateRevocationCheckWithOcspEnabled,
                    new SubjectCertificateNotRevokedValidator(certTrustedValidator,
                        this.ocspClient,
                        this.ocspServiceProvider,
                        this.configuration.AllowedOcspResponseTimeSkew,
                        this.configuration.MaxOcspResponseThisUpdateAge,
                        this.logger));
        }
    }
}
