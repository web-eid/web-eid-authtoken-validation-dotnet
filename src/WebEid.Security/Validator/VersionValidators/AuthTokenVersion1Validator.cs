/*
 * Copyright © 2025-2025 Estonian Information System Authority
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
namespace WebEid.Security.Validator.VersionValidators
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using CertValidators;
    using AuthToken;
    using Exceptions;
    using Util;
    using Ocsp;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Validator for token format web-eid:1.0.
    /// </summary>
    public class AuthTokenVersion1Validator : IAuthTokenVersionValidator
    {
        private const string FormatPrefix = "web-eid:1";

        private readonly SubjectCertificateValidatorBatch simpleSubjectCertificateValidators;
        private readonly AuthTokenSignatureValidator signatureValidator;
        private readonly AuthTokenValidationConfiguration configuration;
        private readonly IOcspClient ocspClient;
        private readonly OcspServiceProvider ocspServiceProvider;
        private readonly ILogger logger;

        /// <summary>
        /// Initializes a validator for Web eID authentication tokens in format <c>web-eid:1.0</c>.
        /// </summary>
        public AuthTokenVersion1Validator(
            SubjectCertificateValidatorBatch simpleSubjectCertificateValidators,
            AuthTokenSignatureValidator signatureValidator,
            AuthTokenValidationConfiguration configuration,
            IOcspClient ocspClient,
            OcspServiceProvider ocspServiceProvider,
            ILogger logger = null)
        {
            this.simpleSubjectCertificateValidators = simpleSubjectCertificateValidators;
            this.signatureValidator = signatureValidator;
            this.configuration = configuration;
            this.ocspClient = ocspClient;
            this.ocspServiceProvider = ocspServiceProvider;
            this.logger = logger;
        }

        /// <summary>
        /// Determines whether this validator supports the specified token format.
        /// </summary>
        public virtual bool Supports(string format) =>
            format != null &&
            format.StartsWith(FormatPrefix, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Validates a Web eID authentication token and returns the authenticated user's certificate.
        /// </summary>
        public virtual async Task<X509Certificate2> Validate(WebEidAuthToken authToken, string currentChallengeNonce)
        {
            if (string.IsNullOrEmpty(authToken.UnverifiedCertificate))
            {
                throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
            }

            var subjectCertificate = X509CertificateExtensions.ParseCertificate(
                authToken.UnverifiedCertificate,
                "unverifiedCertificate"
            );

            await simpleSubjectCertificateValidators.ExecuteFor(subjectCertificate);

            var trustValidators =
                SubjectCertificateValidatorBatch.CreateFrom(
                    new SubjectCertificateTrustedValidator(configuration.TrustedCaCertificates, logger)
                ).AddOptional(
                    configuration.IsUserCertificateRevocationCheckWithOcspEnabled &&
                    ocspClient != null &&
                    ocspServiceProvider != null,
                    new SubjectCertificateNotRevokedValidator(
                        new SubjectCertificateTrustedValidator(configuration.TrustedCaCertificates, logger),
                        ocspClient,
                        ocspServiceProvider,
                        configuration.AllowedOcspResponseTimeSkew,
                        configuration.MaxOcspResponseThisUpdateAge,
                        logger
                    )
                );

            await trustValidators.ExecuteFor(subjectCertificate);

            try
            {
                signatureValidator.Validate(
                    authToken.Algorithm,
                    subjectCertificate.GetAsymmetricPublicKey().CreateSecurityKeyWithoutCachingSignatureProviders(),
                    authToken.Signature,
                    currentChallengeNonce
                );
            }
            catch (Exception ex) when (!(ex is AuthTokenException))
            {
                throw new AuthTokenSignatureValidationException(ex);
            }

            return subjectCertificate;
        }
    }
}
