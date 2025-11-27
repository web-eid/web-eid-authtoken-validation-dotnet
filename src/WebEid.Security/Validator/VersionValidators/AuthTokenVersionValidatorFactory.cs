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
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using CertValidators;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Ocsp;
    using Ocsp.Service;

    /// <summary>
    /// Provides a factory for selecting the correct authentication token validator
    /// based on the token format version.
    /// </summary>
    public sealed class AuthTokenVersionValidatorFactory
    {
        private readonly IReadOnlyList<IAuthTokenVersionValidator> validators;

        /// <summary>
        /// Creates a new instance of the <see cref="AuthTokenVersionValidatorFactory"/> class.
        /// </summary>
        public AuthTokenVersionValidatorFactory(IList<IAuthTokenVersionValidator> validators) =>
            this.validators = validators?.ToList()
                              ?? throw new ArgumentNullException(nameof(validators));

        /// <summary>
        /// Determines whether any registered validator supports the specified token format.
        /// </summary>
        public bool Supports(string format) =>
            validators.Any(v => v.Supports(format));

        /// <summary>
        /// Returns the validator that supports the given token format.
        /// </summary>
        public IAuthTokenVersionValidator GetValidatorFor(string format)
        {
            var validator = validators.FirstOrDefault(v => v.Supports(format));

            if (validator == null)
            {
                throw new AuthTokenParseException(
                    $"Token format version '{format}' is currently not supported");
            }

            return validator;
        }

        /// <summary>
        /// Creates an <see cref="AuthTokenVersionValidatorFactory"/> instance configured
        /// with version-specific Web eID authentication token validators.
        /// </summary>
        public static AuthTokenVersionValidatorFactory Create(
            AuthTokenValidationConfiguration configuration,
            IOcspClient ocspClient,
            ILogger logger = null)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var validationConfig = configuration.Copy();
            var trustedCaCertificates = validationConfig.TrustedCaCertificates;
            var trustedCACertificate = new X509Certificate2Collection();
            trustedCACertificate.AddRange(trustedCaCertificates.ToArray());

            var simpleSubjectValidators = SubjectCertificateValidatorBatch.CreateFrom(
                new SubjectCertificatePurposeValidator(logger),
                new SubjectCertificatePolicyValidator(
                    validationConfig.DisallowedSubjectCertificatePolicies.Select(x => new Oid(x)).ToArray(),
                    logger)
            );

            OcspServiceProvider ocspServiceProvider = null;

            if (validationConfig.IsUserCertificateRevocationCheckWithOcspEnabled && ocspClient != null)
            {
                ocspServiceProvider = new OcspServiceProvider(
                    validationConfig.DesignatedOcspServiceConfiguration,
                    new AiaOcspServiceConfiguration(
                        validationConfig.NonceDisabledOcspUrls,
                        trustedCaCertificates
                    )
                );
            }

            var signatureValidator = new AuthTokenSignatureValidator(validationConfig.SiteOrigin);
            var validatorV10 = new AuthTokenVersion1Validator(
                simpleSubjectValidators,
                signatureValidator,
                validationConfig,
                ocspClient,
                ocspServiceProvider,
                logger
            );

            var validatorV11 = new AuthTokenVersion11Validator(
                simpleSubjectValidators,
                signatureValidator,
                validationConfig,
                ocspClient,
                ocspServiceProvider,
                logger
            );

            return new AuthTokenVersionValidatorFactory(new List<IAuthTokenVersionValidator>
            {
                validatorV11,
                validatorV10
            });
        }
    }
}
