// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Validator.VersionValidators
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using CertValidators;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Ocsp;
    using Ocsp.Service;

    /// <summary>
    /// Provides a factory for selecting the correct authentication token validator
    /// based on the token format version.
    /// </summary>
    /// <remarks>
    /// Creates a new instance of the <see cref="AuthTokenVersionValidatorFactory"/> class.
    /// </remarks>
    public sealed class AuthTokenVersionValidatorFactory(IList<IAuthTokenVersionValidator> validators)
    {
        private readonly IReadOnlyList<IAuthTokenVersionValidator> validators = validators?.ToList()
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
            var validator = validators.FirstOrDefault(v => v.Supports(format)) ?? throw new AuthTokenParseException(
                    $"Token format version '{format}' is currently not supported");

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
            ArgumentNullException.ThrowIfNull(configuration);

            var validationConfig = configuration.Copy();
            var trustedCaCertificates = validationConfig.TrustedCaCertificates;

            var simpleSubjectValidators = SubjectCertificateValidatorBatch.CreateFrom(
                new SubjectCertificatePurposeValidator(logger),
                new SubjectCertificatePolicyValidator(
                    [.. validationConfig.DisallowedSubjectCertificatePolicies.Select(x => new Oid(x))],
                    logger)
            );

            OcspServiceProvider ocspServiceProvider = null;

            if (validationConfig.IsUserCertificateRevocationCheckWithOcspEnabled && ocspClient != null)
            {
                ocspServiceProvider = new OcspServiceProvider(
                    validationConfig.DesignatedOcspServiceConfiguration,
                    new AiaOcspServiceConfiguration(
                        validationConfig.NonceDisabledOcspUrls,
                        trustedCaCertificates,
                        validationConfig.AiaOcspResponderIssuerMatchingPolicy,
                        validationConfig.OcspRequestTimeout
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

            return new AuthTokenVersionValidatorFactory(
            [
                validatorV11,
                validatorV10
            ]);
        }
    }
}
