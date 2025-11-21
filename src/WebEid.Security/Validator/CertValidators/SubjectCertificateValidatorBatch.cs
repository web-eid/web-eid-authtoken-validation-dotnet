/*
 * Copyright © 2020-2025 Estonian Information System Authority
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
namespace WebEid.Security.Validator.CertValidators
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using Ocsp;
    using WebEid.Security.Validator;

    /// <summary>
    /// Represents an ordered batch of subject certificate validators that are executed sequentially
    /// during authentication token validation.
    /// </summary>
    internal sealed class SubjectCertificateValidatorBatch
    {
        private readonly List<ISubjectCertificateValidator> validatorList;

        /// <summary>
        /// Creates a new <see cref="SubjectCertificateValidatorBatch"/> from the provided validators.
        /// </summary>
        internal static SubjectCertificateValidatorBatch CreateFrom(params ISubjectCertificateValidator[] validatorList) =>
            new([.. validatorList]);

        /// <summary>
        /// Executes all validators in this batch for the specified subject certificate.
        /// </summary>
        public async Task ExecuteFor(X509Certificate2 subjectCertificate)
        {
            foreach (var validator in validatorList)
            {
                await validator.Validate(subjectCertificate);
            }
        }

        /// <summary>
        /// Creates the certificate trust validators batch.
        /// As SubjectCertificateTrustedValidator has mutable state that SubjectCertificateNotRevokedValidator depends on,
        /// they cannot be reused/cached in an instance variable in a multi-threaded environment. Hence, they are
        /// re-created for each validation run for thread safety.
        ///
        /// @return certificate trust validator batch
        /// </summary>
        public static SubjectCertificateValidatorBatch ForTrustValidation(
            AuthTokenValidationConfiguration configuration,
            ICollection<X509Certificate2> trustedCaCertificates,
            IOcspClient ocspClient,
            OcspServiceProvider ocspServiceProvider,
            ILogger logger)
        {
            if (configuration.IsUserCertificateRevocationCheckWithOcspEnabled)
            {
                if (ocspClient == null)
                {
                    throw new InvalidOperationException("OCSP revocation checking is enabled but IOcspClient is not configured");
                }

                if (ocspServiceProvider == null)
                {
                    throw new InvalidOperationException("OCSP revocation checking is enabled but OcspServiceProvider is not configured");
                }
            }

            var certTrustedValidator = new SubjectCertificateTrustedValidator(trustedCaCertificates, logger);
            var batch = CreateFrom(certTrustedValidator);

            if (configuration.IsUserCertificateRevocationCheckWithOcspEnabled)
            {
                batch.validatorList.Add(
                    new SubjectCertificateNotRevokedValidator(
                        certTrustedValidator,
                        ocspClient,
                        ocspServiceProvider,
                        configuration.AllowedOcspResponseTimeSkew,
                        configuration.MaxOcspResponseThisUpdateAge,
                        logger
                    )
                );
            }

            return batch;
        }

        private SubjectCertificateValidatorBatch(List<ISubjectCertificateValidator> validatorList) =>
            this.validatorList = validatorList;
    }
}
