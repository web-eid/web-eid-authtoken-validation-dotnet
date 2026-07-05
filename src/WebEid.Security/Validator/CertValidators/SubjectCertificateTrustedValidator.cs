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
    using Util;
    using WebEid.Security.Exceptions;

    internal sealed class SubjectCertificateTrustedValidator(ICollection<X509Certificate2> trustedCaCertificates,
        ICollection<X509Certificate2> additionalIntermediateCertificates,
        TimeSpan revocationUrlRetrievalTimeout,
        ILogger logger) : ISubjectCertificateValidator
    {
        private readonly ICollection<X509Certificate2> trustedCaCertificates = trustedCaCertificates;
        private readonly ICollection<X509Certificate2> additionalIntermediateCertificates = additionalIntermediateCertificates ?? [];
        private readonly TimeSpan revocationUrlRetrievalTimeout = revocationUrlRetrievalTimeout;
        private readonly ILogger logger = logger;

        internal SubjectCertificateTrustedValidator(ICollection<X509Certificate2> trustedCaCertificates,
            ICollection<X509Certificate2> additionalIntermediateCertificates,
            ILogger logger)
            : this(trustedCaCertificates, additionalIntermediateCertificates, TimeSpan.FromSeconds(5), logger)
        {
        }

        internal SubjectCertificateTrustedValidator(ICollection<X509Certificate2> trustedCaCertificates, ILogger logger)
            : this(trustedCaCertificates, [], TimeSpan.FromSeconds(5), logger)
        {
        }

        /// <summary>
        /// Checks that the user certificate from the authentication token is valid and signed by
        /// a trusted certificate authority. Also checks the validity of the user certificate's
        /// trusted CA certificate.
        /// </summary>
        /// <param name="subjectCertificate">the user certificate to be validated</param>
        /// <exception cref="CertificateNotTrustedException">when user certificate is not signed by a trusted CA</exception>
        /// <exception cref="CertificateNotYetValidException">when a CA certificate in the chain or the user certificate is not yet valid</exception>
        /// <exception cref="CertificateExpiredException">when a CA certificate in the chain or the user certificate is expired</exception>
        public Task Validate(X509Certificate2 subjectCertificate)
        {
            SubjectCertificateIssuerCertificate = subjectCertificate.ValidateIsValidAndSignedByTrustedCa(
                "User",
                trustedCaCertificates,
                additionalIntermediateCertificates,
                // Intermediate CA certificates require revocation checks here because they are not checked elsewhere.
                // Subject certificate revocation is handled separately by SubjectCertificateNotRevokedValidator.
                IntermediateRevocationCheck.Enabled,
                revocationUrlRetrievalTimeout,
                DateTimeProvider.UtcNow);

            logger?.LogDebug("Subject certificate is valid and signed by a trusted CA");

            return Task.CompletedTask;
        }

        /// <summary>
        /// Returns the certificate that directly issued the subject certificate, or the trust anchor when the anchor
        /// is the direct issuer. Available after <see cref="Validate(X509Certificate2)"/> has succeeded.
        /// </summary>
        public X509Certificate2 SubjectCertificateIssuerCertificate { get; private set; }
    }
}
