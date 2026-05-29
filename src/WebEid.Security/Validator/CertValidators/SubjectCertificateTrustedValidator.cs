// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Validator.CertValidators
{
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using Util;
    using WebEid.Security.Exceptions;

    internal sealed class SubjectCertificateTrustedValidator : ISubjectCertificateValidator
    {
        private readonly ICollection<X509Certificate2> trustedCaCertificates;
        private readonly ILogger logger;

        public SubjectCertificateTrustedValidator(ICollection<X509Certificate2> trustedCaCertificates, ILogger logger)
        {
            this.trustedCaCertificates = trustedCaCertificates;
            this.logger = logger;
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
            this.SubjectCertificateIssuerCertificate = subjectCertificate.ValidateIsValidAndSignedByTrustedCa(this.trustedCaCertificates);
            this.logger?.LogDebug("Subject certificate is valid and signed by a trusted CA");

            return Task.CompletedTask;
        }

        public X509Certificate2 SubjectCertificateIssuerCertificate { get; private set; }
    }
}
