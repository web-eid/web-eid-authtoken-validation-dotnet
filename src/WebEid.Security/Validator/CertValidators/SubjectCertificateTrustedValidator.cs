namespace WebEid.Security.Validator.CertValidators
{
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using Util;

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
        /// Validates that the user certificate from the authentication token is signed by a trusted certificate authority.
        /// </summary>
        /// <param name="subjectCertificate">the user certificate.</param>
        /// <exception cref="UserCertificateNotTrustedException">when user certificate is not signed by a trusted CA or is valid after CA certificate.</exception>
        public Task Validate(X509Certificate2 subjectCertificate)
        {
            this.SubjectCertificateIssuerCertificate = subjectCertificate.ValidateIsSignedByTrustedCa(this.trustedCaCertificates);
            this.logger?.LogDebug("Subject certificate is signed by a trusted CA");

            return Task.CompletedTask;
        }

        public X509Certificate2 SubjectCertificateIssuerCertificate { get; private set; }
    }
}
