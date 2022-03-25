namespace WebEid.Security.Validator.CertValidators
{
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using Util;

    internal class SubjectCertificateExpiryValidator : ISubjectCertificateValidator
    {
        private readonly List<X509Certificate2> trustedCaCertificates;
        private readonly ILogger logger;

        public SubjectCertificateExpiryValidator(List<X509Certificate2> trustedCaCertificates, ILogger logger = null)
        {
            this.trustedCaCertificates = trustedCaCertificates;
            this.logger = logger;
        }

        /// <summary>
        /// Checks the validity of the user certificate from the authentication token
        /// and the validity of trusted CA certificates.
        /// </summary>
        /// <param name="subjectCertificate">user certificate to be validated</param>
        /// <exception cref="AuthTokenException">when a CA certificate or the user certificate is expired or not yet valid</exception>
        public Task Validate(X509Certificate2 subjectCertificate)
        {
            var now = DateTimeProvider.UtcNow;

            foreach (var cert in this.trustedCaCertificates)
            {
                cert.ValidateCertificateExpiry(now, "Trusted CA");
            }
            this.logger?.LogDebug("CA certificates are valid");

            subjectCertificate.ValidateCertificateExpiry(now, "User");
            this.logger?.LogDebug("User certificate is valid");

            return Task.CompletedTask;
        }
    }
}
