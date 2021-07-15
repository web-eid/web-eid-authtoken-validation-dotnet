namespace WebEid.Security.Validator.Validators
{
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Util;

    internal sealed class SubjectCertificateTrustedValidator : IValidator
    {
        private readonly ICollection<X509Certificate2> trustedCaCertificates;

        public SubjectCertificateTrustedValidator(ICollection<X509Certificate2> trustedCaCertificates)
        {
            this.trustedCaCertificates = trustedCaCertificates;
        }
        
        /// <summary>
        /// Validates that the user certificate from the authentication token is signed by a trusted certificate authority.
        /// </summary>
        /// <param name="actualTokenData">authentication token data that contains the user certificate.</param>
        /// <exception cref="UserCertificateNotTrustedException">when user certificate is not signed by a trusted CA or is valid after CA certificate.</exception>
        public Task Validate(AuthTokenValidatorData actualTokenData)
        {
            this.SubjectCertificateIssuerCertificate =
                new X509Certificate2(actualTokenData.SubjectCertificate).ValidateIsSignedByTrustedCa(
                    this.trustedCaCertificates);
            return Task.CompletedTask;
        }

        public X509Certificate2 SubjectCertificateIssuerCertificate { get; private set; }
    }
}
