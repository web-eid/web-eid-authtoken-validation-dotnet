namespace WebEid.Security.Validator.Validators
{
    using System.Threading.Tasks;
    using Exceptions;
    using Microsoft.Extensions.Logging;

    internal sealed class SiteCertificateFingerprintValidator : IValidator
    {
        private readonly string expectedSiteCertificateFingerprint;
        private readonly ILogger logger;

        public SiteCertificateFingerprintValidator(string expectedSiteCertificateFingerprint, ILogger logger = null)
        {
            this.expectedSiteCertificateFingerprint = expectedSiteCertificateFingerprint;
            this.logger = logger;
        }

        /// <summary>
        /// Validates that the site certificate fingerprint from the authentication token matches with
        /// the configured site certificate fingerprint.
        /// </summary>
        /// <param name="actualTokenData">authentication token data that contains the site fingerprint from authentication token</param>
        /// <exception cref="TokenValidationException"> when fingerprints don't match</exception>
        public Task Validate(AuthTokenValidatorData actualTokenData)
        {
            if (!this.expectedSiteCertificateFingerprint.Equals(actualTokenData.SiteCertificateFingerprint))
            {
                throw new SiteCertificateFingerprintValidationException();
            }
            this.logger?.LogDebug("Site certificate fingerprint is equal to expected fingerprint.");
            return Task.CompletedTask;
        }
    }
}
