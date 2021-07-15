namespace WebEid.Security.Validator.Validators
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;
    using Util;

    internal class CertificateExpiryValidator : IValidator
    {
        private readonly ILogger logger;

        public CertificateExpiryValidator(ILogger logger = null)
        {
            this.logger = logger;
        }

        public Task Validate(AuthTokenValidatorData actualTokenData)
        {
            var cert2 = new X509Certificate2(actualTokenData.SubjectCertificate);
            cert2.ValidateCertificateExpiry(DateTime.UtcNow, "User");
            this.logger?.LogDebug("User certificate is valid");
            return Task.CompletedTask;
        }
    }
}
