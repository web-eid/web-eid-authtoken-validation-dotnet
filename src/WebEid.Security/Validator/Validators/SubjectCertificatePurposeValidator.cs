namespace WebEid.Security.Validator.Validators
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Microsoft.Extensions.Logging;

    public class SubjectCertificatePurposeValidator : IValidator
    {
        private readonly ILogger logger;
        private const string ExtendedKeyUsageClientAuthentication = "1.3.6.1.5.5.7.3.2";

        /// <summary>
        /// Creates an instance of SubjectCertificatePurposeValidator
        /// </summary>
        /// <param name="logger">Logger instance to log validation result</param>
        public SubjectCertificatePurposeValidator(ILogger logger = null)
        {
            this.logger = logger;
        }

        /// <summary>
        /// Validates that the purpose of the user certificate from the authentication token contains client authentication.
        /// </summary>
        /// <param name="actualTokenData">authentication token data that contains the user certificate</param>
        /// <exception cref="TokenValidationException">when the purpose of certificate does not contain client authentication</exception>
        public Task Validate(AuthTokenValidatorData actualTokenData)
        {
            try
            {
                var cert2 = new X509Certificate2(actualTokenData.SubjectCertificate);
                var usages = cert2.Extensions.OfType<X509EnhancedKeyUsageExtension>().ToArray();
                if (!usages.Any())
                {
                    throw new UserCertificateMissingPurposeException();
                }

                if (usages.SelectMany(oid => oid.EnhancedKeyUsages.OfType<Oid>())
                    .All(oid => oid.Value != ExtendedKeyUsageClientAuthentication))
                {
                    throw new UserCertificateWrongPurposeException();
                }

                this.logger?.LogDebug("User certificate can be used for client authentication.");
            }
            catch (CryptographicException ex)
            {
                throw new UserCertificateParseException(ex);
            }
            catch (ArgumentNullException ex)
            {
                throw new UserCertificateParseException(ex);
            }

            return Task.CompletedTask;
        }
    }
}
