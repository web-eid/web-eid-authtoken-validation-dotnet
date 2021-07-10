namespace WebEID.Security.Validator.Validators
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using Microsoft.Extensions.Logging;

    public static class AuthTokenValidatorDataExtensions
    {
        private const string ExtendedKeyUsageClientAuthentication = "1.3.6.1.5.5.7.3.2";

        /// <summary>
        /// Checks the validity of the user certificate from the authentication token.
        /// </summary>
        /// <param name="actualTokenData">authentication token data that contains the user certificate</param>
        /// <param name="logger">Logger instance to log validation result</param>
        /// <exception cref="TokenValidationException">when the user certificate is expired or not yet valid</exception>
        public static void ValidateCertificateExpiry(this AuthTokenValidatorData actualTokenData, ILogger logger = null)
        {
            using (var cert2 = new X509Certificate2(actualTokenData.SubjectCertificate))
            {
                // Use JJWT Clock interface so that the date can be mocked in tests.
                if (cert2.NotAfter <= DateTime.Now)
                {
                    throw new UserCertificateExpiredException();
                }

                if (cert2.NotBefore > DateTime.Now)
                {
                    throw new UserCertificateNotYetValidException();
                }
            }

            logger?.LogDebug("User certificate is valid.");
        }

        /// <summary>
        /// Validates that the purpose of the user certificate from the authentication token contains client authentication.
        /// </summary>
        /// <param name="actualTokenData">authentication token data that contains the user certificate</param>
        /// <param name="logger">Logger instance to log validation result</param>
        /// <exception cref="TokenValidationException">when the purpose of certificate does not contain client authentication</exception>
        public static void ValidateCertificatePurpose(this AuthTokenValidatorData actualTokenData, ILogger logger = null)
        {
            try
            {
                using (var cert2 = new X509Certificate2(actualTokenData.SubjectCertificate))
                {
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
                }

                logger?.LogDebug("User certificate can be used for client authentication.");
            }
            catch (CryptographicException ex)
            {
                throw new UserCertificateParseException(ex);
            }
            catch (ArgumentNullException ex)
            {
                throw new UserCertificateParseException(ex);
            }
        }
    }
}
