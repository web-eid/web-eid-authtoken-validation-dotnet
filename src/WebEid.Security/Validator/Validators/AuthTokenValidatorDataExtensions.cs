namespace WebEid.Security.Validator.Validators
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using Microsoft.Extensions.Logging;

    internal static class AuthTokenValidatorDataExtensions
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
}
