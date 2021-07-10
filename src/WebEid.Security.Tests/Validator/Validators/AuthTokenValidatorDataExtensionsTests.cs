namespace WebEID.Security.Tests.Validator.Validators
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using Security.Validator.Validators;

    [TestFixture]
    public class AuthTokenValidatorDataExtensionsTests
    {
        private const string ExtendedKeyUsageClientAuthentication = "1.3.6.1.5.5.7.3.2";

        [Test]
        public void ValidateExpiredCertificateThrowsExpiredException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddYears(-5), DateTimeOffset.Now.AddYears(-1));
            var data = new AuthTokenValidatorData(cert);
            Assert.Throws<UserCertificateExpiredException>(() => data.ValidateCertificateExpiry());
        }

        [Test]
        public void ValidateNotYetValidCertificateThrowsNotYetValidException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddYears(1), DateTimeOffset.Now.AddYears(5));
            var data = new AuthTokenValidatorData(cert);
            Assert.Throws<UserCertificateNotYetValidException>(() => data.ValidateCertificateExpiry());
        }

        [Test]
        public void ValidateCertificateExpiryDoesNotThrowException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            var data = new AuthTokenValidatorData(cert);
            Assert.DoesNotThrow(() => data.ValidateCertificateExpiry());
        }

        [Test]
        public void ValidateCertificatePurposeThrowsMissingPurposeException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            var data = new AuthTokenValidatorData(cert);
            Assert.Throws<UserCertificateMissingPurposeException>(() => data.ValidateCertificatePurpose());
        }

        [Test]
        public void ValidateCertificatePurposeThrowsWrongPurposeException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.4") },
                true));
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            var data = new AuthTokenValidatorData(cert);
            Assert.Throws<UserCertificateWrongPurposeException>(() => data.ValidateCertificatePurpose());
        }

        [Test]
        public void ValidateCertificatePurposeDoesNotThrowException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(ExtendedKeyUsageClientAuthentication) },
                true));
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            var data = new AuthTokenValidatorData(cert);
            Assert.DoesNotThrow(() => data.ValidateCertificatePurpose());
        }
    }
}
