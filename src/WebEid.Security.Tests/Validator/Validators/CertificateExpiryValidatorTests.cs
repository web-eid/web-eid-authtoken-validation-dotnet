namespace WebEid.Security.Tests.Validator.Validators
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using Security.Validator.Validators;

    [TestFixture]
    public class CertificateExpiryValidatorTests
    {
        [Test]
        public void ValidateExpiredCertificateThrowsExpiredException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddYears(-5), DateTimeOffset.Now.AddYears(-1));
            var validator = new CertificateExpiryValidator(new Logger());
            Assert.Throws<CertificateExpiredException>(() => validator.Validate(new AuthTokenValidatorData(cert)));
        }

        [Test]
        public void ValidateNotYetValidCertificateThrowsNotYetValidException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddYears(1), DateTimeOffset.Now.AddYears(5));
            var validator = new CertificateExpiryValidator(new Logger());
            Assert.Throws<CertificateNotYetValidException>(() => validator.Validate(new AuthTokenValidatorData(cert)));
        }

        [Test]
        public void ValidateCertificateExpiryDoesNotThrowException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            var validator = new CertificateExpiryValidator(new Logger());
            Assert.DoesNotThrow(() => validator.Validate(new AuthTokenValidatorData(cert)));
        }
    }
}
