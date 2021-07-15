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
    public class SubjectCertificatePurposeValidatorTests
    {
        private const string ExtendedKeyUsageClientAuthentication = "1.3.6.1.5.5.7.3.2";

        [Test]
        public void ValidateCertificatePurposeThrowsMissingPurposeException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            var validator = new SubjectCertificatePurposeValidator(new Logger());
            Assert.Throws<UserCertificateMissingPurposeException>(() => validator.Validate(new AuthTokenValidatorData(cert)));
        }

        [Test]
        public void ValidateCertificatePurposeThrowsWrongPurposeException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.4") },
                true));
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            var validator = new SubjectCertificatePurposeValidator(new Logger());
            Assert.Throws<UserCertificateWrongPurposeException>(() => validator.Validate(new AuthTokenValidatorData(cert)));
        }

        [Test]
        public void ValidateCertificatePurposeDoesNotThrowException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(ExtendedKeyUsageClientAuthentication) },
                true));
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            var validator = new SubjectCertificatePurposeValidator(new Logger());
            Assert.DoesNotThrow(() => validator.Validate(new AuthTokenValidatorData(cert)));
        }
    }
}
