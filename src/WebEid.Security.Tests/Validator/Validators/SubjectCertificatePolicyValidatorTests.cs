namespace WebEid.Security.Tests.Validator.Validators
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using Security.Validator.Validators;
    using TestUtils;

    [TestFixture]
    public class SubjectCertificatePolicyValidatorTests
    {
        private X509Certificate certificate;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            this.certificate = CertificateLoader.LoadCertificateFromResource("TEST_of_ESTEID2018.cer");
        }

        [Test]
        public void ValidateSubjectCertificatePolicyThrowsDisallowedPolicyException()
        {
            var validator = new SubjectCertificatePolicyValidator(new[] { new Oid("1.3.6.1.4.1.51361.1.2.1") });
            Assert.Throws<UserCertificateDisallowedPolicyException>(() => validator.Validate(new AuthTokenValidatorData(this.certificate)));
        }

        [Test]
        public void ValidateSubjectCertificatePolicyDoesNotThrowException()
        {
            var validator = new SubjectCertificatePolicyValidator(new[] { new Oid("dummy identifier") });
            Assert.DoesNotThrow(() => validator.Validate(new AuthTokenValidatorData(this.certificate)));
        }

        [Test]
        public void ValidateSubjectCertificatePolicyThrowsInvalidPolicyException()
        {
            var req = new CertificateRequest("cn=foobar", ECDsa.Create(), HashAlgorithmName.SHA384);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            var validator = new SubjectCertificatePolicyValidator(new[] { new Oid("dummy") });
            Assert.Throws<UserCertificateInvalidPolicyException>(() => validator.Validate(new AuthTokenValidatorData(cert)));
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            this.certificate?.Dispose();
        }
    }
}
