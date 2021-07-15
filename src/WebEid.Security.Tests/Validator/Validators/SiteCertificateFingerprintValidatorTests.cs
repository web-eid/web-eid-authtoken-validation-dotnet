namespace WebEid.Security.Tests.Validator.Validators
{
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using Security.Validator.Validators;

    [TestFixture]
    public class SiteCertificateFingerprintValidatorTests
    {
        private const string CorrectFingerprint = "correct";
        private const string IncorrectFingerprint = "incorrect";

        [Test]
        public void CorrectFingerprintDoesNotThrowException()
        {
            Assert.DoesNotThrow(() =>
            {
                new SiteCertificateFingerprintValidator(CorrectFingerprint, new Logger()).Validate(
                    new AuthTokenValidatorData(null) { SiteCertificateFingerprint = CorrectFingerprint });
            });
        }

        [Test]
        public void IncorrectFingerprintThrowsException()
        {
            Assert.Throws<SiteCertificateFingerprintValidationException>(() =>
            {
                new SiteCertificateFingerprintValidator(CorrectFingerprint, new Logger()).Validate(
                    new AuthTokenValidatorData(null) { SiteCertificateFingerprint = IncorrectFingerprint });
            });
        }
    }
}
