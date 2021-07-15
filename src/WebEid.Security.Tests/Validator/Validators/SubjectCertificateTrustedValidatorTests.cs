namespace WebEid.Security.Tests.Validator.Validators
{
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using Security.Validator.Validators;
    using TestUtils;

    [TestFixture]
    public class SubjectCertificateTrustedValidatorTests
    {
        [Test]
        public void ValidateUserCertAgainstWrongCaRootThrowsException()
        {
            var certificates =
                CertificateLoader.LoadCertificatesFromResources("ESTEID2018.cer");
            var validator =
                new SubjectCertificateTrustedValidator(
                    certificates.Select(cert => new X509Certificate2(cert)).ToArray());
            Assert.Throws<CertificateNotTrustedException>(() =>
                validator.Validate(
                    new AuthTokenValidatorData(CertificateLoader.LoadCertificateFromResource("Karl-Kristjan-Joeorg.cer"))));
        }

        [Test]
        public void ValidateUserCertAgainstCorrectCaRootDoesNotThrowException()
        {
            var certificates =
                CertificateLoader.LoadCertificatesFromResources("TEST_of_ESTEID2018.cer");
            var validator =
                new SubjectCertificateTrustedValidator(
                    certificates.Select(cert => new X509Certificate2(cert)).ToArray());
            Assert.DoesNotThrow(() =>
                validator.Validate(
                    new AuthTokenValidatorData(CertificateLoader.LoadCertificateFromResource("Karl-Kristjan-Joeorg.cer"))));
        }
    }
}
