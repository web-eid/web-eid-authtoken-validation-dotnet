namespace WebEID.Security.Tests.Validator.Validators
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using Security.Validator.Validators;
    using TestUtils;

    [TestFixture]
    public class OriginValidatorTests
    {
        [Test]
        public void ValidOriginUriDoesNotThrowException()
        {
            var validator = new OriginValidator(new Uri("https://origin"), null);
            Assert.DoesNotThrow(() =>
                validator.Validate(
                    new AuthTokenValidatorData(new X509Certificate()) { Origin = "https://origin", Nonce = "", SiteCertificateFingerprint = "" }));
        }

        [Test]
        public void InvalidOriginUriThrowsOriginMismatchException()
        {
            var validator = new OriginValidator(new Uri("https://origin"), null);
            Assert.Throws<OriginMismatchException>(() =>
                    validator.Validate(
                        new AuthTokenValidatorData(new X509Certificate()) { Origin = "https://invalid-origin" }))
                .WithMessage("Origin from the token does not match the configured origin");
        }

        [Test]
        public void InvalidOriginUriThrowsOriginMismatchException2()
        {
            var validator = new OriginValidator(new Uri("https://origin/test"), null);
            Assert.Throws<OriginMismatchException>(() =>
                    validator.Validate(
                        new AuthTokenValidatorData(new X509Certificate()) { Origin = "https://origin/test" }))
                .WithMessage("Origin from the token does not match the configured origin");
        }
    }
}
