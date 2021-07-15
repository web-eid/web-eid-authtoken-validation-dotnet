namespace WebEid.Security.Tests.Validator.Validators
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
            var validator = new OriginValidator(new Uri("https://origin"), new Logger());
            Assert.DoesNotThrow(() =>
                validator.Validate(
                    new AuthTokenValidatorData(new X509Certificate()) { Origin = "https://origin", Nonce = "", SiteCertificateFingerprint = "" }));
        }

        [Test]
        public void InvalidOriginUriThrowsOriginMismatchException()
        {
            var validator = new OriginValidator(new Uri("https://origin"), new Logger());
            Assert.Throws<OriginMismatchException>(() =>
                    validator.Validate(
                        new AuthTokenValidatorData(new X509Certificate()) { Origin = "https://invalid-origin" }))
                .WithMessage("Origin from the token does not match the configured origin");
        }

        [Test]
        public void TokenOriginNotUriThrowsOriginMismatchException()
        {
            Assert.Throws<OriginMismatchException>(() =>
                new OriginValidator(new Uri("https://origin/test"), new Logger()).Validate(
                    new AuthTokenValidatorData(new X509Certificate()) { Origin = "not-url" }));
        }
    }
}
