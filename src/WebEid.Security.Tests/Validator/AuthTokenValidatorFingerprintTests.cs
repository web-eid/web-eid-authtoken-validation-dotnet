namespace WebEid.Security.Tests.Validator
{
    using Exceptions;
    using NUnit.Framework;
    using TestUtils;

    [TestFixture]
    public class AuthTokenValidatorFingerprintTests : AbstractTestWithMockedDateAndCorrectNonce
    {

        [Test]
        public void ValidateFingerprint()
        {
            var validator = AuthTokenValidators.GetAuthTokenValidator(this.Cache,
                "urn:cert:sha-256:6f0df244e4a856b94b3b3b47582a0a51a32d674dbc7107211ed23d4bec6d9c72");
#pragma warning disable CS0618 // is obsolete
            Assert.DoesNotThrow(() => validator.Validate(Tokens.SignedTest));
#pragma warning restore CS0618
        }

        [Test]

        public void ValidateInvalidFingerprint()
        {
            var validator = AuthTokenValidators.GetAuthTokenValidator(this.Cache,
                "abcde6f0df244e4a856b94b3b3b47582a0a51a32d674dbc7107211ed23d4bec6d9c72");
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<SiteCertificateFingerprintValidationException>(async () =>
                await validator.Validate(Tokens.SignedTest));
#pragma warning restore CS0618
        }

        [Test]
        public void TestMismatchingSiteCertificateFingerprint()
        {
            var validator = AuthTokenValidators.GetAuthTokenValidator(this.Cache,
                "urn:cert:sha-256:6f0df244e4a856b94b3b3b47582a0a51a32d674dbc7107211ed23d4bec6d9c72");
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<SiteCertificateFingerprintValidationException>(async () =>
                await validator.Validate(Tokens.MismatchingSiteCertificateFingerprint));
#pragma warning restore CS0618
        }
    }
}
