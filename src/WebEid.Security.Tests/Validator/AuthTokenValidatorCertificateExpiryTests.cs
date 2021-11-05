namespace WebEid.Security.Tests.Validator
{
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator;
    using TestUtils;

    public class AuthTokenValidatorCertificateExpiryTests : AbstractTestWithCache
    {
        private IAuthTokenValidator validator;

        [SetUp]
        protected override void SetUp()
        {
            base.SetUp();
            this.validator = AuthTokenValidators.GetAuthTokenValidatorWithOcspCheck(this.Cache);
        }

        [Test]
        public void TestTokenCertRsaExpired()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<CertificateExpiredException>(async () => await this.validator.Validate(Tokens.TokenCertRsaExipred));
#pragma warning restore CS0618
        }

        [Test]
        public void TestTokenCertEcdsaExpired()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<CertificateExpiredException>(async () => await this.validator.Validate(Tokens.TokenCertEcdsaExipred));
#pragma warning restore CS0618
        }
    }
}
