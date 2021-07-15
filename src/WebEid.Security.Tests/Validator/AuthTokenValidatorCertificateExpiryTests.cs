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
            Assert.ThrowsAsync<CertificateExpiredException>(async () => await this.validator.Validate(Tokens.TokenCertRsaExipred));
        }

        [Test]
        public void TestTokenCertEcdsaExpired()
        {
            Assert.ThrowsAsync<CertificateExpiredException>(async () => await this.validator.Validate(Tokens.TokenCertEcdsaExipred));
        }
    }
}
