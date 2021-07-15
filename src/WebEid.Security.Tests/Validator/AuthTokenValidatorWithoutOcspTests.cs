namespace WebEid.Security.Tests.Validator
{
    using System.Threading.Tasks;
    using Exceptions;
    using NUnit.Framework;
    using Security.Util;
    using Security.Validator;
    using TestUtils;
    using Util;

    [TestFixture]
    public class AuthTokenValidatorParseTests : AbstractTestWithMockedDate
    {
        private IAuthTokenValidator validator;

        [SetUp]
        protected override void SetUp()
        {
            base.SetUp();
            this.validator = AuthTokenValidators.GetAuthTokenValidator(this.Cache);
        }

        [Test]
        public async Task ParseSignedToken()
        {
            this.PutCorrectNonceToCache();
            var certificate = await this.validator.Validate(Tokens.SignedTest);
            Assert.AreEqual("JÕEORG,JAAK-KRISTJAN,38001085718", certificate.GetSubjectCn());
            Assert.AreEqual("Jaak-Kristjan", certificate.GetSubjectGivenName().ToTitleCase());
            Assert.AreEqual("Jõeorg", certificate.GetSubjectSurname().ToTitleCase());
            Assert.AreEqual("PNOEE-38001085718", certificate.GetSubjectIdCode());
            Assert.AreEqual("EE", certificate.GetSubjectCountryCode());
        }

        [Test]
        public void DetectUnsignedToken()
        {
            Assert.ThrowsAsync<TokenSignatureValidationException>(async () =>
                await this.validator.Validate(Tokens.GetUnsignedTokenString()));
        }

        [Test]
        public void DetectCorruptedToken()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.validator.Validate(Tokens.Corrupted));
        }
    }
}
