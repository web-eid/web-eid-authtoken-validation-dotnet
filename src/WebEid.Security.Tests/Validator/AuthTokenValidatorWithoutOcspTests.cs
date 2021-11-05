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
#pragma warning disable CS0618 // is obsolete
            var certificate = await this.validator.Validate(Tokens.SignedTest);
#pragma warning restore CS0618
            Assert.AreEqual("JÕEORG,JAAK-KRISTJAN,38001085718", certificate.GetSubjectCn());
            Assert.AreEqual("Jaak-Kristjan", certificate.GetSubjectGivenName().ToTitleCase());
            Assert.AreEqual("Jõeorg", certificate.GetSubjectSurname().ToTitleCase());
            Assert.AreEqual("PNOEE-38001085718", certificate.GetSubjectIdCode());
            Assert.AreEqual("EE", certificate.GetSubjectCountryCode());
        }

        [Test]
        public void DetectUnsignedToken()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenSignatureValidationException>(async () =>
                await this.validator.Validate(Tokens.GetUnsignedTokenString()));
#pragma warning restore CS0618
        }

        [Test]
        public void DetectCorruptedToken()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.validator.Validate(Tokens.Corrupted));
#pragma warning restore CS0618
        }
    }
}
