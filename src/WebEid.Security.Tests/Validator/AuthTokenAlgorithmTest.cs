namespace WebEid.Security.Tests.Validator
{
    using NUnit.Framework;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Tests.TestUtils;

    public class AuthTokenAlgorithmTest : AbstractTestWithValidator
    {
        [Test]
        public void WhenAlgorithmNoneThenValidationFailsAsync()
        {
            var authToken = this.ReplaceTokenField(ValidAuthTokenStr, "ES384", "NONE");
            Assert.ThrowsAsync<AuthTokenParseException>(() => this.Validator.Validate(authToken, ValidChallengeNonce))
                .WithMessage("Unsupported signature algorithm");
        }

        [Test]
        public void WhenAlgorithmEmptyThenParsingFailsAsync()
        {
            var authToken = this.ReplaceTokenField(ValidAuthTokenStr, "ES384", "");
            Assert.ThrowsAsync<AuthTokenParseException>(() => this.Validator.Validate(authToken, ValidChallengeNonce))
                .WithMessage("'algorithm' is null or empty");
        }

        [Test]
        public void WhenAlgorithmInvalidThenParsingFailsAsync()
        {
            var authToken = this.ReplaceTokenField(ValidAuthTokenStr, "ES384", "\u0000\t\ninvalid");
            Assert.ThrowsAsync<AuthTokenParseException>(() => this.Validator.Validate(authToken, ValidChallengeNonce))
                .WithMessage("Unsupported signature algorithm");
        }
    }
}
