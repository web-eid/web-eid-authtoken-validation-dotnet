namespace WebEid.Security.Tests.Validator
{
    using NUnit.Framework;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Tests.TestUtils;

    public class AuthTokenStructureTest : AbstractTestWithValidator
    {
        [Test]
        public void WhenNullTokenThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => this.Validator.Parse(null))
                .WithMessage("Auth token is null or too short");

        [Test]
        public void WhenNullStrTokenThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => this.Validator.Parse("null"))
                .WithMessage("Auth token is null or too short");

        [Test]
        public void WhenTokenTooShortThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => this.Validator.Parse(new string(new char[99])))
                .WithMessage("Auth token is null or too short");

        [Test]
        public void WhenTokenTooLongThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => this.Validator.Parse(new string(new char[10001])))
                .WithMessage("Auth token is too long");

        [Test]
        public void WhenUnknownTokenVersionThenParsingFailsAsync()
        {
            var authToken = this.ReplaceTokenField(ValidAuthTokenStr, "web-eid:1", "invalid");
            Assert.ThrowsAsync<AuthTokenParseException>(() => this.Validator.Validate(authToken, ""))
                .WithMessage("Only token format version 'web-eid:1' is currently supported");
        }
    }
}
