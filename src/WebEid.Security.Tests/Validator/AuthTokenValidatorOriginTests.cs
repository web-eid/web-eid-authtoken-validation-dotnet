namespace WebEid.Security.Tests.Validator
{
    using System;
    using Exceptions;
    using NUnit.Framework;
    using TestUtils;

    [TestFixture]
    public class AuthTokenValidatorOriginTests : AbstractTestWithMockedDateValidatorAndCorrectNonce
    {
        [Test]
        public void ValidateOriginMismatchFailure()
        {
            this.Validator = AuthTokenValidators.GetAuthTokenValidator("https://mismatch.ee", this.Cache);
            Assert.ThrowsAsync<OriginMismatchException>(async () => await this.Validator.Validate(Tokens.SignedTest));
        }

        [Test]
        public void TestOriginMissing()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.OriginMissing))
                .HasMessageStartingWith("aud field must be present in authentication token body and must be an array");
        }

        [Test]
        public void TestOriginEmpty()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.OriginEmpty))
                .HasMessageStartingWith("origin from aud field must not be empty");
        }

        [Test]
        public void TestOriginNotString()
        {
            Assert.ThrowsAsync<OriginMismatchException>(async () => await this.Validator.Validate(Tokens.OriginNotString));
        }

        [Test]
        public void TestValidatorOriginNotUrl()
        {
            Assert.Throws<UriFormatException>(() =>
                AuthTokenValidators.GetAuthTokenValidator("not-url", this.Cache));
        }

        [Test]
        public void TestTokenOriginNotUrl()
        {
            Assert.ThrowsAsync<OriginMismatchException>(async () => await this.Validator.Validate(Tokens.OriginNotUrl));
        }

        [Test]
        public void TestValidatorOriginExcessiveElements()
        {
            Assert.Throws<ArgumentException>(() =>
                    AuthTokenValidators.GetAuthTokenValidator("https://ria.ee/excessive-element", this.Cache))
                .HasMessageStartingWith("Origin URI must only contain the HTTPS scheme, host and optional port component");
        }

        [Test]
        public void TestTokenOriginExcessiveElements()
        {
            var validator = AuthTokenValidators.GetAuthTokenValidator("https://ria.ee", this.Cache);
            Assert.ThrowsAsync<OriginMismatchException>(async () => await validator.Validate(Tokens.OriginUrlWithExcessiveElements));
        }

        [Test]
        public void TestValidatorOriginNotHttps()
        {
            Assert.Throws<ArgumentException>(() => AuthTokenValidators.GetAuthTokenValidator("http://ria.ee", this.Cache));
        }

        [Test]
        public void TestTokenOriginNotHttps()
        {
            var validator = AuthTokenValidators.GetAuthTokenValidator("https://ria.ee", this.Cache);
            Assert.ThrowsAsync<OriginMismatchException>(async () => await validator.Validate(Tokens.OriginValidUrlNotHttps));
        }

        [Test]
        public void TestValidatorOriginNotValidUrl()
        {
            Assert.Throws<UriFormatException>(() =>
                AuthTokenValidators.GetAuthTokenValidator("ria://ria.ee", this.Cache));
        }

        [Test]
        public void TestValidatorOriginNotValidSyntax()
        {
            Assert.Throws<UriFormatException>(() =>
                AuthTokenValidators.GetAuthTokenValidator("https:///ria.ee", this.Cache));
        }
    }
}
