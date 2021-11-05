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
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<OriginMismatchException>(async () => await this.Validator.Validate(Tokens.SignedTest));
#pragma warning restore CS0618
        }

        [Test]
        public void TestOriginMissing()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.OriginMissing))
                .HasMessageStartingWith("aud field must be present in authentication token body and must be an array");
#pragma warning restore CS0618
        }

        [Test]
        public void TestOriginEmpty()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.OriginEmpty))
                .HasMessageStartingWith("origin from aud field must not be empty");
#pragma warning restore CS0618
        }

        [Test]
        public void TestOriginNotString()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<OriginMismatchException>(async () => await this.Validator.Validate(Tokens.OriginNotString));
#pragma warning restore CS0618
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
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<OriginMismatchException>(async () => await this.Validator.Validate(Tokens.OriginNotUrl));
#pragma warning restore CS0618
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
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<OriginMismatchException>(async () => await validator.Validate(Tokens.OriginUrlWithExcessiveElements));
#pragma warning restore CS0618
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
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<OriginMismatchException>(async () => await validator.Validate(Tokens.OriginValidUrlNotHttps));
#pragma warning restore CS0618
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
