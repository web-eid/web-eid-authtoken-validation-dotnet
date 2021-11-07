namespace WebEid.Security.Tests.Validator
{
    using System;
    using Exceptions;
    using Microsoft.QualityTools.Testing.Fakes;
    using NUnit.Framework;
    using TestUtils;

    [TestFixture]
    public class AuthTokenValidatorNonceTests : AbstractTestWithValidator
    {
        [Test]
        public void ValidateIncorrectNonce()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
                this.PutIncorrectNonceToCache();
                Assert.ThrowsAsync<NonceNotFoundException>(async () => await this.Validator.Validate(Tokens.SignedTest));
            }
        }

        [Test]
        public void ValidateExpiredNonce()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
                this.PutExpiredNonceToCache();
                Assert.ThrowsAsync<NonceExpiredException>(async () => await this.Validator.Validate(Tokens.SignedTest));
            }
        }

        [Test]
        public void MissingNonceThrowsTokenParseException()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
                Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.NonceMissing))
                    .HasMessageStartingWith("nonce field must be present and not empty in authentication token body");
            }
        }

        [Test]
        public void EmptyNonceThrowsTokenParseException()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
                Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.NonceEmpty))
                    .HasMessageStartingWith("nonce field must be present and not empty in authentication token body");
            }
        }

        [Test]
        public void TokenNonceNotStringThrowsTokenParseException()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
                Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.NonceNotString))
                    .HasMessageStartingWith("nonce field type must be string in authentication token body");
            }
        }

        [Test]
        public void TooShortNonceThrowsTokenParseException()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
                this.PutTooShortNonceToCache();
                Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.NonceTooShort));
            }
        }
    }
}
