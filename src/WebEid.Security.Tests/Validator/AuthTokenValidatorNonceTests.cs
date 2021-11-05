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
#pragma warning disable CS0618 // is obsolete
                Assert.ThrowsAsync<NonceNotFoundException>(async () => await this.Validator.Validate(Tokens.SignedTest));
#pragma warning restore CS0618
            }
        }

        [Test]
        public void ValidateExpiredNonce()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
                this.PutExpiredNonceToCache();
#pragma warning disable CS0618 // is obsolete
                Assert.ThrowsAsync<NonceExpiredException>(async () => await this.Validator.Validate(Tokens.SignedTest));
#pragma warning restore CS0618
            }
        }

        [Test]
        public void MissingNonceThrowsTokenParseException()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
#pragma warning disable CS0618 // is obsolete
                Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.NonceMissing))
                    .HasMessageStartingWith("nonce field must be present and not empty in authentication token body");
#pragma warning restore CS0618
            }
        }

        [Test]
        public void EmptyNonceThrowsTokenParseException()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
#pragma warning disable CS0618 // is obsolete
                Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.NonceEmpty))
                    .HasMessageStartingWith("nonce field must be present and not empty in authentication token body");
#pragma warning restore CS0618
            }
        }

        [Test]
        public void TokenNonceNotStringThrowsTokenParseException()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
#pragma warning disable CS0618 // is obsolete
                Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.NonceNotString))
                    .HasMessageStartingWith("nonce field type must be string in authentication token body");
#pragma warning restore CS0618
            }
        }

        [Test]
        public void TooShortNonceThrowsTokenParseException()
        {
            using (ShimsContext.Create())
            {
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 00, 00, DateTimeKind.Utc);
                this.PutTooShortNonceToCache();
#pragma warning disable CS0618 // is obsolete
                Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.NonceTooShort));
#pragma warning restore CS0618
            }
        }
    }
}
