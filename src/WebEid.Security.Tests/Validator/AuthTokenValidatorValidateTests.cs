namespace WebEid.Security.Tests.Validator
{
    using System;
    using Exceptions;
    using Microsoft.QualityTools.Testing.Fakes;
    using NUnit.Framework;
    using TestUtils;

    [TestFixture]
    public class AuthTokenValidatorValidateTests : AbstractTestWithValidatorAndCorrectNonce
    {
        [Test]
        public void CertificateIsNotValidYet()
        {
            using (ShimsContext.Create())
            {
                // Authentication token expires at 2020-04-14
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2018, 10, 17, 0, 0, 0, DateTimeKind.Utc);
#pragma warning disable CS0618 // is obsolete
                Assert.ThrowsAsync<CertificateNotYetValidException>(async () => await this.Validator.Validate(Tokens.SignedTest));
#pragma warning restore CS0618
            }
        }

        [Test]
        public void CertificateIsNoLongerValid()
        {
            using (ShimsContext.Create())
            {
                // Authentication token expires at 2020-04-14
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2023, 10, 19, 0, 0, 0, DateTimeKind.Utc);
#pragma warning disable CS0618 // is obsolete
                Assert.ThrowsAsync<CertificateExpiredException>(async () => await this.Validator.Validate(Tokens.SignedTest));
#pragma warning restore CS0618
            }
        }

        [Test]
        public void TokenTooShortThrowsExceptionWithMessage()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.TokenTooShort))
                .WithMessage("Auth token is null or too short");
#pragma warning restore CS0618
        }

        [Test]
        public void TokenTooLongThrowsExceptionWithMessage()
        {
#pragma warning disable CS0618 // is obsolete
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.TokenTooLong))
                .WithMessage("Auth token is too long");
#pragma warning restore CS0618
        }
    }
}
