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
                Assert.ThrowsAsync<CertificateNotYetValidException>(async () => await this.Validator.Validate(Tokens.SignedTest));
            }
        }

        [Test]
        public void CertificateIsNoLongerValid()
        {
            using (ShimsContext.Create())
            {
                // Authentication token expires at 2020-04-14
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2023, 10, 19, 0, 0, 0, DateTimeKind.Utc);
                Assert.ThrowsAsync<CertificateExpiredException>(async () => await this.Validator.Validate(Tokens.SignedTest));
            }
        }

        [Test]
        public void TokenTooShortThrowsExceptionWithMessage()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.TokenTooShort))
                .WithMessage("Auth token is null or too short");
        }

        [Test]
        public void TokenTooLongThrowsExceptionWithMessage()
        {
            Assert.ThrowsAsync<TokenParseException>(async () => await this.Validator.Validate(Tokens.TokenTooLong))
                .WithMessage("Auth token is too long");
        }
    }
}
