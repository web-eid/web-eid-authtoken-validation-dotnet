namespace WebEid.Security.Tests.Validator
{
    using System;
    using Exceptions;
    using Microsoft.QualityTools.Testing.Fakes;
    using NUnit.Framework;
    using TestUtils;

    public class AuthTokenValidatorClockSkewTests : AbstractTestWithValidatorAndCorrectNonce
    {

        [Test]
        public void BlockLargeClockSkew4Min()
        {
            using (ShimsContext.Create())
            {
                // Authentication token expires at 2020-04-14 13:32:49
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 36, 49, DateTimeKind.Utc);
                Assert.ThrowsAsync<TokenExpiredException>(async () => await this.Validator.Validate(Tokens.SignedTest));
            }
        }

        [Test]
        public void AllowSmallClockSkew2Min()
        {
            using (ShimsContext.Create())
            {
                // Authentication token expires at 2020-04-14 13:32:49
                System.Fakes.ShimDateTime.UtcNowGet = () => new DateTime(2020, 4, 14, 13, 30, 49, DateTimeKind.Utc);
                Assert.DoesNotThrowAsync(async () => await this.Validator.Validate(Tokens.SignedTest));
            }
        }
    }
}
