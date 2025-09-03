/*
 * Copyright © 2020-2025 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
namespace WebEid.Security.Tests.Validator
{
    using System;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Util;

    public class AuthTokenValidatonOcspTest : AbstractTestWithValidator
    {

        [Test]
        public void WhenOcspRequestTimeoutIsReachedThenValidationFails()
        {
            using var _ = DateTimeProvider.OverrideUtcNow(new DateTime(2023, 10, 21));
            var authTokenValidator = AuthTokenValidators
                .GetDefaultAuthTokenValidatorBuilder()
               .WithOcspRequestTimeout(TimeSpan.FromMilliseconds(1))
                .Build();

            var exception = Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() => authTokenValidator.Validate(authTokenValidator.Parse(ValidAuthTokenStr), ValidChallengeNonce));
            Assert.That(exception.InnerException, Is.TypeOf<TaskCanceledException>());
            Assert.That(exception.InnerException.Message, Does.Match("The request was canceled due to the configured HttpClient.Timeout of 0,[0-9]* seconds elapsing."));

        }

        [Test]
        public async Task WhenCertificateIsNotRevokedThenOcspCheckIsSuccessful()
        {
            using var _ = DateTimeProvider.OverrideUtcNow(new DateTime(2023, 10, 21));
            var authTokenValidator = AuthTokenValidators
                .GetDefaultAuthTokenValidatorBuilder()
                .WithAllowedOcspResponseTimeSkew(TimeSpan.FromDays(365 * 20))
                .Build();

            var certificate = await authTokenValidator.Validate(authTokenValidator.Parse(ValidAuthTokenStr), ValidChallengeNonce);
            Assert.That(certificate, Is.Not.Null);
        }
    }
}
