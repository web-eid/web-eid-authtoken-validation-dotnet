/*
 * Copyright © 2020-2024 Estonian Information System Authority
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
