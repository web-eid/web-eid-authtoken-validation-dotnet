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
    using Exceptions;
    using TestUtils;

    public class AuthTokenAlgorithmTest : AbstractTestWithValidator
    {
        [Test]
        public void WhenAlgorithmNoneThenValidationFailsAsync()
        {
            var authToken = ReplaceTokenField(ValidAuthTokenStr, "ES384", "NONE");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(authToken, ValidChallengeNonce))
                .WithMessage("Unsupported signature algorithm");
        }

        [Test]
        public void WhenAlgorithmEmptyThenParsingFailsAsync()
        {
            var authToken = ReplaceTokenField(ValidAuthTokenStr, "ES384", "");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(authToken, ValidChallengeNonce))
                .WithMessage("'algorithm' is null or empty");
        }

        [Test]
        public void WhenAlgorithmInvalidThenParsingFailsAsync()
        {
            var authToken = ReplaceTokenField(ValidAuthTokenStr, "ES384", "\u0000\t\ninvalid");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(authToken, ValidChallengeNonce))
                .WithMessage("Unsupported signature algorithm");
        }

        [Test]
        public void WhenV11TokenMissingSupportedAlgorithmsThenValidationFailsAsync()
        {
            var tokenJson = RemoveJsonField(ValidV11AuthTokenStr, "supportedSignatureAlgorithms");
            var token = Validator.Parse(tokenJson);

            var ex = Assert.ThrowsAsync<AuthTokenParseException>(() =>
                Validator.Validate(token, ValidChallengeNonce));

            Assert.That(ex.Message, Does.Contain("'supportedSignatureAlgorithms' field is missing"));
        }

        [Test]
        public void WhenV11TokenHasInvalidCryptoAlgorithmThenValidationFailsAsync()
        {
            var token = ReplaceTokenField(ValidV11AuthTokenStr, "\"cryptoAlgorithm\":\"RSA\"", "\"cryptoAlgorithm\":\"INVALID\"");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce))
                .WithMessage("Unsupported signature algorithm");
        }

        [Test]
        public void WhenV11TokenHasInvalidHashFunctionThenValidationFailsAsync()
        {
            var token = ReplaceTokenField( ValidV11AuthTokenStr, "\"hashFunction\":\"SHA-256\"", "\"hashFunction\":\"NOT_A_HASH\"");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce))
                .WithMessage("Unsupported signature algorithm");
        }

        [Test]
        public void WhenV11TokenHasInvalidPaddingSchemeThenValidationFailsAsync()
        {
            var token = ReplaceTokenField( ValidV11AuthTokenStr, "\"paddingScheme\":\"PKCS1.5\"", "\"paddingScheme\":\"BAD_PADDING\"");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce))
                .WithMessage("Unsupported signature algorithm");
        }

        [Test]
        public void WhenV11TokenHasEmptySupportedAlgorithmsThenValidationFailsAsync()
        {
            var token = ReplaceTokenField( ValidV11AuthTokenStr, "\"supportedSignatureAlgorithms\":[{\"cryptoAlgorithm\":\"RSA\",\"hashFunction\":\"SHA-256\",\"paddingScheme\":\"PKCS1.5\"}]", "\"supportedSignatureAlgorithms\":[]");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce))
                .WithMessage("'supportedSignatureAlgorithms' field is missing");
        }
    }
}
