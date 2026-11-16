// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Tests.Validator
{
    using Exceptions;
    using NUnit.Framework;
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
        public void WhenAlgorithmInvalidThenParsingFails()
        {
            var authToken = ValidAuthTokenStr.Replace("\"ES384\"", "\"\u0000\t\ninvalid\"");

            Assert.Throws<AuthTokenParseException>(() => Validator.Parse(authToken))
                .WithMessage("Error parsing Web eID authentication token");
        }

        [Test]
        public void WhenV11TokenMissingSupportedAlgorithmsThenValidationFailsAsync()
        {
            var token = ReplaceTokenField(
                ValidV11AuthTokenStr,
                "\"supportedSignatureAlgorithms\":[{\"cryptoAlgorithm\":\"RSA\",\"hashFunction\":\"SHA-256\",\"paddingScheme\":\"PKCS1.5\"}]",
                "");

            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce))
                .WithMessage("'supportedSignatureAlgorithms' field is missing");
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
            var token = ReplaceTokenField(ValidV11AuthTokenStr, "\"hashFunction\":\"SHA-256\"", "\"hashFunction\":\"NOT_A_HASH\"");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce))
                .WithMessage("Unsupported signature algorithm");
        }

        [Test]
        public void WhenV11TokenHasInvalidPaddingSchemeThenValidationFailsAsync()
        {
            var token = ReplaceTokenField(ValidV11AuthTokenStr, "\"paddingScheme\":\"PKCS1.5\"", "\"paddingScheme\":\"BAD_PADDING\"");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce))
                .WithMessage("Unsupported signature algorithm");
        }

        [Test]
        public void WhenV11TokenHasEmptySupportedAlgorithmsThenValidationFailsAsync()
        {
            var token = ReplaceTokenField(ValidV11AuthTokenStr, "\"supportedSignatureAlgorithms\":[{\"cryptoAlgorithm\":\"RSA\",\"hashFunction\":\"SHA-256\",\"paddingScheme\":\"PKCS1.5\"}]", "\"supportedSignatureAlgorithms\":[]");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(token, ValidChallengeNonce))
                .WithMessage("'supportedSignatureAlgorithms' field is missing");
        }
    }
}
