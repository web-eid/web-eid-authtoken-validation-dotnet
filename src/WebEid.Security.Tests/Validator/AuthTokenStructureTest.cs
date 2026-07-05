// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Tests.Validator
{
    using NUnit.Framework;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Tests.TestUtils;

    public class AuthTokenStructureTest : AbstractTestWithValidator
    {
        [Test]
        public void WhenNullTokenThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => Validator.Parse(null))
                .WithMessage("Auth token is null or too short");

        [Test]
        public void WhenNullStrTokenThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => Validator.Parse("null"))
                .WithMessage("Auth token is null or too short");

        [Test]
        public void WhenTokenTooShortThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => Validator.Parse(new string(new char[99])))
                .WithMessage("Auth token is null or too short");

        [Test]
        public void WhenTokenTooLongThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => Validator.Parse(new string(new char[65537])))
                .WithMessage("Auth token is too long");

        [TestCase(10001)]
        [TestCase(65536)]
        public void WhenTokenIsWithinIncreasedLengthLimitThenParsingSucceeds(int tokenLength)
        {
            var token = ValidAuthTokenStr + new string(' ', tokenLength - ValidAuthTokenStr.Length);

            Assert.That(Validator.Parse(token).Format, Is.EqualTo("web-eid:1"));
        }

        [Test]
        public void WhenUnknownTokenVersionThenParsingFailsAsync()
        {
            var authToken = ReplaceTokenField(ValidAuthTokenStr, "web-eid:1", "invalid");
            Assert.ThrowsAsync<AuthTokenParseException>(() => Validator.Validate(authToken, ""))
                .WithMessage("Token format version 'invalid' is currently not supported");
        }
    }
}
