/*
 * Copyright © 2020-2023 Estonian Information System Authority
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

    public class AuthTokenStructureTest : AbstractTestWithValidator
    {
        [Test]
        public void WhenNullTokenThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => this.Validator.Parse(null))
                .WithMessage("Auth token is null or too short");

        [Test]
        public void WhenNullStrTokenThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => this.Validator.Parse("null"))
                .WithMessage("Auth token is null or too short");

        [Test]
        public void WhenTokenTooShortThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => this.Validator.Parse(new string(new char[99])))
                .WithMessage("Auth token is null or too short");

        [Test]
        public void WhenTokenTooLongThenParsingFails() =>
            Assert.Throws<AuthTokenParseException>(() => this.Validator.Parse(new string(new char[10001])))
                .WithMessage("Auth token is too long");

        [Test]
        public void WhenUnknownTokenVersionThenParsingFailsAsync()
        {
            var authToken = this.ReplaceTokenField(ValidAuthTokenStr, "web-eid:1", "invalid");
            Assert.ThrowsAsync<AuthTokenParseException>(() => this.Validator.Validate(authToken, ""))
                .WithMessage("Only token format version 'web-eid:1' is currently supported");
        }
    }
}
