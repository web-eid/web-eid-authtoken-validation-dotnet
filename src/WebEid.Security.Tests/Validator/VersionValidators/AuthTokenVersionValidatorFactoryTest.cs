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
namespace WebEid.Security.Tests.Validator.VersionValidators
{
    using System.Collections.Generic;
    using NUnit.Framework;
    using Moq;
    using Exceptions;
    using WebEid.Security.Validator.VersionValidators;

    public class AuthTokenVersionValidatorFactoryTest
    {
        [Test]
        public void WhenValidatorSupportsFormatThenSupportsReturnsTrue()
        {
            var v11 = new Mock<IAuthTokenVersionValidator>();
            v11.Setup(v => v.Supports("web-eid:1.1")).Returns(true);

            var factory = new AuthTokenVersionValidatorFactory(
                new List<IAuthTokenVersionValidator> { v11.Object }
            );

            Assert.That(factory.Supports("web-eid:1.1"), Is.True);
        }

        [Test]
        public void WhenValidatorDoesNotSupportFormatThenSupportsReturnsFalse()
        {
            var v11 = new Mock<IAuthTokenVersionValidator>();
            v11.Setup(v => v.Supports("web-eid:1.1")).Returns(false);

            var factory = new AuthTokenVersionValidatorFactory(
                new List<IAuthTokenVersionValidator> { v11.Object }
            );

            Assert.That(factory.Supports("web-eid:2"), Is.False);
        }

        [TestCase("web-eid:0.9")]
        [TestCase("web-eid:2")]
        [TestCase("foo")]
        [TestCase("1")]
        [TestCase("web-eid")]
        public void WhenUnsupportedFormatThenGetValidatorForThrows(string format)
        {
            var factory = new AuthTokenVersionValidatorFactory(new List<IAuthTokenVersionValidator>());

            Assert.Throws<AuthTokenParseException>(() =>
                factory.GetValidatorFor(format)
            );
        }

        [Test]
        public void WhenMultipleValidatorsAndFirstIsV11ThenGetValidatorForReturnsV11()
        {
            var v11 = new Mock<IAuthTokenVersionValidator>();
            v11.Setup(v => v.Supports("web-eid:1.1")).Returns(true);

            var v1 = new Mock<IAuthTokenVersionValidator>();
            v1.Setup(v => v.Supports("web-eid:1")).Returns(true);

            var factory = new AuthTokenVersionValidatorFactory(
                new List<IAuthTokenVersionValidator> { v11.Object, v1.Object }
            );

            var chosen = factory.GetValidatorFor("web-eid:1.1");

            Assert.That(chosen, Is.SameAs(v11.Object));
        }

        [Test]
        public void WhenFormatIsBaseV1ThenGetValidatorForReturnsV1()
        {
            var v11 = new Mock<IAuthTokenVersionValidator>();
            v11.Setup(v => v.Supports("web-eid:1.1")).Returns(true);

            var v1 = new Mock<IAuthTokenVersionValidator>();
            v1.Setup(v => v.Supports("web-eid:1")).Returns(true);

            var factory = new AuthTokenVersionValidatorFactory(
                new List<IAuthTokenVersionValidator> { v11.Object, v1.Object }
            );

            var chosen = factory.GetValidatorFor("web-eid:1");

            Assert.That(chosen, Is.SameAs(v1.Object));
        }
    }
}
