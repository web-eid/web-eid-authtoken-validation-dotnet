// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Tests.Validator.VersionValidators
{
    using Exceptions;
    using Moq;
    using NUnit.Framework;
    using WebEid.Security.Validator.VersionValidators;

    public class AuthTokenVersionValidatorFactoryTest
    {
        [Test]
        public void WhenValidatorSupportsFormatThenSupportsReturnsTrue()
        {
            var v11 = new Mock<IAuthTokenVersionValidator>();
            v11.Setup(v => v.Supports("web-eid:1.1")).Returns(true);

            var factory = new AuthTokenVersionValidatorFactory(
                [v11.Object]
            );

            Assert.That(factory.Supports("web-eid:1.1"), Is.True);
        }

        [Test]
        public void WhenValidatorDoesNotSupportFormatThenSupportsReturnsFalse()
        {
            var v11 = new Mock<IAuthTokenVersionValidator>();
            v11.Setup(v => v.Supports("web-eid:1.1")).Returns(false);

            var factory = new AuthTokenVersionValidatorFactory(
                [v11.Object]
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
            var factory = new AuthTokenVersionValidatorFactory([]);

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
                [v11.Object, v1.Object]
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
                [v11.Object, v1.Object]
            );

            var chosen = factory.GetValidatorFor("web-eid:1");

            Assert.That(chosen, Is.SameAs(v1.Object));
        }
    }
}
