// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Tests.Validator.VersionValidators
{
    using NUnit.Framework;
    using WebEid.Security.Validator.VersionValidators;

    public class AuthTokenVersionTest
    {
        [TestCase("web-eid:1", 1, 0, true)]
        [TestCase("web-eid:1.0", 1, 0, true)]
        [TestCase("web-eid:1.1", 1, 0, true)]
        [TestCase("web-eid:1.1", 1, 1, true)]
        [TestCase("web-eid:1.999", 1, 1, true)]
        [TestCase("web-eid:2.0", 2, 0, true)]
        [TestCase("web-eid:2.3", 2, 1, true)]
        [TestCase("web-eid:1.0", 1, 1, false)]
        [TestCase("web-eid:1", 1, 1, false)]
        [TestCase("web-eid:2", 1, 0, false)]
        [TestCase("web-eid:1.5", 2, 0, false)]
        [TestCase("web-eid:1.00", 1, 0, false)]
        [TestCase("web-eid:1.000", 1, 0, false)]
        [TestCase("web-eid:01", 1, 0, false)]
        [TestCase("web-eid:1.", 1, 0, false)]
        [TestCase("web-eid:1.1.0", 1, 0, false)]
        [TestCase("web-eid:0.9", 1, 0, false)]
        [TestCase("webauthn:1", 1, 0, false)]
        public void WhenFormatMatchesRequiredMajorAndAtLeastRequiredMinorThenSupportsReturnsExpected(
            string format, int requiredMajorVersion, int requiredMinorVersion, bool expected) =>
            Assert.That(
                AuthTokenVersion.Supports(format, requiredMajorVersion, requiredMinorVersion),
                Is.EqualTo(expected));

        [Test]
        public void WhenFormatIsNullThenSupportsReturnsFalse() =>
            Assert.That(AuthTokenVersion.Supports(null, 1, 0), Is.False);

        [TestCase("web-eid:1", 1, 0, true)]
        [TestCase("web-eid:1.0", 1, 0, true)]
        [TestCase("web-eid:1.1", 1, 1, true)]
        [TestCase("web-eid:2.0", 2, 0, true)]
        [TestCase("web-eid:1.1", 1, 0, false)]
        [TestCase("web-eid:1.2", 1, 1, false)]
        [TestCase("web-eid:1.0", 1, 1, false)]
        [TestCase("web-eid:1", 2, 0, false)]
        [TestCase("web-eid:1.00", 1, 0, false)]
        [TestCase("web-eid:01", 1, 0, false)]
        [TestCase("webauthn:1", 1, 0, false)]
        public void WhenFormatMatchesRequiredMajorAndExactMinorThenSupportsExactlyReturnsExpected(
            string format, int requiredMajorVersion, int requiredMinorVersion, bool expected) =>
            Assert.That(
                AuthTokenVersion.SupportsExactly(format, requiredMajorVersion, requiredMinorVersion),
                Is.EqualTo(expected));

        [Test]
        public void WhenFormatIsNullThenSupportsExactlyReturnsFalse() =>
            Assert.That(AuthTokenVersion.SupportsExactly(null, 1, 0), Is.False);
    }
}
