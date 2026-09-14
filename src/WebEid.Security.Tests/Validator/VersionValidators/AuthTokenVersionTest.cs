/*
 * Copyright © 2025-2025 Estonian Information System Authority
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
