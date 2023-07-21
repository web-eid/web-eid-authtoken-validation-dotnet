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
namespace WebEid.Security.Tests.Validator.Ocsp
{
    using System;
    using Exceptions;
    using NUnit.Framework;
    using Security.Validator.Ocsp;
    using TestUtils;

    [TestFixture]
    public class OcspResponseValidatorTests
    {
        [Test]
        public void WhenThisUpdateDayBeforeProducedAtThenThrows()
        {
            var thisUpdate = new DateTime(2021, 9, 1, 0, 0, 0, DateTimeKind.Utc);
            var producedAt = new DateTime(2021, 9, 2, 0, 0, 0, DateTimeKind.Utc);
            Assert.Throws<UserCertificateOcspCheckFailedException>(() =>
                    OcspResponseValidator.ValidateCertificateStatusUpdateTime(thisUpdate, null, producedAt))
                .WithMessage("User certificate revocation check has failed: "
                             + "Certificate status update time check failed: "
                             + "notAllowedBefore: 2021-09-01 23:45:00 +00:00, "
                             + "notAllowedAfter: 2021-09-02 00:15:00 +00:00, "
                             + "thisUpdate: 2021-09-01 00:00:00 +00:00, "
                             + "nextUpdate: null");
        }
        [Test]
        public void WhenThisUpdateDayAfterProducedAtThenThrows()
        {
            var thisUpdate = new DateTime(2021, 9, 2, 0, 0, 0, DateTimeKind.Utc);
            var producedAt = new DateTime(2021, 9, 1, 0, 0, 0, DateTimeKind.Utc);
            Assert.Throws<UserCertificateOcspCheckFailedException>(() =>
                    OcspResponseValidator.ValidateCertificateStatusUpdateTime(thisUpdate, null, producedAt))
                .WithMessage("User certificate revocation check has failed: "
                             + "Certificate status update time check failed: "
                             + "notAllowedBefore: 2021-08-31 23:45:00 +00:00, "
                             + "notAllowedAfter: 2021-09-01 00:15:00 +00:00, "
                             + "thisUpdate: 2021-09-02 00:00:00 +00:00, "
                             + "nextUpdate: null");
        }

        [Test]
        public void WhenNextUpdateDayBeforeProducedAtThenThrows()
        {
            var thisUpdate = new DateTime(2021, 9, 2, 0, 0, 0, DateTimeKind.Utc);
            var nextUpdate = new DateTime(2021, 9, 1, 0, 0, 0, DateTimeKind.Utc);
            var producedAt = new DateTime(2021, 9, 1, 0, 0, 0, DateTimeKind.Utc);
            Assert.Throws<UserCertificateOcspCheckFailedException>(() =>
                    OcspResponseValidator.ValidateCertificateStatusUpdateTime(thisUpdate, nextUpdate, producedAt))
                .WithMessage("User certificate revocation check has failed: "
                             + "Certificate status update time check failed: "
                             + "notAllowedBefore: 2021-08-31 23:45:00 +00:00, "
                             + "notAllowedAfter: 2021-09-01 00:15:00 +00:00, "
                             + "thisUpdate: 2021-09-02 00:00:00 +00:00, "
                             + "nextUpdate: 2021-09-01 00:00:00 +00:00");
        }
    }
}
