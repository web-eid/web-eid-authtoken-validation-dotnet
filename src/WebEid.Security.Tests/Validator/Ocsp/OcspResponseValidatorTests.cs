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
