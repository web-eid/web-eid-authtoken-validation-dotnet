// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Tests.Validator.Ocsp
{
    using System;
    using NUnit.Framework;
    using Org.BouncyCastle.Ocsp;
    using Security.Validator.Ocsp;
    using WebEid.Security.Validator;
    using Org.BouncyCastle.Asn1.Ocsp;
    using System.Globalization;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Util;

    [TestFixture]
    public class OcspResponseValidatorTests
    {
        private static TimeSpan timeSkew;
        private static TimeSpan maxThisUpdateAge;

        [SetUp]
        public void SetUp()
        {
            var configuration = new AuthTokenValidationConfiguration();
            timeSkew = configuration.AllowedOcspResponseTimeSkew;
            maxThisUpdateAge = configuration.MaxOcspResponseThisUpdateAge;
        }

        [Test]
        public void WhenThisAndNextUpdateWithinSkewThenValidationSucceeds()
        {
            var now = DateTimeProvider.UtcNow;
            var thisUpdateWithinAgeLimit = GetThisUpdateWithinAgeLimit(now);
            var nextUpdateWithinAgeLimit = now.Subtract(maxThisUpdateAge.Subtract(TimeSpan.FromSeconds(2)));

            var mockedResponse = new SingleResp(new SingleResponse(null, null, thisUpdateWithinAgeLimit.ToDerGenTime(), nextUpdateWithinAgeLimit.ToDerGenTime(), null));

            Assert.DoesNotThrow(() =>
                OcspResponseValidator.ValidateCertificateStatusUpdateTime(mockedResponse, timeSkew, maxThisUpdateAge));
        }

        [Test]
        public void WhenNextUpdateBeforeThisUpdateThenThrows()
        {
            var now = DateTimeProvider.UtcNow;
            var thisUpdateWithinAgeLimit = GetThisUpdateWithinAgeLimit(now);
            var beforeThisUpdate = thisUpdateWithinAgeLimit.Subtract(TimeSpan.FromSeconds(1));

            var mockedResponse = new SingleResp(new SingleResponse(null, null, thisUpdateWithinAgeLimit.ToDerGenTime(), beforeThisUpdate.ToDerGenTime(), null));

            Assert.Throws<UserCertificateOcspCheckFailedException>(() =>
                OcspResponseValidator.ValidateCertificateStatusUpdateTime(mockedResponse, timeSkew, maxThisUpdateAge))
                    .HasMessageStartingWith("User certificate revocation check has failed: "
                    + "Certificate status update time check failed: "
                    + $"nextUpdate {beforeThisUpdate.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)} is before thisUpdate {thisUpdateWithinAgeLimit.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)}");
        }

        [Test]
        public void WhenThisUpdateHalfHourBeforeNowThenThrows()
        {
            var now = DateTimeProvider.UtcNow;
            var halfHourBeforeNow = now.Subtract(TimeSpan.FromMinutes(30));
            var mockedResponse = new SingleResp(new SingleResponse(null, null, halfHourBeforeNow.ToDerGenTime(), null, null));

            Assert.Throws<UserCertificateOcspCheckFailedException>(() =>
                OcspResponseValidator.ValidateCertificateStatusUpdateTime(mockedResponse, timeSkew, maxThisUpdateAge))
                    .HasMessageStartingWith("User certificate revocation check has failed: "
                    + "Certificate status update time check failed: "
                    + $"thisUpdate {halfHourBeforeNow.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)} is too old, minimum time allowed: ");
        }

        [Test]
        public void WhenThisUpdateHalfHourAfterNowThenThrows()
        {
            var now = DateTimeProvider.UtcNow;
            var halfHourAfterNow = now.Add(TimeSpan.FromMinutes(30));
            var mockedResponse = new SingleResp(new SingleResponse(null, null, halfHourAfterNow.ToDerGenTime(), null, null));

            Assert.Throws<UserCertificateOcspCheckFailedException>(() =>
                OcspResponseValidator.ValidateCertificateStatusUpdateTime(mockedResponse, timeSkew, maxThisUpdateAge))
                    .HasMessageStartingWith("User certificate revocation check has failed: "
                    + "Certificate status update time check failed: "
                    + $"thisUpdate {halfHourAfterNow.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)} is too far in the future, latest allowed: ");
        }

        [Test]
        public void WhenNextUpdateHalfHourBeforeNowThenThrows()
        {
            var now = DateTimeProvider.UtcNow;
            var thisUpdateWithinAgeLimit = GetThisUpdateWithinAgeLimit(now);
            var halfHourBeforeNow = now.Subtract(TimeSpan.FromMinutes(30));
            var mockedResponse = new SingleResp(new SingleResponse(null, null, thisUpdateWithinAgeLimit.ToDerGenTime(), halfHourBeforeNow.ToDerGenTime(), null));

            Assert.Throws<UserCertificateOcspCheckFailedException>(() =>
                OcspResponseValidator.ValidateCertificateStatusUpdateTime(mockedResponse, timeSkew, maxThisUpdateAge))
                    .HasMessageStartingWith("User certificate revocation check has failed: "
                    + "Certificate status update time check failed: "
                    + $"nextUpdate {halfHourBeforeNow.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)} is in the past");
        }

        private static DateTime GetThisUpdateWithinAgeLimit(DateTime now)
        {
            var maxThisUpdateAgeMinusOne = maxThisUpdateAge.Subtract(TimeSpan.FromSeconds(1));
            return now.Subtract(maxThisUpdateAgeMinusOne);
        }
    }
}
