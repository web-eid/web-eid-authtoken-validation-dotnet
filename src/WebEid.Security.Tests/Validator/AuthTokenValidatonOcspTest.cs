/*
 * Copyright © 2020-2025 Estonian Information System Authority
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
    using System;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Util;

    public class AuthTokenValidatonOcspTest : AbstractTestWithValidator
    {
        private const string AuthToken = "{\"algorithm\":\"ES384\"," +
        "\"unverifiedCertificate\":\"MIIEBDCCA2WgAwIBAgIQY5OGshxoPMFg+Wfc0gFEaTAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTIxMDcyMjEyNDMwOFoXDTI2MDcwOTIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQmwEKsJTjaMHSaZj19hb9EJaJlwbKc5VFzmlGMFSJVk4dDy+eUxa5KOA7tWXqzcmhh5SYdv+MxcaQKlKWLMa36pfgv20FpEDb03GCtLqjLTRZ7649PugAQ5EmAqIic29CjggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFPlp/ceABC52itoqppEmbf71TJz6MGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgDCAgybz0u3W+tGI+AX+PiI5CrE9ptEHO5eezR1Jo4j7iGaO0i39xTGUB+NSC7P6AQbyE/ywqJjA1a62jTLcS9GHAJCARxN4NO4eVdWU3zVohCXm8WN3DWA7XUcn9TZiLGQ29P4xfQZOXJi/z4PNRRsR4plvSNB3dfyBvZn31HhC7my8woi\"," +
        "\"appVersion\":\"https://web-eid.eu/web-eid-app/releases/2.5.0+0\"," +
        "\"signature\":\"0Ov7ME6pTY1K2GXMj8Wxov/o2fGIMEds8OMY5dKdkB0nrqQX7fG1E5mnsbvyHpMDecMUH6Yg+p1HXdgB/lLqOcFZjt/OVXPjAAApC5d1YgRYATDcxsR1zqQwiNcHdmWn\"," +
        "\"format\":\"web-eid:1.0\"}";

        [Test]
        public void WhenOcspRequestTimeoutIsReachedThenValidationFails()
        {
            using var _ = DateTimeProvider.OverrideUtcNow(new DateTime(2026, 02, 03));
            var authTokenValidator = AuthTokenValidators
                .GetDefaultAuthTokenValidatorBuilder()
               .WithOcspRequestTimeout(TimeSpan.FromMilliseconds(1))
                .Build();

            var exception = Assert.ThrowsAsync<UserCertificateOcspCheckFailedException>(() => authTokenValidator.Validate(authTokenValidator.Parse(AuthToken), ValidChallengeNonce));
            Assert.That(exception.InnerException, Is.TypeOf<TaskCanceledException>());
            Assert.That(exception.InnerException.Message, Does.Contain("The request was canceled due to the configured HttpClient.Timeout of"));

        }

        [Test]
        public async Task WhenCertificateIsNotRevokedThenOcspCheckIsSuccessful()
        {
            using var _ = DateTimeProvider.OverrideUtcNow(new DateTime(2026, 02, 03));
            var authTokenValidator = AuthTokenValidators
                .GetDefaultAuthTokenValidatorBuilder()
                .WithAllowedOcspResponseTimeSkew(TimeSpan.FromDays(365 * 20))
                .Build();

            var certificate = await authTokenValidator.Validate(authTokenValidator.Parse(AuthToken), ValidChallengeNonce);
            Assert.That(certificate, Is.Not.Null);
        }
    }
}
