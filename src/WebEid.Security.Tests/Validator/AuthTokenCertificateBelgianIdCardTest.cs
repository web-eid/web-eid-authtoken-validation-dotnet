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
namespace WebEid.Security.Tests.Validator
{
    using System;
    using NUnit.Framework;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Util;

    public class AuthTokenCertificateBelgianIdCardTest : AbstractTestWithValidator
    {
        private const string BelgianTestIdCardAuthTokenEcc = 
            "{" +
            "  \"action\": \"web-eid:authenticate-success\"," +
            "  \"algorithm\": \"ES384\"," +
            "  \"appVersion\": \"https://web-eid.eu/web-eid-app/releases/2.7.0+965\"," +
            "  \"format\": \"web-eid:1.0\"," +
            "  \"signature\": \"VWCxJ+NrWpNsLJwLbJ1IXuJkkrRsxhfZ1uVmaoY3gBMPrvULaLAp+A1VYGJ2QWobL9FvhMyEQpVlO99ytovux3pX75gHkf3Z0sBjtNqr/QS0ac+qI2hEccFnU0H7deO7\"," +
            "  \"unverifiedCertificate\": \"MIIDQDCCAsegAwIBAgIQEAAAAAAA8evx/gAAAAGKYTAKBggqhkjOPQQDAzAuMQswCQYDVQQGEwJCRTEfMB0GA1UEAwwWZUlEIFRFU1QgRUMgQ2l0aXplbiBDQTAeFw0yMDEwMjIyMjAwMDBaFw0zMDEwMjIyMjAwMDBaMHYxCzAJBgNVBAYTAkJFMScwJQYDVQQDDB5Ob3JhIFNwZWNpbWVuIChBdXRoZW50aWNhdGlvbikxETAPBgNVBAQMCFNwZWNpbWVuMRUwEwYDVQQqDAxOb3JhIEFuZ8OobGUxFDASBgNVBAUTCzAxMDUwMzk5ODY0MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPybypdwlvczyuKQtJ87s/RmB+hRFaP4BdtR/Sc8jfQTmKUYVn0KDYZPBllh928yMPxU7F+Za3FtFrAPCnDH75IquYsn0oc5olVO7Uas5gn61Y2EA5askyCljNVLA0Gquo4IBYDCCAVwwHwYDVR0jBBgwFoAU3bN/45oZjlnJEVYCLfX6nW/ehEswDgYDVR0PAQH/BAQDAgeAMEkGA1UdIARCMEAwPgYHYDgMAQECAjAzMDEGCCsGAQUFBwIBFiVodHRwOi8vZWlkZGV2Y2FyZHMuemV0ZXNjYXJkcy5iZS9jZXJ0MBMGA1UdJQQMMAoGCCsGAQUFBwMCMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9laWRkZXZjYXJkcy56ZXRlc2NhcmRzLmJlL2NybC9jaXRpemVuY2FFQy5jcmwwgYEGCCsGAQUFBwEBBHUwczA+BggrBgEFBQcwAoYyaHR0cDovL2VpZGRldmNhcmRzLnpldGVzY2FyZHMuYmUvY2VydC9yb290Y2FFQy5jcnQwMQYIKwYBBQUHMAGGJWh0dHA6Ly9laWRkZXZjYXJkcy56ZXRlc2NhcmRzLmJlOjg4ODgwCgYIKoZIzj0EAwMDZwAwZAIwE7uLOjrhXbid+tRKe/5wgE/R3rFVsE6HkpHJg+9+mqlBToLrLWvckmiPRmUot85BAjBNyxy48pVF+azJEnt0Z/hipToVhgJLlMkPFwZiL2+4B3w2WtNeSphEl3gjClos+Wg=\"" +
            "}";

        private const string BelgianTestIdCardAuthTokenRsa = 
            "{" +
            "  \"action\": \"web-eid:authenticate-success\"," +
            "  \"algorithm\": \"RS256\"," +
            "  \"appVersion\": \"https://web-eid.eu/web-eid-app/releases/2.7.0+965\"," +
            "  \"format\": \"web-eid:1.0\"," +
            "  \"signature\": \"KQsMoSj3lWz1H3NZ2LYtV27oIi2LdiBonYVjxZrRUt7qFBmepRRHY+vtM0qOZ0J8i9DwR25hmVi60S2yNAkYMIdYp3g2o8FamSpdz5MZBAGCpxF0yqK74sHN+87qjqj4qMv2rUIKMluhvjuwLSzZHaJzJyels/jdOHTQNgZ8S3ufEoCvLYcVU19TFryoo7ZWKfSB8qTWIv3UdOBTWG7fcU/fOwQmw9YAGrfKTJevTDIwcdLccqKXc1JzDWx6eargAx9Pa3Ehwa1SwB0aTXYVsfO+9awlFzjTXAnCudzKLoYBmNJedmv0MXlxNHSFQ9sNZDVgV4Sb5nQSlXE0st9uoQ==\"," +
            "  \"unverifiedCertificate\": \"MIID7zCCA3WgAwIBAgIQEAAAAAAA8evx/gAAAAHu2TAKBggqhkjOPQQDAzAuMQswCQYDVQQGEwJCRTEfMB0GA1UEAwwWZUlEIFRFU1QgRUMgQ2l0aXplbiBDQTAeFw0yMzA5MjYyMjAwMDBaFw0zMzA5MjYyMjAwMDBaMHYxCzAJBgNVBAYTAkJFMScwJQYDVQQDDB5Ob3JhIFNwZWNpbWVuIChBdXRoZW50aWNhdGlvbikxETAPBgNVBAQMCFNwZWNpbWVuMRUwEwYDVQQqDAxOb3JhIEFuZ8OobGUxFDASBgNVBAUTCzAxMDUwMzk5ODY0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/JkeHwt4rQhx/QrpPSCLUd98YxiZRvtKyo1glLiByNvDu7D6Jgg70tj2wlrwn3X0c8Rz/Yy3SgLIPzc92ptvaJG0H52cecRKABzDKwn9Qf/ZwsasDkKnprx0KUbiTaBU9Se1AEim5hyG4naahcfQJo+SwvIMhjIVPk1l1B+fbwRBlYG+LoJXdLSwoYRWArnf+4vx2PXR1nrmfLDw0NrtuNQy637O58DSL2XGd0+jKpQfYCBrqN0B26zA2RU0Uzb0ztEf4VXYH26dmv+bqwpXdPQYPQ7elNFXzFCRnmgJfxt4aKSkGZ2sQFWrKeIRxzVizLFDnfW8TSV5S4tuwYSMwIDAQABo4IBYDCCAVwwHwYDVR0jBBgwFoAU3bN/45oZjlnJEVYCLfX6nW/ehEswDgYDVR0PAQH/BAQDAgeAMEkGA1UdIARCMEAwPgYHYDgMAQECAjAzMDEGCCsGAQUFBwIBFiVodHRwOi8vZWlkZGV2Y2FyZHMuemV0ZXNjYXJkcy5iZS9jZXJ0MBMGA1UdJQQMMAoGCCsGAQUFBwMCMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9laWRkZXZjYXJkcy56ZXRlc2NhcmRzLmJlL2NybC9jaXRpemVuY2FFQy5jcmwwgYEGCCsGAQUFBwEBBHUwczA+BggrBgEFBQcwAoYyaHR0cDovL2VpZGRldmNhcmRzLnpldGVzY2FyZHMuYmUvY2VydC9yb290Y2FFQy5jcnQwMQYIKwYBBQUHMAGGJWh0dHA6Ly9laWRkZXZjYXJkcy56ZXRlc2NhcmRzLmJlOjg4ODgwCgYIKoZIzj0EAwMDaAAwZQIwL3Mp3pSlxfjUQ6zlsAwLHBbs1//7vPiqx//IcyUZYuVXZ00KG8MelmaMNbmzDVxaAjEAnqHxkwV5sSDwQCUbb6Tofaypm+DO6C2LriHS5r+s84x2Eq+s+lAJ1L4WkcgsKxns\"" +
            "}";



        [Test]
        public void WhenIdCardWithECCSignatureCertificateIsValidatedThenValidationSucceeds()
        {
            using var _ = DateTimeProvider.OverrideUtcNow(new DateTime(2024, 12, 24));
            var validator = AuthTokenValidators.GetAuthTokenValidatorForBelgianIdCard();
            var token = validator.Parse(BelgianTestIdCardAuthTokenEcc);
            Assert.DoesNotThrowAsync(() => validator.Validate(token, "iMeEwP2cgUINY2XoO/lqEpOUn7z/ysHRqGXkGKC4VXE="));
        }

        [Test]
        public void WhenIdCardWithRSASignatureCertificateIsValidatedThenValidationSucceeds()
        {
            using var _ = DateTimeProvider.OverrideUtcNow(new DateTime(2024, 12, 24));
            var validator = AuthTokenValidators.GetAuthTokenValidatorForBelgianIdCard();
            var token = validator.Parse(BelgianTestIdCardAuthTokenRsa);
            Assert.DoesNotThrowAsync(() => validator.Validate(token, "YPVgYc7Qds0qmK/RilPLffnsIg7IIovM4BAWqGZWwiY="));
        }
      
    }
}
