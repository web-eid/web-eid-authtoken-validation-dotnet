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
    using System.Globalization;
    using NUnit.Framework;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Tests.TestUtils;
    using WebEid.Security.Util;
    using WebEid.Security.Validator;

    public class AuthTokenSignatureValidatorTests : AbstractTestWithValidator
    {
        private const string ValidRs256AuthToken = "{\"algorithm\":\"RS256\"," +
        "\"unverifiedCertificate\":\"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\"," +
        "\"issuerApp\":\"https://web-eid.eu/web-eid-app/releases/2.0.0+0\"," +
        "\"signature\":\"xsjXsQvVYXWcdV0YPhxLthJxtf0//R8p9WFFlYJGRARrl1ruyoAUwl0xeHgeZOKeJtwiCYCNWJzCG3VM3ydgt92bKhhk1u0JXIPVqvOkmDY72OCN4q73Y8iGSPVTgjk93TgquHlodf7YcqZNhutwNNf3oldHEWJD5zmkdwdpBFXgeOwTAdFwGljDQZbHr3h1Dr+apUDuloS0WuIzUuu8YXN2b8lh8FCTlF0G0DEjhHd/MGx8dbe3UTLHmD7K9DXv4zLJs6EF9i2v/C10SIBQDkPBSVPqMxCDPECjbEPi2+ds94eU7ThOhOQlFFtJ4KjQNTUa2crSixH7cYZF2rNNmA==\"," +
        "\"format\":\"web-eid:1.0\"}";
        private const string ValidV11Rs256AuthToken = "{\"algorithm\":\"RS256\"," +
        "\"unverifiedCertificate\":\"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\"," +
        "\"unverifiedSigningCertificate\":\"X5C\"," +
        "\"supportedSignatureAlgorithms\":[{\"cryptoAlgorithm\":\"RSA\",\"hashFunction\":\"SHA-256\",\"paddingScheme\":\"PKCS1.5\"}]," +
        "\"issuerApp\":\"https://web-eid.eu/web-eid-mobile-app/releases/v1.0.0\"," +
        "\"signature\":\"xsjXsQvVYXWcdV0YPhxLthJxtf0//R8p9WFFlYJGRARrl1ruyoAUwl0xeHgeZOKeJtwiCYCNWJzCG3VM3ydgt92bKhhk1u0JXIPVqvOkmDY72OCN4q73Y8iGSPVTgjk93TgquHlodf7YcqZNhutwNNf3oldHEWJD5zmkdwdpBFXgeOwTAdFwGljDQZbHr3h1Dr+apUDuloS0WuIzUuu8YXN2b8lh8FCTlF0G0DEjhHd/MGx8dbe3UTLHmD7K9DXv4zLJs6EF9i2v/C10SIBQDkPBSVPqMxCDPECjbEPi2+ds94eU7ThOhOQlFFtJ4KjQNTUa2crSixH7cYZF2rNNmA==\"," +
        "\"format\":\"web-eid:1.1\"}";
        private const string AuthTokenWithWrongCert = "{\"algorithm\":\"ES384\"," +
        "\"unverifiedCertificate\":\"MIIEBDCCA2WgAwIBAgIQH9NeN14jo0ReaircrN2YvDAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTIwMDMxMjEyMjgxMloXDTI1MDMxMjIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARVeP+9l3b1mm3fMHPeCFLbD7esXI8lDc+soWCBoMnZGo3d2Rg/mzKCIWJtw+JhcN7RwFFH9cwZ8Gni4C3QFYBIIJ2GdjX2KQfEkDvRsnKw6ZZmJQ+HC4ZFew3r8gauhfejggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFOfk7lPOq6rb9IbFZF1q97kJ4s2iMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgEQRbzFOSHIcmIEKczhN8xuteYgN2zEXZSJdP0q1iH1RR2AzZ8Ddz6SKRn/bZSzjcd4b7h3AyOEQr2hcidYkxT7sAJCAMPtOUryqp2WbTEUoOpbWrKqp8GjaAiVpBGDn/Xdu5M2Z6dvwZHnFGgRrZXtyUbcAgRW7MQJ0s/9GCVro3iqUzNN\"," +
        "\"appVersion\":\"https://web-eid.eu/web-eid-app/releases/2.0.0+0\"," +
        "\"signature\":\"arx164xRiwhIQDINe0J+ZxJWZFOQTx0PBtOaWaxAe7gofEIHRIbV1w0sOCYBJnvmvMem9hU4nc2+iJx2x8poYck4Z6eI3GwtiksIec3XQ9ZIk1n/XchXnmPn3GYV+HzJ\"," +
        "\"format\":\"web-eid:1.0\"}";
        private const string V11AuthTokenWithWrongCert = "{\"algorithm\":\"ES384\"," +
        "\"unverifiedCertificate\":\"MIIEDDCCA26gAwIBAgIQM8UTDe8zVKtcysotoMgBlzAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDUwMVoXDTI5MDUwMjEwNDUwMVowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARh/M6SBatkyMHjTmRgIF1MTqZpVIfqHZD6MrQUHdlykVSLNBmloFjoXbQbSe0l+sgKUPSZWb48IGPC7Mrudt5vLvnKy31qZ5a+2Ceg87NrVzdNCWF2oQrwXw63HieIBMmjggHMMIIByDAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwKAYDVR0RBCEwH4EdamFhay1rcmlzdGphbi5qb2VvcmdAZWVzdGkuZWUwHQYDVR0OBBYEFOSW4XJH0oDJAh2nEqFGhrlF9zXQMGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQQjG3AnPzJdtmoaNI59T8vcjsNjVB5XLfUXiBguizma9I6dFqhHiTtfqo2aWpd+dcL8iz/3Dn03C0ruPLnJVt24lAkIB8M6KO+RcVJqXz8KXMUGstjK+1iIE0hd+2JtNmIJcqgNT7sj8f4NZfsix5JuUpY1j4msWG3k0h79U2bWcR8NQZdU=\"," +
        "\"unverifiedSigningCertificate\":\"MIID6zCCA02gAwIBAgIQT7j6zk6pmVRcyspLo5SqejAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTE5MDUwMjEwNDUzMVoXDTI5MDUwMjEwNDUzMVowfzELMAkGA1UEBhMCRUUxFjAUBgNVBCoMDUpBQUstS1JJU1RKQU4xEDAOBgNVBAQMB0rDlUVPUkcxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASkwENR8GmCpEs6OshDWDfIiKvGuyNMOD2rjIQW321AnZD3oIsqD0svBMNEJJj9Dlvq/47TYDObIa12KAU5IuOBfJs2lrFdSXZjaM+a5TWT3O2JTM36YDH2GcMe/eisepejggGrMIIBpzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGQDBIBgNVHSAEQTA/MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAJBgcEAIvsQAECMB0GA1UdDgQWBBTVX3s48Spy/Es2TcXgkRvwUn2YcjCBigYIKwYBBQUHAQMEfjB8MAgGBgQAjkYBATAIBgYEAI5GAQQwEwYGBACORgEGMAkGBwQAjkYBBgEwUQYGBACORgEFMEcwRRY/aHR0cHM6Ly9zay5lZS9lbi9yZXBvc2l0b3J5L2NvbmRpdGlvbnMtZm9yLXVzZS1vZi1jZXJ0aWZpY2F0ZXMvEwJFTjAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQgGBr+Jbo1GeqgWdIwgMo7SA29AP38JxNm2HWq2Qb+kIHpusAK574Co1K5D4+Mk7/ITTuXQaET5WphHoN7tdAciTaQJBAn0zBigYyVPYSTO68HM6hmlwTwi/KlJDdXW/2NsMjSqofFFJXpGvpxk2CTqSRCjcavxLPnkasTbNROYSJcmM8Xc=\"," +
        "\"supportedSignatureAlgorithms\":[{\"cryptoAlgorithm\":\"RSA\",\"hashFunction\":\"SHA-256\",\"paddingScheme\":\"PKCS1.5\"}]," +
        "\"appVersion\":\"https://web-eid.eu/web-eid-mobile-app/releases/v1.0.0\"," +
        "\"signature\":\"arx164xRiwhIQDINe0J+ZxJWZFOQTx0PBtOaWaxAe7gofEIHRIbV1w0sOCYBJnvmvMem9hU4nc2+iJx2x8poYck4Z6eI3GwtiksIec3XQ9ZIk1n/XchXnmPn3GYV+HzJ\"," +
        "\"format\":\"web-eid:1.1\"}";

        private static readonly TextInfo Ti = new CultureInfo("et-EE", false).TextInfo;

        [Test]
        public void WhenValidES384SignatureThenValidationSucceedsAsync() =>
            Assert.DoesNotThrowAsync(async () =>
            {
                var certificate = await Validator.Validate(ValidAuthToken, ValidChallengeNonce);

                Assert.That(certificate, Is.Not.Null);
                Assert.That(certificate.GetSubjectCn(), Is.EqualTo("JÕEORG,JAAK-KRISTJAN,38001085718"));
                Assert.That(ToTitleCase(certificate.GetSubjectGivenName()), Is.EqualTo("Jaak-Kristjan"));
                Assert.That(ToTitleCase(certificate.GetSubjectSurname()), Is.EqualTo("Jõeorg"));
                Assert.That(certificate.GetSubjectIdCode(), Is.EqualTo("PNOEE-38001085718"));
                Assert.That(certificate.GetSubjectCountryCode(), Is.EqualTo("EE"));
            });

        [Test]
        public void WhenValidRS256SignatureThenValidationSucceeds() =>
            Assert.DoesNotThrow(() =>
            {
                var authToken = Validator.Parse(ValidRs256AuthToken);
                var publicKey =
                    X509CertificateExtensions.ParseCertificate(authToken.UnverifiedCertificate, "unverifiedCertificate")
                        .GetAsymmetricPublicKey()
                        .CreateSecurityKeyWithoutCachingSignatureProviders();
                var signatureValidator = new AuthTokenSignatureValidator(new Uri("https://ria.ee"));
                signatureValidator.Validate("RS256", publicKey, authToken.Signature, ValidChallengeNonce);
            });

        [Test]
        public void WhenValidTokenAndWrongChallengeNonceThenValidationFailsAsync() =>
            Assert.ThrowsAsync<AuthTokenSignatureValidationException>(() =>
                Validator.Validate(ValidAuthToken, "12345678123456781234567812345678912356789124"));

        [Test]
        public void WhenValidTokenAndWrongOriginThenValidationFailsAsync()
        {
            var authTokenValidator = AuthTokenValidators.GetAuthTokenValidator("https://invalid.org");
            Assert.ThrowsAsync<AuthTokenSignatureValidationException>(() =>
                authTokenValidator.Validate(ValidAuthToken, ValidChallengeNonce));
        }

        [Test]
        public void WhenTokenWithWrongCertThenValidationFailsAsync()
        {
            var authTokenWithWrongCert = Validator.Parse(AuthTokenWithWrongCert);
            Assert.ThrowsAsync<AuthTokenSignatureValidationException>(() =>
                Validator.Validate(authTokenWithWrongCert, ValidChallengeNonce));
        }

        [Test]
        public void WhenValidV11TokenAndNonceThenValidationSucceedsAsync() =>
            Assert.DoesNotThrowAsync(async () =>
            {
                var token = Validator.Parse(ValidV11AuthTokenStr);

                var certificate = await Validator.Validate(token, ValidChallengeNonce);

                Assert.That(certificate, Is.Not.Null);
                Assert.That(certificate.GetSubjectCn(), Is.EqualTo("JÕEORG,JAAK-KRISTJAN,38001085718"));
                Assert.That(ToTitleCase(certificate.GetSubjectGivenName()), Is.EqualTo("Jaak-Kristjan"));
                Assert.That(ToTitleCase(certificate.GetSubjectSurname()), Is.EqualTo("Jõeorg"));
                Assert.That(certificate.GetSubjectIdCode(), Is.EqualTo("PNOEE-38001085718"));
                Assert.That(certificate.GetSubjectCountryCode(), Is.EqualTo("EE"));
            });

        [Test]
        public void WhenV11TokenWithWrongChallengeNonceThenValidationFailsAsync()
        {
            var token = Validator.Parse(ValidV11AuthTokenStr);

            var ex = Assert.ThrowsAsync<AuthTokenSignatureValidationException>(() =>
                Validator.Validate(token, "12345678123456781234567812345678912356789124"))!;

            Assert.That(ex.Message, Does.Contain("signature"));
        }

        [Test]
        public void WhenV11TokenWithWrongOriginThenValidationFailsAsync()
        {
            var validatorWithWrongOrigin =
                AuthTokenValidators.GetAuthTokenValidator("https://wrong-origin.com");

            var token = validatorWithWrongOrigin.Parse(ValidV11AuthTokenStr);

            var ex = Assert.ThrowsAsync<AuthTokenSignatureValidationException>(() =>
                validatorWithWrongOrigin.Validate(token, ValidChallengeNonce))!;

            Assert.That(ex.Message, Does.Contain("Token signature validation has failed"));
        }

        [Test]
        public void WhenV11TokenWithWrongCertThenValidationFailsAsync()
        {
            var token = Validator.Parse(V11AuthTokenWithWrongCert);

            var ex = Assert.ThrowsAsync<AuthTokenSignatureValidationException>(() =>
                Validator.Validate(token, ValidChallengeNonce))!;

            Assert.That(ex.Message, Does.Contain("signature"));
        }

        [Test]
        public void WhenValidRS256V11SignatureThenValidationSucceeds() =>
            Assert.DoesNotThrow(() =>
            {
                var authToken = Validator.Parse(ValidV11Rs256AuthToken);
                var publicKey =
                    X509CertificateExtensions
                        .ParseCertificate(authToken.UnverifiedCertificate, "unverifiedCertificate")
                        .GetAsymmetricPublicKey()
                        .CreateSecurityKeyWithoutCachingSignatureProviders();

                var signatureValidator = new AuthTokenSignatureValidator(new Uri("https://ria.ee"));

                signatureValidator.Validate( "RS256", publicKey, authToken.Signature, ValidChallengeNonce);
            });


        private static string ToTitleCase(string s) => Ti.ToTitleCase(Ti.ToLower(s));
    }
}
