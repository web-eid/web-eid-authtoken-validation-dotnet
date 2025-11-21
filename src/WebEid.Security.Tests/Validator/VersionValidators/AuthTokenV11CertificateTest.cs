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
    using System;
    using System.Collections.Generic;
    using NUnit.Framework;
    using Exceptions;
    using WebEid.Security.Validator;
    using System.Text.Json;
    using AuthToken;
    using TestUtils;

    public class AuthTokenV11CertificateTest : AbstractTestWithValidator
    {
        private const string V11AuthTokenStr = "{\"algorithm\":\"ES384\"," +
        "\"unverifiedCertificate\":\"MIIEBDCCA2WgAwIBAgIQY5OGshxoPMFg+Wfc0gFEaTAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4MB4XDTIxMDcyMjEyNDMwOFoXDTI2MDcwOTIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UEBRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQmwEKsJTjaMHSaZj19hb9EJaJlwbKc5VFzmlGMFSJVk4dDy+eUxa5KOA7tWXqzcmhh5SYdv+MxcaQKlKWLMa36pfgv20FpEDb03GCtLqjLTRZ7649PugAQ5EmAqIic29CjggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDiDBHBgNVHSAEQDA+MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBBgwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFPlp/ceABC52itoqppEmbf71TJz6MGEGCCsGAQUFBwEDBFUwUzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcnRpZmljYXRlcy8TAkVOMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQUFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgDCAgybz0u3W+tGI+AX+PiI5CrE9ptEHO5eezR1Jo4j7iGaO0i39xTGUB+NSC7P6AQbyE/ywqJjA1a62jTLcS9GHAJCARxN4NO4eVdWU3zVohCXm8WN3DWA7XUcn9TZiLGQ29P4xfQZOXJi/z4PNRRsR4plvSNB3dfyBvZn31HhC7my8woi\"," +
        "\"unverifiedSigningCertificate\":\"X5C\"," +
        "\"supportedSignatureAlgorithms\":[{\"cryptoAlgorithm\":\"RSA\",\"hashFunction\":\"SHA-256\",\"paddingScheme\":\"PKCS1.5\"}]," +
        "\"appVersion\":\"https://web-eid.eu/web-eid-mobile-app/releases/v1.0.0\"," +
        "\"signature\":\"0Ov7ME6pTY1K2GXMj8Wxov/o2fGIMEds8OMY5dKdkB0nrqQX7fG1E5mnsbvyHpMDecMUH6Yg+p1HXdgB/lLqOcFZjt/OVXPjAAApC5d1YgRYATDcxsR1zqQwiNcHdmWn\"," +
        "\"format\":\"web-eid:1.1\"}";

        private const string DifferentCertBase64 = "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";
        private const string MissingKeyUsageCert = "MIICxjCCAa6gAwIBAgIJANTbd26vS6fmMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNVBAMTCndlYi1laWQuZXUwHhcNMjAwOTI0MTIyNDMzWhcNMzAwOTIyMTIyNDMzWjAVMRMwEQYDVQQDEwp3ZWItZWlkLmV1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAza5qBFu5fvs47rx3o9yzBVfIxHjMotID8ppkwWVen/uFxlqsRVi+XnWkggW+K8X45inAnBAVi1rIw7GQNdacSHglyvQfwM64AallmD0+K+QgbqxcO9fvRvlAeISENBc2bGgqTIytPEON5ZmazzbOZjqY3M1QcPlPZOeUm6M9ZcZFhsxpiB4gwZUic9tnCz9eujd6k6DzNVfSRaJcpGA5hJ9aKH4vXS3x7anewna+USEXkRb4Il5zSlZR0i1yrVA1YNOxCG/+GgWvXfvXwdQ0z9BpGwNEyc0mRDNx+umaTukz9t+7/qTcB2JLTuiwM9Gqg5sDDnzPlcZSa7GnIU0MLQIDAQABoxkwFzAVBgNVHREEDjAMggp3ZWItZWlkLmV1MA0GCSqGSIb3DQEBBQUAA4IBAQAYGkBhTlet47uw3JYunYo6dj4nGWSGV4x6LYjCp5QlAmGd28HpC1RFB3ba+inwW8SP69kEOcB0sJQAZ/tV90oCATNsy/Whg/TtiHISL2pr1dyBoKDRWbgTp8jjzcp2Bj9nL14aqpj1t4K1lcoYETX41yVmyyJu6VFs80M5T3yikm2giAhszjChnjyoT2kaEKoua9EUK9SS27pVltgbbvtmeTp3ZPHtBfiDOATL6E03RZ5WfMLRefI796a+RcznnudzQHhMSwcjLpMDgIWpUU4OU7RiwrU+S3MrvgzCjkWh2MGu/OGLB+d3JZoW+eCvigoshmAsbJCMLbh4N78BCPqk";

        private AuthTokenValidationConfiguration config;

        [SetUp]
        public void Init()
        {
            config = new AuthTokenValidationConfiguration
            {
                SiteOrigin = new Uri("https://example.com"),
                IsUserCertificateRevocationCheckWithOcspEnabled = false
            };
            config.TrustedCaCertificates.Clear();
        }

        [Test]
        public void WhenValidV11TokenThenValidationSucceeds()
        {
            var authTokenValidator = new AuthTokenValidator(config);
            var token = authTokenValidator.Parse(ValidV11AuthTokenStr);
            Assert.DoesNotThrowAsync(() => Validator.Validate(token, ValidChallengeNonce));
        }

        [Test]
        public void WhenV11SigningCertificateMissingThenValidationFails()
        {
            var tokenFields = JsonSerializer.Deserialize<Dictionary<string, object>>(V11AuthTokenStr);
            tokenFields.Remove("unverifiedSigningCertificate");
            var modifiedTokenJson = JsonSerializer.Serialize(tokenFields);
            var token = JsonSerializer.Deserialize<WebEidAuthToken>(modifiedTokenJson);

            Assert.ThrowsAsync<AuthTokenParseException>(() =>
                Validator.Validate(token, ValidChallengeNonce));
        }

        [Test]
        public void WhenV11SigningCertificateIsNotBase64ThenValidationFails()
        {
            var tokenFields = JsonSerializer.Deserialize<Dictionary<string, object>>(V11AuthTokenStr);
            tokenFields["unverifiedSigningCertificate"] = "This is not a certificate";
            var modifiedTokenJson = JsonSerializer.Serialize(tokenFields);
            var token = JsonSerializer.Deserialize<WebEidAuthToken>(modifiedTokenJson);

            Assert.ThrowsAsync<AuthTokenParseException>(() =>
                Validator.Validate(token, ValidChallengeNonce));
        }

        [Test]
        public void WhenV11SigningCertificateIsNotACertificateThenValidationFails()
        {
            var tokenFields = JsonSerializer.Deserialize<Dictionary<string, object>>(V11AuthTokenStr);
            tokenFields["unverifiedSigningCertificate"] = "VGhpcyBpcyBub3QgYSBjZXJ0aWZpY2F0ZQ";
            var modifiedTokenJson = JsonSerializer.Serialize(tokenFields);
            var token = JsonSerializer.Deserialize<WebEidAuthToken>(modifiedTokenJson);

            Assert.ThrowsAsync<AuthTokenParseException>(() =>
                Validator.Validate(token, ValidChallengeNonce));
        }

        [Test]
        public void WhenV11SigningCertificateSubjectDoesNotMatchThenValidationFails()
        {
            var tokenFields = JsonSerializer.Deserialize<Dictionary<string, object>>(V11AuthTokenStr);
            tokenFields["unverifiedSigningCertificate"] = DifferentCertBase64;
            var modifiedTokenJson = JsonSerializer.Serialize(tokenFields);
            var token = JsonSerializer.Deserialize<WebEidAuthToken>(modifiedTokenJson);

            Assert.ThrowsAsync<AuthTokenParseException>(() =>
                Validator.Validate(token, ValidChallengeNonce));
        }

        [Test]
        public void WhenV11SigningCertificateNotIssuedBySameAuthorityThenValidationFails()
        {
            var tokenFields = JsonSerializer.Deserialize<Dictionary<string, object>>(V11AuthTokenStr);
            tokenFields["unverifiedSigningCertificate"] = ValidChallengeNonce;
            var modifiedTokenJson = JsonSerializer.Serialize(tokenFields);
            var token = JsonSerializer.Deserialize<WebEidAuthToken>(modifiedTokenJson);

            Assert.ThrowsAsync<AuthTokenParseException>(() =>
                Validator.Validate(token, ValidChallengeNonce));
        }

        [Test]
        public void WhenV11SigningCertificateKeyUsageInvalidThenValidationFails()
        {
            var tokenFields = JsonSerializer.Deserialize<Dictionary<string, object>>(V11AuthTokenStr);
            tokenFields["unverifiedSigningCertificate"] = MissingKeyUsageCert;
            var modifiedTokenJson = JsonSerializer.Serialize(tokenFields);
            var token = JsonSerializer.Deserialize<WebEidAuthToken>(modifiedTokenJson);

            Assert.ThrowsAsync<AuthTokenParseException>(() =>
                Validator.Validate(token, ValidChallengeNonce));
        }
    }
}
