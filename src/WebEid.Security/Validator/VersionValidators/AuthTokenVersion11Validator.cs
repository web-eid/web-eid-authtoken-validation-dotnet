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
namespace WebEid.Security.Validator.VersionValidators
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using CertValidators;
    using Microsoft.Extensions.Logging;
    using Ocsp;
    using AuthToken;
    using Exceptions;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X509;
    using Util;

    /// <summary>
    /// Validator for token format web-eid:1.1.
    /// Extends V1 validator with additional checks for signing certificate + supported algorithms.
    /// </summary>
    public sealed class AuthTokenVersion11Validator : AuthTokenVersion1Validator
    {
        private const string FormatPrefix = "web-eid:1.1";

        private static readonly HashSet<string> SupportedCryptoAlgorithms =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "ECC",
                "RSA"
            };

        private static readonly HashSet<string> SupportedPaddingSchemes =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "NONE",
                "PKCS1.5",
                "PSS"
            };

        private static readonly HashSet<string> SupportedHashFunctions =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "SHA-224",
                "SHA-256",
                "SHA-384",
                "SHA-512",
                "SHA3-224",
                "SHA3-256",
                "SHA3-384",
                "SHA3-512"
            };

        /// <summary>
        /// Initializes a validator for Web eID authentication tokens in format <c>web-eid:1.1</c>.
        /// </summary>
        public AuthTokenVersion11Validator(
            SubjectCertificateValidatorBatch simpleSubjectCertificateValidators,
            AuthTokenSignatureValidator signatureValidator,
            AuthTokenValidationConfiguration configuration,
            IOcspClient ocspClient,
            OcspServiceProvider ocspServiceProvider,
            ILogger logger = null)
            : base(simpleSubjectCertificateValidators, signatureValidator, configuration,
                   ocspClient, ocspServiceProvider, logger)
        {
        }

        /// <summary>
        /// Determines whether this validator supports the specified token format.
        /// </summary>
        public override bool Supports(string format) =>
            format != null &&
            format.StartsWith(FormatPrefix, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Validates a Web eID authentication token in format <c>web-eid:1.1</c>
        /// and returns the authenticated user's certificate.
        /// </summary>
        public override async Task<X509Certificate2> Validate(WebEidAuthToken authToken, string currentChallengeNonce)
        {
            var subjectCertificate = await base.Validate(authToken, currentChallengeNonce);
            var signingCertificate = ValidateSigningCertificateExists(authToken);
            ValidateSupportedSignatureAlgorithms(authToken.SupportedSignatureAlgorithms);
            ValidateSameSubject(subjectCertificate, signingCertificate);
            ValidateSameIssuer(subjectCertificate, signingCertificate);
            ValidateSigningCertificateValidity(signingCertificate);
            ValidateSigningCertificateKeyUsage(signingCertificate);

            return subjectCertificate;
        }

        private static X509Certificate2 ValidateSigningCertificateExists(WebEidAuthToken token)
        {
            if (string.IsNullOrEmpty(token.UnverifiedSigningCertificate))
            {
                throw new AuthTokenParseException(
                    "'unverifiedSigningCertificate' field is missing, null or empty for format 'web-eid:1.1'");
            }

            try
            {
                return X509CertificateExtensions.ParseCertificate(
                    token.UnverifiedSigningCertificate,
                    "unverifiedSigningCertificate");
            }
            catch (Exception ex)
            {
                throw new AuthTokenParseException("Failed to decode signing certificate", ex);
            }
        }

        private static void ValidateSupportedSignatureAlgorithms(
            IList<SupportedSignatureAlgorithm> algorithms)
        {
            if (algorithms == null || algorithms.Count == 0)
            {
                throw new AuthTokenParseException("'supportedSignatureAlgorithms' field is missing");
            }

            bool hasInvalid =
                algorithms.Any(a =>
                    !SupportedCryptoAlgorithms.Contains(a.CryptoAlgorithm) ||
                    !SupportedHashFunctions.Contains(a.HashFunction) ||
                    !SupportedPaddingSchemes.Contains(a.PaddingScheme));

            if (hasInvalid)
            {
                throw new AuthTokenParseException("Unsupported signature algorithm");
            }
        }

        private static void ValidateSameSubject(X509Certificate2 subjectCert, X509Certificate2 signingCert)
        {
            if (!SubjectsMatch(subjectCert, signingCert))
            {
                throw new AuthTokenParseException(
                    "Signing certificate subject does not match authentication certificate subject");
            }
        }

        private static void ValidateSameIssuer(X509Certificate2 subjectCert, X509Certificate2 signingCert)
        {
            var subjectAki = GetAuthorityKeyIdentifier(subjectCert);
            var signingAki = GetAuthorityKeyIdentifier(signingCert);

            if (subjectAki.Length == 0 ||
                signingAki.Length == 0 ||
                !subjectAki.SequenceEqual(signingAki))
            {
                throw new AuthTokenParseException(
                    "Signing certificate is not issued by the same issuing authority as the authentication certificate");
            }
        }

        private static void ValidateSigningCertificateValidity(X509Certificate2 cert)
        {
            try
            {
                var bcCert = cert.ToBouncyCastle();
                bcCert.ValidateCertificateExpiry(DateTime.UtcNow, "signing_certificate");
            }
            catch (Exception ex)
            {
                throw new AuthTokenParseException(
                    "Signing certificate is not valid: " + ex.Message, ex);
            }
        }

        private static void ValidateSigningCertificateKeyUsage(X509Certificate2 cert)
        {
            var keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsage == null ||
                !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.NonRepudiation))
            {
                throw new AuthTokenParseException(
                    "Signing certificate key usage extension missing or does not contain non-repudiation bit required for digital signatures");
            }
        }

        private static bool SubjectsMatch(X509Certificate2 subjectCert, X509Certificate2 signingCert)
        {
            byte[] authRaw = subjectCert.SubjectName.RawData;
            byte[] signRaw = signingCert.SubjectName.RawData;

            var authAsn1 = Asn1Object.FromByteArray(authRaw);
            var signAsn1 = Asn1Object.FromByteArray(signRaw);

            var authName = X509Name.GetInstance(authAsn1);
            var signName = X509Name.GetInstance(signAsn1);

            return authName.Equivalent(signName);
        }

        private static byte[] GetAuthorityKeyIdentifier(X509Certificate2 cert)
        {
            try
            {
                var akiExt = cert.Extensions["2.5.29.35"];
                if (akiExt == null)
                {
                    return Array.Empty<byte>();
                }

                var akiObj = Asn1Object.FromByteArray(akiExt.RawData);
                var aki = AuthorityKeyIdentifier.GetInstance(akiObj);

                return aki.GetKeyIdentifier() ?? Array.Empty<byte>();
            }
            catch (Exception ex)
            {
                throw new AuthTokenParseException("Failed to parse Authority Key Identifier", ex);
            }
        }
    }
}
