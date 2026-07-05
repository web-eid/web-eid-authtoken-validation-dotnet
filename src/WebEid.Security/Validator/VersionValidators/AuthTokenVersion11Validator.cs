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
namespace WebEid.Security.Validator.VersionValidators
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using AuthToken;
    using CertValidators;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Ocsp;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X509;
    using Util;

    /// <summary>
    /// Validator for token formats with major version 1 and minor version 1 or higher, e.g. web-eid:1.1.
    /// Extends V1 validator with additional checks for signing certificate + supported algorithms.
    /// </summary>
    public sealed class AuthTokenVersion11Validator : AuthTokenVersion1Validator
    {
        private const int SupportedMinimalMinorVersion = 1;

        private static readonly HashSet<string> SupportedSigningCryptoAlgorithms =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "ECC",
                "RSA"
            };

        private static readonly HashSet<string> SupportedSigningPaddingSchemes =
            new(StringComparer.OrdinalIgnoreCase)
            {
                "NONE",
                "PKCS1.5",
                "PSS"
            };

        private static readonly HashSet<string> SupportedSigningHashFunctions =
            new(StringComparer.OrdinalIgnoreCase)
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

        private readonly AuthTokenValidationConfiguration configuration;

        /// <summary>
        /// Initializes a validator for Web eID authentication tokens with token format major version 1
        /// and minor version 1 or higher.
        /// </summary>
        internal AuthTokenVersion11Validator(
            SubjectCertificateValidatorBatch simpleSubjectCertificateValidators,
            AuthTokenSignatureValidator signatureValidator,
            AuthTokenValidationConfiguration configuration,
            IOcspClient ocspClient,
            OcspServiceProvider ocspServiceProvider,
            ILogger logger = null)
            : base(simpleSubjectCertificateValidators, signatureValidator, configuration,
                   ocspClient, ocspServiceProvider, logger)
            => this.configuration = configuration;

        /// <summary>
        /// Determines whether this validator supports the specified token format.
        /// </summary>
        public override bool Supports(string format) =>
            AuthTokenVersion.Supports(format, SupportedExactMajorVersion, SupportedMinimalMinorVersion);

        /// <summary>
        /// Validates a Web eID authentication token with token format major version 1
        /// and minor version 1 or higher, and returns the authenticated user's certificate.
        /// </summary>
        public override async Task<X509Certificate2> Validate(WebEidAuthToken authToken, string currentChallengeNonce)
        {
            var subjectCertificate = await base.Validate(authToken, currentChallengeNonce);

            foreach (var unverifiedSigningCertificate in ValidateSigningCertificates(authToken))
            {
                var signingCertificate = ParseSigningCertificate(unverifiedSigningCertificate.Certificate);
                ValidateSameSubject(subjectCertificate, signingCertificate);
                ValidateSameIssuer(subjectCertificate, signingCertificate);
                ValidateSigningCertificateKeyUsage(signingCertificate);
                ValidateSigningCertificateChain(signingCertificate,
                    X509CertificateExtensions.ParseCertificates(
                        unverifiedSigningCertificate.IntermediateCertificates, "intermediateCertificates"));
            }

            return subjectCertificate;
        }

        private static void ValidateSupportedSignatureAlgorithms(UnverifiedSigningCertificate cert)
        {
            var algorithms = cert.SupportedSignatureAlgorithms;

            if (algorithms == null || algorithms.Count == 0)
            {
                throw new AuthTokenParseException("'supportedSignatureAlgorithms' field is missing");
            }

            var hasInvalid =
                algorithms.Any(algorithm =>
                    algorithm == null ||
                    algorithm.CryptoAlgorithm == null ||
                    algorithm.HashFunction == null ||
                    algorithm.PaddingScheme == null ||
                    !SupportedSigningCryptoAlgorithms.Contains(algorithm.CryptoAlgorithm) ||
                    !SupportedSigningHashFunctions.Contains(algorithm.HashFunction) ||
                    !SupportedSigningPaddingSchemes.Contains(algorithm.PaddingScheme));

            if (hasInvalid)
            {
                throw new AuthTokenParseException("Unsupported signature algorithm");
            }
        }

        private static List<UnverifiedSigningCertificate> ValidateSigningCertificates(WebEidAuthToken token)
        {
            var signingCertificates = token.UnverifiedSigningCertificates;
            var intermediateCertificates = token.UnverifiedIntermediateCertificates;

            // When the authentication certificate's intermediate certificates are present, signing certificates
            // are optional.
            if (signingCertificates == null && intermediateCertificates is { Count: > 0 })
            {
                return [];
            }
            if (signingCertificates == null || signingCertificates.Count == 0)
            {
                throw new AuthTokenParseException(
                    $"'unverifiedSigningCertificates' field is missing, null or empty for format '{token.Format}'");
            }

            foreach (var certificate in signingCertificates)
            {
                if (certificate == null || string.IsNullOrEmpty(certificate.Certificate))
                {
                    throw new AuthTokenParseException(
                        $"'unverifiedSigningCertificates' contains a null or empty entry for format '{token.Format}'");
                }

                ValidateSupportedSignatureAlgorithms(certificate);
                ValidateIntermediateCertificatesField(certificate.IntermediateCertificates,
                    "intermediateCertificates", token.Format);
            }

            return signingCertificates;
        }

        private static X509Certificate2 ParseSigningCertificate(string certificateInBase64)
        {
            try
            {
                return X509CertificateExtensions.ParseCertificate(certificateInBase64, "unverifiedSigningCertificates");
            }
            catch (Exception ex)
            {
                throw new AuthTokenParseException("Failed to decode signing certificate", ex);
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

        private void ValidateSigningCertificateChain(X509Certificate2 signingCertificate,
            ICollection<X509Certificate2> intermediateCertificates)
        {
            try
            {
                // The signing certificate itself deliberately gets no revocation check during authentication: its
                // revocation status matters at signing time and is the signature validation service's concern.
                // Token-supplied intermediate certificates in its path are checked for revocation.
                signingCertificate.ValidateIsValidAndSignedByTrustedCa(
                    "Signing",
                    configuration.TrustedCaCertificates,
                    intermediateCertificates,
                    IntermediateRevocationCheck.Enabled,
                    configuration.OcspRequestTimeout,
                    DateTimeProvider.UtcNow);
            }
            catch (Exception ex)
            {
                throw new AuthTokenParseException(
                    "Signing certificate chain validation failed",
                    ex
                );
            }
        }

        private static bool SubjectsMatch(X509Certificate2 subjectCert, X509Certificate2 signingCert)
        {
            var authRaw = subjectCert.SubjectName.RawData;
            var signRaw = signingCert.SubjectName.RawData;

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
                    return [];
                }

                var akiObj = Asn1Object.FromByteArray(akiExt.RawData);
                var aki = AuthorityKeyIdentifier.GetInstance(akiObj);

                return aki.GetKeyIdentifier() ?? [];
            }
            catch (Exception ex)
            {
                throw new AuthTokenParseException("Failed to parse Authority Key Identifier", ex);
            }
        }
    }
}
