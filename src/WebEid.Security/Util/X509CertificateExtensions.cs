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
namespace WebEid.Security.Util
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using Microsoft.IdentityModel.Tokens;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Security;

    /// <summary>
    /// Provides extension methods for <see cref="X509Certificate2"/> and <see cref="X509Certificate"/>.
    /// </summary>
    public static class X509CertificateExtensions
    {
        private static readonly TimeSpan DefaultRevocationUrlRetrievalTimeout = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Checks whether the certificate was valid on the given date.
        /// </summary>
        /// <param name="certificate">Certificate to validate</param>
        /// <param name="dateTime">DateTime moment when the certificate is checked to be valid</param>
        /// <param name="subject">Subject of the certificate</param>
        public static void ValidateCertificateExpiry(this X509Certificate2 certificate, DateTime dateTime, string subject) =>
            DotNetUtilities.FromX509Certificate(certificate).ValidateCertificateExpiry(dateTime, subject);

        /// <summary>
        /// Checks whether the certificate was valid on the given date.
        /// </summary>
        /// <param name="certificate">Certificate to validate</param>
        /// <param name="dateTime">DateTime moment when the certificate is checked to be valid</param>
        /// <param name="subject">Subject of the certificate</param>
        public static void ValidateCertificateExpiry(this Org.BouncyCastle.X509.X509Certificate certificate, DateTime dateTime, string subject)
        {
            try
            {
                certificate.CheckValidity(dateTime);
            }
            catch (Org.BouncyCastle.Security.Certificates.CertificateNotYetValidException e)
            {
                throw new CertificateNotYetValidException(subject, e);
            }
            catch (Org.BouncyCastle.Security.Certificates.CertificateExpiredException e)
            {
                throw new CertificateExpiredException(subject, e);
            }
        }

        /// <summary>
        /// Validates whether the given certificate is valid and signed by a trusted certificate authority (CA).
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <param name="trustedCaCertificates">A collection of trusted CA certificates.</param>
        /// <returns>The certificate that directly issued the given certificate; the trust anchor when the anchor is the direct issuer.</returns>
        /// <exception cref="CertificateNotTrustedException">If the certificate is not signed by a trusted CA or if any other error occurs.</exception>
        /// <exception cref="CertificateNotYetValidException">when a CA certificate in the chain or the user certificate is not yet valid</exception>
        /// <exception cref="CertificateExpiredException">when a CA certificate in the chain or the user certificate is expired</exception>
        public static X509Certificate2 ValidateIsValidAndSignedByTrustedCa(this X509Certificate2 certificate, ICollection<X509Certificate2> trustedCaCertificates) =>
            ValidateIsValidAndSignedByTrustedCa(certificate, "User", trustedCaCertificates, [],
                IntermediateRevocationCheck.Disabled, DateTimeProvider.UtcNow);

        /// <summary>
        /// Validates that the given certificate is valid and signed by a trusted CA and returns the certificate
        /// that directly issued it.
        /// </summary>
        /// <param name="certificate">The certificate whose certification path is validated.</param>
        /// <param name="certificateSubject">The role of the certificate, e.g. "User" or "AIA OCSP responder", used in
        /// validity failure messages.</param>
        /// <param name="trustedCaCertificates">A collection of trusted CA certificates.</param>
        /// <param name="additionalIntermediateCertificates">Untrusted intermediate certificates offered as
        /// certification-path candidates only; the path must still terminate at one of the trusted CA certificates.</param>
        /// <param name="intermediateRevocationCheck">Whether the non-anchor intermediate CA certificates of the built
        /// path are checked for revocation.</param>
        /// <param name="now">Validation date.</param>
        /// <returns>The certificate that directly issued the given certificate; the trust anchor when the anchor
        /// is the direct issuer.</returns>
        /// <exception cref="CertificateNotTrustedException">If the certificate is not signed by a trusted CA or if any other error occurs.</exception>
        /// <exception cref="CertificateNotYetValidException">when a CA certificate in the chain or the user certificate is not yet valid</exception>
        /// <exception cref="CertificateExpiredException">when a CA certificate in the chain or the user certificate is expired</exception>
        public static X509Certificate2 ValidateIsValidAndSignedByTrustedCa(this X509Certificate2 certificate,
            string certificateSubject,
            ICollection<X509Certificate2> trustedCaCertificates,
            ICollection<X509Certificate2> additionalIntermediateCertificates,
            IntermediateRevocationCheck intermediateRevocationCheck,
            DateTime now) =>
            ValidateIsValidAndSignedByTrustedCa(certificate, certificateSubject, trustedCaCertificates,
                additionalIntermediateCertificates, intermediateRevocationCheck,
                DefaultRevocationUrlRetrievalTimeout, now);

        /// <summary>
        /// Validates that the given certificate is valid and signed by a trusted CA and returns the certificate
        /// that directly issued it.
        /// </summary>
        /// <param name="certificate">The certificate whose certification path is validated.</param>
        /// <param name="certificateSubject">The role of the certificate, e.g. "User" or "AIA OCSP responder", used in
        /// validity failure messages.</param>
        /// <param name="trustedCaCertificates">A collection of trusted CA certificates.</param>
        /// <param name="additionalIntermediateCertificates">Untrusted intermediate certificates offered as
        /// certification-path candidates only; the path must still terminate at one of the trusted CA certificates.</param>
        /// <param name="intermediateRevocationCheck">Whether the non-anchor intermediate CA certificates of the built
        /// path are checked for revocation.</param>
        /// <param name="revocationUrlRetrievalTimeout">Maximum time spent retrieving OCSP or CRL data while checking
        /// intermediate certificate revocation.</param>
        /// <param name="now">Validation date.</param>
        /// <returns>The certificate that directly issued the given certificate; the trust anchor when the anchor
        /// is the direct issuer.</returns>
        /// <exception cref="CertificateNotTrustedException">If the certificate is not signed by a trusted CA or if any other error occurs.</exception>
        /// <exception cref="CertificateNotYetValidException">when a CA certificate in the chain or the user certificate is not yet valid</exception>
        /// <exception cref="CertificateExpiredException">when a CA certificate in the chain or the user certificate is expired</exception>
        public static X509Certificate2 ValidateIsValidAndSignedByTrustedCa(this X509Certificate2 certificate,
            string certificateSubject,
            ICollection<X509Certificate2> trustedCaCertificates,
            ICollection<X509Certificate2> additionalIntermediateCertificates,
            IntermediateRevocationCheck intermediateRevocationCheck,
            TimeSpan revocationUrlRetrievalTimeout,
            DateTime now)
        {
            ValidateCertificateExpiry(certificate, now, certificateSubject);
            RequirePositiveRevocationUrlRetrievalTimeout(revocationUrlRetrievalTimeout);

            var chain = new X509Chain
            {
                ChainPolicy =
                {
                    // Revocation checking of the validated certificate is intentionally disabled here: each caller
                    // applies its own role-specific leaf revocation policy. Non-anchor intermediate certificates are
                    // checked separately below when the intermediate revocation check is enabled.
                    RevocationMode = X509RevocationMode.NoCheck,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot,
                    VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority,
                    VerificationTime = now,
                    UrlRetrievalTimeout = revocationUrlRetrievalTimeout,
                    DisableCertificateDownloads = true
                }
            };

            foreach (var cert in trustedCaCertificates)
            {
                chain.ChainPolicy.ExtraStore.Add(cert);
            }
            foreach (var cert in additionalIntermediateCertificates ?? [])
            {
                chain.ChainPolicy.ExtraStore.Add(cert);
            }

            try
            {
                if (!chain.Build(certificate))
                {
                    var errors = chain.ChainStatus
                        .Select(x => string.Format(CultureInfo.InvariantCulture,
                            "{0} ({1})",
                            x.StatusInformation.Trim(),
                            x.Status))
                        .ToArray();
                    var certificateErrorsString = errors.Length > 0
                        ? string.Join(Environment.NewLine, errors)
                        : "Unknown errors.";

                    throw new CertificateNotTrustedException(certificate, certificateErrorsString);
                }

                // The built chain is ordered from the subject towards the root. The first element that is
                // a trusted CA certificate is the trust anchor; the path must terminate at it.
                var trustedCaIndex = -1;
                for (var i = 0; i < chain.ChainElements.Count; i++)
                {
                    if (trustedCaCertificates.Any(ca => chain.ChainElements[i].Certificate.Thumbprint == ca.Thumbprint))
                    {
                        trustedCaIndex = i;
                        break;
                    }
                }
                if (trustedCaIndex < 0)
                {
                    throw new CertificateNotTrustedException(certificate);
                }
                var trustedCaCertificate = chain.ChainElements[trustedCaIndex].Certificate;

                if (intermediateRevocationCheck == IntermediateRevocationCheck.Enabled)
                {
                    ValidateIntermediateCertificatesNotRevoked(chain, trustedCaIndex, trustedCaCertificates,
                        additionalIntermediateCertificates, revocationUrlRetrievalTimeout, now);
                }

                // Verify that the trusted CA cert is presently valid before returning the result.
                ValidateCertificateExpiry(trustedCaCertificate, now, "Trusted CA");

                // Index 1 (when present before the anchor) is the subject's direct issuer; otherwise the subject
                // was issued directly by the trust anchor.
                return trustedCaIndex > 0 ? chain.ChainElements[1].Certificate : trustedCaCertificate;
            }
            catch (Exception ex) when (ex is not CertificateNotTrustedException
                and not CertificateExpiredException
                and not CertificateNotYetValidException)
            {
                throw new CertificateNotTrustedException(certificate, ex);
            }
        }

        /// <summary>
        /// Validates that the non-anchor intermediate CA certificates of the built certification path are not revoked.
        /// </summary>
        private static void ValidateIntermediateCertificatesNotRevoked(X509Chain builtChain,
            int trustedCaIndex,
            ICollection<X509Certificate2> trustedCaCertificates,
            ICollection<X509Certificate2> additionalIntermediateCertificates,
            TimeSpan revocationUrlRetrievalTimeout,
            DateTime now)
        {
            if (trustedCaIndex <= 1)
            {
                return; // The leaf chains directly to a trust anchor; there is no non-anchor intermediate to validate.
            }

            // Validate only the CA suffix of the built path, excluding the leaf at index 0, whose revocation policy
            // is role-specific and applied by the caller, and the trust anchor, which is excluded from the check
            // by treating it as the custom trusted root of the revocation chain.
            var firstIntermediateCertificate = builtChain.ChainElements[1].Certificate;

            using var revocationChain = new X509Chain();
            ConfigureIntermediateRevocationPolicy(revocationChain.ChainPolicy, revocationUrlRetrievalTimeout, now);

            foreach (var cert in trustedCaCertificates)
            {
                revocationChain.ChainPolicy.CustomTrustStore.Add(cert);
                revocationChain.ChainPolicy.ExtraStore.Add(cert);
            }
            foreach (var cert in additionalIntermediateCertificates ?? [])
            {
                revocationChain.ChainPolicy.ExtraStore.Add(cert);
            }

            if (!revocationChain.Build(firstIntermediateCertificate))
            {
                var offendingCertificate = GetOffendingCertificate(revocationChain, firstIntermediateCertificate);
                var errors = revocationChain.ChainStatus
                    .Select(x => string.Format(CultureInfo.InvariantCulture,
                        "{0} ({1})",
                        x.StatusInformation.Trim(),
                        x.Status))
                    .ToArray();
                var certificateErrorsString = errors.Length > 0
                    ? string.Join(Environment.NewLine, errors)
                    : "Unknown errors.";

                throw new CertificateNotTrustedException(offendingCertificate, certificateErrorsString);
            }
        }

        internal static void ConfigureIntermediateRevocationPolicy(X509ChainPolicy chainPolicy,
            TimeSpan revocationUrlRetrievalTimeout,
            DateTime now)
        {
            ArgumentNullException.ThrowIfNull(chainPolicy);
            RequirePositiveRevocationUrlRetrievalTimeout(revocationUrlRetrievalTimeout);

            // Revocation checking prefers OCSP and falls back to CRLs. Hard-fail is deliberately retained: an
            // intermediate whose revocation status cannot be established must not become part of a trusted path.
            chainPolicy.RevocationMode = X509RevocationMode.Online;
            chainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chainPolicy.VerificationTime = now;
            chainPolicy.UrlRetrievalTimeout = revocationUrlRetrievalTimeout;
            chainPolicy.DisableCertificateDownloads = true;
        }

        private static void RequirePositiveRevocationUrlRetrievalTimeout(TimeSpan revocationUrlRetrievalTimeout)
        {
            if (revocationUrlRetrievalTimeout <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(revocationUrlRetrievalTimeout),
                    "Intermediate certificate revocation URL retrieval timeout must be greater than zero");
            }
        }

        /// <summary>
        /// Returns the intermediate certificate that failed the revocation check, or the first intermediate when
        /// the failing certificate cannot be determined.
        /// </summary>
        private static X509Certificate2 GetOffendingCertificate(X509Chain revocationChain, X509Certificate2 firstIntermediateCertificate)
        {
            var offendingElement = revocationChain.ChainElements
                .Cast<X509ChainElement>()
                .FirstOrDefault(element => element.ChainElementStatus.Length > 0);
            return offendingElement?.Certificate ?? firstIntermediateCertificate;
        }

        /// <summary>
        /// Parses a base64-encoded certificate and returns an <see cref="X509Certificate2"/> instance.
        /// </summary>
        /// <param name="certificateInBase64">The base64-encoded certificate.</param>
        /// <param name="fieldName">The name of the field containing the certificate.</param>
        /// <returns>An <see cref="X509Certificate2"/> instance.</returns>
        /// <exception cref="AuthTokenParseException">Thrown when parsing fails.</exception>
        public static X509Certificate2 ParseCertificate(string certificateInBase64, string fieldName)
        {
            try
            {
                var certificateBytes = Convert.FromBase64String(certificateInBase64);
                return X509CertificateLoader.LoadCertificate(certificateBytes);
            }
            catch (Exception ex)
            {
                throw new AuthTokenParseException($"'{fieldName}' field must contain a valid certificate", ex);
            }
        }

        /// <summary>
        /// Parses a list of base64-encoded certificates and returns a list of <see cref="X509Certificate2"/> instances.
        /// </summary>
        /// <param name="certificatesInBase64">The base64-encoded certificates.</param>
        /// <param name="fieldName">The name of the field containing the certificates.</param>
        /// <returns>A list of <see cref="X509Certificate2"/> instances.</returns>
        /// <exception cref="AuthTokenParseException">Thrown when parsing fails.</exception>
        public static List<X509Certificate2> ParseCertificates(ICollection<string> certificatesInBase64, string fieldName)
        {
            if (certificatesInBase64 == null || certificatesInBase64.Count == 0)
            {
                return [];
            }
            return [.. certificatesInBase64.Select(certificate => ParseCertificate(certificate, fieldName))];
        }

        /// <summary>
        /// Gets the Common Name (CN) from the certificate's subject.
        /// </summary>
        public static string GetSubjectCn(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.CN);

        /// <summary>
        /// Gets the Serial Number from the certificate's subject.
        /// </summary>
        public static string GetSubjectIdCode(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.SerialNumber);

        /// <summary>
        /// Gets the Given Name from the certificate's subject.
        /// </summary>
        public static string GetSubjectGivenName(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.GivenName);

        /// <summary>
        /// Gets the Surname from the certificate's subject.
        /// </summary>
        public static string GetSubjectSurname(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.Surname);

        /// <summary>
        /// Gets the Country code from the certificate's subject.
        /// </summary>
        public static string GetSubjectCountryCode(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.C);

        private static string GetSubjectFieldValue(this X509Certificate certificate, DerObjectIdentifier oid)
        {
            var bcCertificate = DotNetUtilities.FromX509Certificate(certificate);
            var valueList = bcCertificate.SubjectDN.GetValueList(oid);
            return valueList.Count == 0 ? null : string.Join(' ', valueList.Cast<object>().Select(i => i.ToString()));
        }

        /// <summary>
        /// Gets the asymmetric public key from the certificate.
        /// </summary>
        public static AsymmetricAlgorithm GetAsymmetricPublicKey(this X509Certificate2 certificate2) =>
            certificate2.GetECDsaPublicKey() ?? (AsymmetricAlgorithm)certificate2.GetRSAPublicKey();

        /// <summary>
        /// Creates a <see cref="SecurityKey"/> from the asymmetric algorithm without caching signature providers.
        /// </summary>
        public static SecurityKey CreateSecurityKeyWithoutCachingSignatureProviders(this AsymmetricAlgorithm asymmetricAlgorithm)
        {
            if (asymmetricAlgorithm is ECDsa ecDsa)
            {
                return new ECDsaSecurityKey(ecDsa).AddCryptoProviderFactory();
            }
            return new RsaSecurityKey((RSA)asymmetricAlgorithm).AddCryptoProviderFactory();
        }

        private static SecurityKey AddCryptoProviderFactory(this SecurityKey securityKey)
        {
            securityKey.CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false };
            return securityKey;
        }
    }
}
