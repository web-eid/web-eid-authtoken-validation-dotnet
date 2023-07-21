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
    using Org.BouncyCastle.Security.Certificates;

    public static class X509CertificateExtensions
    {
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
                throw new Exceptions.CertificateNotYetValidException(subject, e);
            }
            catch (Org.BouncyCastle.Security.Certificates.CertificateExpiredException e)
            {
                throw new Exceptions.CertificateExpiredException(subject, e);
            }
        }

        public static X509Certificate2 ValidateIsSignedByTrustedCa(this X509Certificate2 certificate, ICollection<X509Certificate2> trustedCaCertificates)
        {
            var chain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot,
                    VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority,
                    VerificationTime = DateTimeProvider.UtcNow,
                    UrlRetrievalTimeout = TimeSpan.Zero
                }
            };
            foreach (var cert in trustedCaCertificates)
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

                var chainElement = chain.ChainElements
                    .Cast<X509ChainElement>()
                    .FirstOrDefault(x => trustedCaCertificates.Any(ca =>
                        x.Certificate.Thumbprint == ca.Thumbprint));
                if (chainElement?.Certificate == null)
                {
                    throw new CertificateNotTrustedException(certificate);
                }

                return chainElement.Certificate;
            }
            catch (Exception ex) when (!(ex is CertificateNotTrustedException))
            {
                throw new CertificateNotTrustedException(certificate, ex);
            }
        }

        public static X509Certificate2 ParseCertificate(string certificateInBase64, string fieldName)
        {
            try
            {
                var certificateBytes = Convert.FromBase64String(certificateInBase64);
                return new X509Certificate2(certificateBytes);
            }
            catch (Exception ex)
            {
                throw new AuthTokenParseException($"'{fieldName}' field must contain a valid certificate", ex);
            }
        }

        public static string GetSubjectCn(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.CN);

        public static string GetSubjectIdCode(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.SerialNumber);

        public static string GetSubjectGivenName(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.GivenName);

        public static string GetSubjectSurname(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.Surname);

        public static string GetSubjectCountryCode(this X509Certificate certificate) =>
            certificate.GetSubjectFieldValue(X509Name.C);

        private static string GetSubjectFieldValue(this X509Certificate certificate, DerObjectIdentifier oid)
        {
            var bcCertificate = DotNetUtilities.FromX509Certificate(certificate);
            var valueList = bcCertificate.SubjectDN.GetValueList(oid);
            if (valueList.Count == 0 || valueList[0] is null)
            {
                throw new Exceptions.CertificateEncodingException(oid.ToString());
            }
            else
            {
                return valueList[0].ToString();
            }
        }

        public static AsymmetricAlgorithm GetAsymmetricPublicKey(this X509Certificate2 certificate2) =>
            certificate2.GetECDsaPublicKey() ?? (AsymmetricAlgorithm)certificate2.GetRSAPublicKey();

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
