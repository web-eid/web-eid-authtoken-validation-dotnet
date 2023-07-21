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
namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using System.Globalization;
    using Exceptions;
    using Org.BouncyCastle.Ocsp;
    using Org.BouncyCastle.Security.Certificates;
    using Org.BouncyCastle.Utilities.Date;
    using Org.BouncyCastle.X509;

    internal static class OcspResponseValidator
    {
        /// <summary>
        /// Indicates that a X.509 Certificates corresponding private key may be used by an authority to sign OCSP responses.
        /// https://oidref.com/1.3.6.1.5.5.7.3.9
        /// </summary>
        private const string OidOcspSigning = "1.3.6.1.5.5.7.3.9";

        private static readonly TimeSpan AllowedTimeSkew = TimeSpan.FromMinutes(15);

        public static void ValidateHasSigningExtension(X509Certificate certificate)
        {
            try
            {
                var extendedKeyUsage = certificate.GetExtendedKeyUsage();
                if (extendedKeyUsage == null || !extendedKeyUsage.Contains(OidOcspSigning))
                {
                    throw new OcspCertificateException(
                        $"Certificate {certificate.SubjectDN} does not contain the key usage extension for OCSP response signing");
                }
            }
            catch (CertificateParsingException e)
            {
                throw new OcspCertificateException($"Certificate parsing failed: {e.Message}");
            }
        }

        public static void ValidateResponseSignature(BasicOcspResp response, X509Certificate certificate)
        {
            if (!response.Verify(certificate.GetPublicKey()))
            {
                throw new UserCertificateOcspCheckFailedException("OCSP response signature is invalid");
            }
        }

        public static void ValidateCertificateStatusUpdateTime(SingleResp certStatusResponse, DateTime producedAt)
        {
            ValidateCertificateStatusUpdateTime(certStatusResponse.ThisUpdate,
                certStatusResponse.NextUpdate?.Value,
                producedAt);
        }

        internal static void ValidateCertificateStatusUpdateTime(DateTime validFrom,
            DateTime? validTo,
            DateTime producedAt)
        {
            // From RFC 2560, https://www.ietf.org/rfc/rfc2560.txt:
            // 4.2.2.  Notes on OCSP Responses
            // 4.2.2.1.  Time
            //   Responses whose nextUpdate value is earlier than
            //   the local system time value SHOULD be considered unreliable.
            //   Responses whose thisUpdate time is later than the local system time
            //   SHOULD be considered unreliable.
            //   If nextUpdate is not set, the responder is indicating that newer
            //   revocation information is available all the time.
            var notAllowedBefore = producedAt.Add(AllowedTimeSkew.Negate());
            var notAllowedAfter = producedAt.Add(AllowedTimeSkew);
            if (notAllowedAfter < validFrom || notAllowedBefore > (validTo ?? validFrom))
            {
                throw new UserCertificateOcspCheckFailedException(
                    "Certificate status update time check failed: "
                    + $"notAllowedBefore: {ToUtcString(notAllowedBefore)}, "
                    + $"notAllowedAfter: {ToUtcString(notAllowedAfter)}, "
                    + $"thisUpdate: {ToUtcString(validFrom)}, "
                    + $"nextUpdate: {ToUtcString(validTo)}");
            }
        }

        public static void ValidateOcspResponseStatus(SingleResp certStatusResponse)
        {
            var status = certStatusResponse.GetCertStatus();
            if (status == CertificateStatus.Good)
            {
                return;
            }

            if (status is RevokedStatus revokedStatus)
            {
                throw revokedStatus.HasRevocationReason
                    ? new UserCertificateRevokedException(
                        $"Revocation reason: {revokedStatus.RevocationReason}")
                    : new UserCertificateRevokedException();
            }

            if (status is UnknownStatus)
            {
                throw new UserCertificateRevokedException("Unknown status");
            }

            throw new UserCertificateRevokedException(
                "Status is neither good, revoked nor unknown");
        }

        private static string ToUtcString(this DateTime? date)
        {
            return date?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture) ?? "null";
        }
    }

    internal interface ISingleResp
    {
        DateTime ThisUpdate { get; }
        DateTimeObject NextUpdate { get; }
    }
}
