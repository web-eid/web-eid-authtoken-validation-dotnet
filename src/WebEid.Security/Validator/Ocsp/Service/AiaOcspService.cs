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
namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using Exceptions;
    using Org.BouncyCastle.Security;
    using Util;

    /// <summary>
    /// An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
    /// </summary>
    internal class AiaOcspService : IOcspService
    {
        private readonly List<X509Certificate2> trustedCaCertificates;

        public AiaOcspService(AiaOcspServiceConfiguration configuration,
            Org.BouncyCastle.X509.X509Certificate certificate)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }
            this.AccessLocation = this.GetOcspAiaUrlFromCertificate(certificate);
            this.trustedCaCertificates = configuration.TrustedCaCertificates;
            this.DoesSupportNonce = !configuration.NonceDisabledOcspUrls.Contains(this.AccessLocation);
        }

        public bool DoesSupportNonce { get; }
        public Uri AccessLocation { get; }

        private Uri GetOcspAiaUrlFromCertificate(Org.BouncyCastle.X509.X509Certificate certificate)
        {
            if (certificate == null)
            { throw new ArgumentNullException(nameof(certificate)); }

            return certificate.GetOcspUri() ??
                   throw new UserCertificateOcspCheckFailedException("Getting the AIA OCSP responder field " +
                                                                     "from the certificate failed");
        }

        public void ValidateResponderCertificate(Org.BouncyCastle.X509.X509Certificate responderCertificate, DateTime producedAt)
        {
            try
            {
                responderCertificate.ValidateCertificateExpiry(producedAt, "AIA OCSP responder");
                // Trusted certificates validity has been already verified in ValidateCertificateExpiry().
                OcspResponseValidator.ValidateHasSigningExtension(responderCertificate);
                _ = new X509Certificate2(DotNetUtilities.ToX509Certificate(responderCertificate))
                    .ValidateIsValidAndSignedByTrustedCa(this.trustedCaCertificates);
            }
            catch (Exception ex) when (!(ex is CertificateNotTrustedException))
            {
                throw new OcspCertificateException("Invalid certificate", ex);
            }
        }
    }
}
