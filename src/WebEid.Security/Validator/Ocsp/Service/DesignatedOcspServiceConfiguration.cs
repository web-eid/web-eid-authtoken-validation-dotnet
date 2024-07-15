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
    using System.Linq;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.X509;

    /// <summary>
    /// Represents the configuration for a designated OCSP (Online Certificate Status Protocol) service.
    /// </summary>
    public sealed class DesignatedOcspServiceConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DesignatedOcspServiceConfiguration"/> class.
        /// </summary>
        /// <param name="ocspServiceAccessLocation">The URI of the OCSP service.</param>
        /// <param name="responderCertificate">The responder's X.509 certificate.</param>
        /// <param name="supportedCertificateIssuers">A list of supported certificate issuers.</param>
        /// <param name="doesSupportNonce">Indicates whether the service supports including a nonce in requests (default is true).</param>
        /// <exception cref="ArgumentNullException">Thrown when any of the parameters is null.</exception>
        public DesignatedOcspServiceConfiguration(Uri ocspServiceAccessLocation,
            X509Certificate responderCertificate,
            List<X509Certificate> supportedCertificateIssuers,
            bool doesSupportNonce = true)
        {
            this.OcspServiceAccessLocation = ocspServiceAccessLocation ??
                                             throw new ArgumentNullException(nameof(ocspServiceAccessLocation));
            this.ResponderCertificate =
                responderCertificate ?? throw new ArgumentNullException(nameof(responderCertificate));
            this.SupportedIssuers = supportedCertificateIssuers.Select(i => i.SubjectDN).ToList();
            this.DoesSupportNonce = doesSupportNonce;
            OcspResponseValidator.ValidateHasSigningExtension(responderCertificate);
        }

        /// <summary>
        /// Gets the URI of the OCSP service.
        /// </summary>
        public Uri OcspServiceAccessLocation { get; }

        /// <summary>
        /// Gets the responder's X.509 certificate.
        /// </summary>
        public X509Certificate ResponderCertificate { get; }

        /// <summary>
        /// Gets a list of supported certificate issuers.
        /// </summary>
        public List<X509Name> SupportedIssuers { get; }

        /// <summary>
        /// Gets a value indicating whether the service supports including a nonce in requests.
        /// </summary>
        public bool DoesSupportNonce { get; }

        /// <summary>
        /// Determines if the service supports the issuer of the specified certificate.
        /// </summary>
        /// <param name="certificate">The X.509 certificate to check.</param>
        /// <returns>True if the issuer is supported; otherwise, false.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the certificate is null.</exception>
        public bool SupportsIssuerOf(X509Certificate certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }
            return this.SupportedIssuers.Contains(certificate.IssuerDN);
        }
    }
}
