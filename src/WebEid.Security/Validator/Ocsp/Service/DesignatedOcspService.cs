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
    using Exceptions;
    using Org.BouncyCastle.X509;
    using Util;

    /// <summary>
    /// An OCSP service that uses a single designated OCSP responder.
    /// </summary>
    internal class DesignatedOcspService : IOcspService
    {
        private readonly DesignatedOcspServiceConfiguration configuration;

        public DesignatedOcspService(DesignatedOcspServiceConfiguration configuration)
        {
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            this.DoesSupportNonce = this.configuration.DoesSupportNonce;
        }

        public bool DoesSupportNonce { get; }
        public Uri AccessLocation => this.configuration.OcspServiceAccessLocation;

        public bool SupportsIssuerOf(X509Certificate certificate) => this.configuration.SupportsIssuerOf(certificate);

        public void ValidateResponderCertificate(X509Certificate responderCertificate, DateTime producedAt)
        {
            // Certificate pinning is implemented simply by comparing the certificates or their public keys,
            // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
            if (!this.configuration.ResponderCertificate.Equals(responderCertificate))
            {
                throw new OcspCertificateException(
                    "Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate");
            }
            responderCertificate.ValidateCertificateExpiry(producedAt, "Designated OCSP responder");
        }
    }
}
