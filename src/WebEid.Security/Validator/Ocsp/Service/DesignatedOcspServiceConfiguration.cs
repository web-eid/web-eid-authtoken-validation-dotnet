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
namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.X509;

    public sealed class DesignatedOcspServiceConfiguration
    {
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

        public Uri OcspServiceAccessLocation { get; }
        public X509Certificate ResponderCertificate { get; }
        public List<X509Name> SupportedIssuers { get; }
        public bool DoesSupportNonce { get; }

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
