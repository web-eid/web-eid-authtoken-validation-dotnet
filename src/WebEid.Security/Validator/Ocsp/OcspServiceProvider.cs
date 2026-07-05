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
namespace WebEid.Security.Validator.Ocsp
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using Service;

    /// <summary>
    /// Provides an OCSP (Online Certificate Status Protocol) service provider based on configuration.
    /// </summary>
    /// <remarks>
    /// Initializes a new instance of the <see cref="OcspServiceProvider"/> class.
    /// </remarks>
    /// <param name="designatedOcspServiceConfiguration">The configuration for the designated OCSP service.</param>
    /// <param name="aiaOcspServiceConfiguration">The configuration for the AIA (Authority Information Access) OCSP service.</param>
    public class OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration)
    {
        private readonly DesignatedOcspService designatedOcspService = designatedOcspServiceConfiguration != null ? new DesignatedOcspService(designatedOcspServiceConfiguration) : null;
        private readonly AiaOcspServiceConfiguration aiaOcspServiceConfiguration = aiaOcspServiceConfiguration ??
                                               throw new ArgumentNullException(nameof(aiaOcspServiceConfiguration));

        /// <summary>
        /// Gets the appropriate OCSP service based on the certificate issuer.
        /// An AIA OCSP service instance is created for a single validation run of the given certificate.
        /// </summary>
        /// <param name="certificate">The X.509 certificate for which to retrieve the OCSP service.</param>
        /// <param name="certificateIssuerCertificate">The certificate that directly issued the subject certificate.</param>
        /// <param name="additionalIntermediateCertificates">Untrusted, token-supplied intermediate certificates that may be
        /// needed to build the OCSP responder's certification path to a trusted CA; may be empty.</param>
        /// <returns>An instance of <see cref="IOcspService"/>.</returns>
        public IOcspService GetService(Org.BouncyCastle.X509.X509Certificate certificate,
            X509Certificate2 certificateIssuerCertificate,
            ICollection<X509Certificate2> additionalIntermediateCertificates)
        {
            if (designatedOcspService != null && designatedOcspService.SupportsIssuerOf(certificate))
            {
                // The designated responder is pinned by equality, so the subject issuer and token-supplied
                // intermediate certificates are not needed for its validation.
                return designatedOcspService;
            }
            return new AiaOcspService(aiaOcspServiceConfiguration, certificate, certificateIssuerCertificate, additionalIntermediateCertificates);
        }
    }
}
