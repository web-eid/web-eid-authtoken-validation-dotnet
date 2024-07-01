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
    using Service;

    /// <summary>
    /// Provides an OCSP (Online Certificate Status Protocol) service provider based on configuration.
    /// </summary>
    public class OcspServiceProvider
    {
        private readonly DesignatedOcspService designatedOcspService;
        private readonly AiaOcspServiceConfiguration aiaOcspServiceConfiguration;

        /// <summary>
        /// Initializes a new instance of the <see cref="OcspServiceProvider"/> class.
        /// </summary>
        /// <param name="designatedOcspServiceConfiguration">The configuration for the designated OCSP service.</param>
        /// <param name="aiaOcspServiceConfiguration">The configuration for the AIA (Authority Information Access) OCSP service.</param>
        public OcspServiceProvider(DesignatedOcspServiceConfiguration designatedOcspServiceConfiguration, AiaOcspServiceConfiguration aiaOcspServiceConfiguration)
        {
            this.designatedOcspService = designatedOcspServiceConfiguration != null ? new DesignatedOcspService(designatedOcspServiceConfiguration) : null;
            this.aiaOcspServiceConfiguration = aiaOcspServiceConfiguration ??
                                               throw new ArgumentNullException(nameof(aiaOcspServiceConfiguration));
        }

        /// <summary>
        /// Gets the appropriate OCSP service based on the certificate issuer.
        /// </summary>
        /// <param name="certificate">The X.509 certificate for which to retrieve the OCSP service.</param>
        /// <returns>An instance of <see cref="IOcspService"/>.</returns>
        public IOcspService GetService(Org.BouncyCastle.X509.X509Certificate certificate = null)
        {
            if (this.designatedOcspService != null && this.designatedOcspService.SupportsIssuerOf(certificate))
            {
                return this.designatedOcspService;
            }
            return new AiaOcspService(this.aiaOcspServiceConfiguration, certificate);
        }
    }
}
