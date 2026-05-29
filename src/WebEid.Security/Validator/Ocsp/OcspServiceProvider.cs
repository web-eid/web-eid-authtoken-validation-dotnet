// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
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
