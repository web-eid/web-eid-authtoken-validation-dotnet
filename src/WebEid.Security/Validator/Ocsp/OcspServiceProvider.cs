// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Validator.Ocsp
{
    using System;
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
        /// </summary>
        /// <param name="certificate">The X.509 certificate for which to retrieve the OCSP service.</param>
        /// <returns>An instance of <see cref="IOcspService"/>.</returns>
        public IOcspService GetService(Org.BouncyCastle.X509.X509Certificate certificate = null)
        {
            if (designatedOcspService != null && designatedOcspService.SupportsIssuerOf(certificate))
            {
                return designatedOcspService;
            }
            return new AiaOcspService(aiaOcspServiceConfiguration, certificate);
        }
    }
}
