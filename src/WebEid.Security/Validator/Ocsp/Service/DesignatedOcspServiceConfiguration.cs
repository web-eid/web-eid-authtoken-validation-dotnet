// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
            OcspServiceAccessLocation = ocspServiceAccessLocation ??
                                             throw new ArgumentNullException(nameof(ocspServiceAccessLocation));
            ResponderCertificate =
                responderCertificate ?? throw new ArgumentNullException(nameof(responderCertificate));
            SupportedIssuers = [.. supportedCertificateIssuers.Select(i => i.SubjectDN)];
            DoesSupportNonce = doesSupportNonce;
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
            ArgumentNullException.ThrowIfNull(certificate);
            return SupportedIssuers.Contains(certificate.IssuerDN);
        }
    }
}
