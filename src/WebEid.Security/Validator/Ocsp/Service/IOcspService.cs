// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.Validator.Ocsp.Service
{
    using System;

    /// <summary>
    /// Represents an OCSP (Online Certificate Status Protocol) service.
    /// </summary>
    public interface IOcspService
    {
        /// <summary>
        /// Gets a value indicating whether the service supports including a nonce in requests.
        /// </summary>
        bool DoesSupportNonce { get; }

        /// <summary>
        /// Gets the access location (URI) of the OCSP service.
        /// </summary>
        Uri AccessLocation { get; }

        /// <summary>
        /// Validates the responder certificate based on current system time.
        /// </summary>
        /// <param name="responderCertificate">The responder's X.509 certificate.</param>
        /// <param name="now">Current system time.</param>
        void ValidateResponderCertificate(Org.BouncyCastle.X509.X509Certificate responderCertificate, DateTime now);
    }
}
