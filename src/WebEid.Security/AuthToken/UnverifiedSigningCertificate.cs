// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.AuthToken
{
    using System.Collections.Generic;

    /// <summary>
    /// Unverified signing certificate and its supported signature algorithms.
    /// </summary>
    public class UnverifiedSigningCertificate
    {
        /// <summary>
        /// The base64-encoded signing certificate (DER).
        /// </summary>
        public string Certificate { get; set; }
        /// <summary>
        /// The base64-encoded DER-encoded intermediate CA certificates that may be needed to build the
        /// signing certificate's certification path to a trusted CA.
        /// </summary>
        public List<string> IntermediateCertificates { get; set; }
        /// <summary>
        /// List of supported signature algorithms from the card.
        /// </summary>
        public List<SupportedSignatureAlgorithm> SupportedSignatureAlgorithms { get; set; }
    }
}
