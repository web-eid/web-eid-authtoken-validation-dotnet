// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT
namespace WebEid.Security.AuthToken
{
    /// <summary>
    /// The Web eID authentication token
    /// </summary>
    public class WebEidAuthToken
    {
        /// <summary>
        /// The signature algorithm used to produce the signature.
        /// The allowed values are the algorithms specified in JWA RFC sections 3.3, 3.4 and 3.5
        /// </summary>
        public string Algorithm { get; set; }
        /// <summary>
        /// The type identifier and version of the token format separated by a colon character ':', web-eid:1.0 for example.
        /// The version number consists of the major and minor number separated by a dot.
        /// </summary>
        public string Format { get; set; }
        /// <summary>
        /// The base64-encoded signature of the token.
        /// </summary>
        public string Signature { get; set; }
        /// <summary>
        /// The base64-encoded DER-encoded authentication certificate of the eID user.
        /// </summary>
        public string UnverifiedCertificate { get; set; }
    }
}
