// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.AuthToken
{
    /// <summary>
    /// Represents a signature algorithm supported by the authentication token,
    /// including its cryptographic algorithm, hash function, and padding scheme.
    /// </summary>
    public class SupportedSignatureAlgorithm
    {
        /// <summary>
        /// The cryptographic algorithm, e.g. "RSA" or "ECDSA".
        /// </summary>
        public string CryptoAlgorithm { get; set; }
        /// <summary>
        /// The hash function, e.g. "SHA-256".
        /// </summary>
        public string HashFunction { get; set; }
        /// <summary>
        /// The padding scheme, e.g. "PKCS1" or "PSS".
        /// </summary>
        public string PaddingScheme { get; set; }
    }
}
