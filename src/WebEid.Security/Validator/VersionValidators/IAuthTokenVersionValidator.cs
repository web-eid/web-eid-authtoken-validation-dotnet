// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Validator.VersionValidators
{
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using AuthToken;
    using Exceptions;

    /// <summary>
    /// Version-specific Web eID authentication token validator.
    /// </summary>
    public interface IAuthTokenVersionValidator
    {
        /// <summary>
        /// Whether this validator supports the specified token format,
        /// e.g. "web-eid:1.0" or "web-eid:1.1".
        /// </summary>
        public bool Supports(string format);

        /// <summary>
        /// Validates the Web eID authentication token according to the
        /// version-specific rules and returns the authenticated user's certificate.
        /// </summary>
        /// <param name="authToken">Parsed Web eID authentication token.</param>
        /// <param name="currentChallengeNonce">Server-issued challenge nonce.</param>
        /// <returns>Validated authentication certificate.</returns>
        /// <exception cref="AuthTokenException">If validation fails.</exception>
        public Task<X509Certificate2> Validate(WebEidAuthToken authToken, string currentChallengeNonce);
    }
}
