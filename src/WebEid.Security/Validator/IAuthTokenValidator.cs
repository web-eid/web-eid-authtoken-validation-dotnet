// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace WebEid.Security.Validator
{
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using AuthToken;
    using Exceptions;
    using Util;

    /// <summary>
    /// Interface for validating Web eID authentication tokens.
    /// </summary>
    public interface IAuthTokenValidator
    {
        /// <summary>
        /// Parses the Web eID authentication token signed by the subject.
        /// </summary>
        /// <param name="authToken">the Web eID authentication token string, in Web eID JSON format</param>
        /// <returns>the Web eID authentication token</returns>
        /// <exception cref="AuthTokenException">When parsing fails</exception>
        public WebEidAuthToken Parse(string authToken);

        /// <summary>
        /// Validates the Web eID authentication token signed by the subject and returns
        /// the subject certificate that can be used for retrieving information about the subject.
        /// See <see cref="X509CertificateExtensions"/> for convenience methods for retrieving user
        /// information from the certificate.
        /// </summary>
        /// <param name="authToken">the Web eID authentication token, in Web eID custom format</param>
        /// <param name="currentChallengeNonce"></param>
        /// <returns>validated subject certificate</returns>
        /// <exception cref="AuthTokenException">When validation fails</exception>
        public Task<X509Certificate2> Validate(WebEidAuthToken authToken, string currentChallengeNonce);
    }
}
