/*
 * Copyright © 2020-2025 Estonian Information System Authority
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
namespace WebEid.Security.Validator
{
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Util;
    using AuthToken;

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
        WebEidAuthToken Parse(string authToken);

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
        Task<X509Certificate2> Validate(WebEidAuthToken authToken, string currentChallengeNonce);
    }
}
