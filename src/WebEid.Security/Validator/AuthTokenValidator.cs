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
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Newtonsoft.Json;
    using AuthToken;
    using VersionValidators;

    /// <summary>
    /// Represents the configuration for validating authentication tokens (JWTs) in the Web eID system.
    /// </summary>
    public sealed class AuthTokenValidator : IAuthTokenValidator
    {
        private readonly ILogger logger;
        private readonly AuthTokenVersionValidatorFactory versionValidatorFactory;

        // Use human-readable meaningful names for token length limits.
        private const int TokenMinLength = 100;
        private const int TokenMaxLength = 10000;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthTokenValidator"/> class.
        /// </summary>
        /// <param name="configuration">The configuration for token validation.</param>
        /// <param name="logger">The logger for capturing log messages (optional).</param>
        public AuthTokenValidator(AuthTokenValidationConfiguration configuration, ILogger logger = null)
        {
            this.logger = logger;
            var validationConfig = configuration.Copy();

            versionValidatorFactory =
                AuthTokenVersionValidatorFactory.Create(validationConfig, null, this.logger);
        }

        /// <summary>
        /// Parses the authentication token (JWT) and returns a <see cref="WebEidAuthToken"/> instance.
        /// </summary>
        /// <param name="authToken">The authentication token to parse.</param>
        /// <returns>A parsed <see cref="WebEidAuthToken"/> instance.</returns>
        public WebEidAuthToken Parse(string authToken)
        {
            logger?.LogInformation("Starting token parsing");

            try
            {
                ValidateTokenLength(authToken);
                return ParseToken(authToken);
            }
            catch (Exception ex)
            {
                // Generally "log and rethrow" is an anti-pattern, but it fits with the surrounding logging style.
                logger?.LogWarning(ex, "Token parsing was interrupted");
                throw;
            }
        }

        /// <summary>
        /// Validates the authentication token (JWT) and returns the user certificate.
        /// </summary>
        /// <param name="authToken">The authentication token to validate.</param>
        /// <param name="currentChallengeNonce">The current challenge nonce value.</param>
        /// <returns>A task representing the validation result with the user certificate.</returns>
        public Task<X509Certificate2> Validate(WebEidAuthToken authToken, string currentChallengeNonce)
        {
            logger?.LogInformation("Starting token validation");

            try
            {
                var validator = versionValidatorFactory.GetValidatorFor(authToken.Format);
                return validator.Validate(authToken, currentChallengeNonce);
            }
            catch (Exception ex)
            {
                logger?.LogWarning(ex, "Token validation was interrupted");
                throw;
            }
        }

        private static void ValidateTokenLength(string authToken)
        {
            if (authToken == null || authToken.Length < TokenMinLength)
            {
                throw new AuthTokenParseException("Auth token is null or too short");
            }
            if (authToken.Length > TokenMaxLength)
            {
                throw new AuthTokenParseException("Auth token is too long");
            }
        }

        private static WebEidAuthToken ParseToken(string authToken)
        {
            try
            {
                return JsonConvert.DeserializeObject<WebEidAuthToken>(authToken)
                       ?? throw new AuthTokenParseException("Web eID authentication token is null");
            }
            catch (JsonException ex)
            {
                throw new AuthTokenParseException("Error parsing Web eID authentication token", ex);
            }
        }
    }
}
