namespace WebEID.Security.Validator.Validators
{
    using System;
    using Cache;
    using Exceptions;
    using Microsoft.Extensions.Logging;
    using Nonce;

    public sealed class NonceValidator : IValidator
    {
        private readonly ICache<DateTime?> cache;
        private readonly ILogger logger;

        public NonceValidator(ICache<DateTime?> cache, ILogger logger)
        {
            this.cache = cache;
            this.logger = logger;
        }

        /// <summary>
        /// Validates that the nonce from the authentication token has the correct length, exists in cache and has not expired.
        /// </summary>
        /// <param name="actualTokenData">authentication token data that contains the nonce</param>
        /// <exception cref="TokenValidationException">when the nonce in the token does not meet the requirements</exception>
        public void Validate(AuthTokenValidatorData actualTokenData)
        {
            var nonceExpirationTime = this.cache.GetAndRemove(actualTokenData.Nonce);
            if (nonceExpirationTime == null)
            {
                throw new NonceNotFoundException();
            }
            if (actualTokenData.Nonce.Length < INonceGenerator.NonceLength)
            {
                throw new TokenParseException($"Nonce is shorter than the required length of {INonceGenerator.NonceLength}");
            }
            if (nonceExpirationTime < DateTime.Now)
            {
                throw new NonceExpiredException();
            }
            this.logger?.LogDebug("Nonce was found and has not expired.");
        }
    }
}
