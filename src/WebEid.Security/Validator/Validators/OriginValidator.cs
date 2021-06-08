namespace WebEID.Security.Validator.Validators
{
    using System;
    using Exceptions;
    using Microsoft.Extensions.Logging;

    public sealed class OriginValidator
    {

        private readonly Uri expectedOrigin;
        private readonly ILogger logger;

        public OriginValidator(Uri expectedOrigin, ILogger logger)
        {
            this.expectedOrigin = expectedOrigin;
            this.logger = logger;
        }

        /// <summary>
        /// Validates that the origin from the authentication token matches with the configured site origin.
        /// Throws TokenValidationException when origins don't match.
        /// </summary>
        /// <param name="actualTokenData">authentication token data that contains the origin from authentication token</param>
        public void ValidateOrigin(AuthTokenValidatorData actualTokenData)
        {
            try
            {
                var originUri = new Uri(actualTokenData.Origin);

                ValidateIsOriginURL(originUri);

                if (!this.expectedOrigin.Equals(originUri))
                {
                    throw new OriginMismatchException();
                }

                this.logger?.LogDebug("Origin is equal to expected origin.");

            }
            catch (ArgumentException e)
            {
                throw new OriginMismatchException(e);
            }
        }

        /// <summary>
        /// Validates that the given URI is an origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
        /// in the form of <code> <scheme> "://" <hostname> [ ":" <port> ]</code>.
        // Throws IllegalArgumentException when the URI is not in the form of origin URL
        /// </summary>
        /// <param name="uri">URI with origin URL</param>
        public static void ValidateIsOriginURL(Uri uri)
        {
            try
            {
                // 1. Verify that the URI can be converted to absolute URL.
                if (!uri.IsAbsoluteUri)
                {
                    throw new ArgumentException("Provided URI is not a valid URL");
                }
                // 2. Verify that the URI contains only HTTPS scheme, host and optional port components.
                if (!new Uri($"https://{uri.Host}:{uri.Port}").Equals(uri))
                {
                    throw new ArgumentException("Origin URI must only contain the HTTPS scheme, host and optional port component");
                }
            }
            catch (InvalidOperationException e)
            {
                throw new ArgumentException("Provided URI is not a valid URL", e);
            }
        }
    }
}
