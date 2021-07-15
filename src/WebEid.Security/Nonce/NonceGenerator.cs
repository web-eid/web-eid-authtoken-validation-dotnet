namespace WebEid.Security.Nonce
{
    using System;
    using System.Security.Cryptography;
    using Cache;
    using Util;

    internal sealed class NonceGenerator : INonceGenerator
    {
        private readonly ICache<DateTime> cache;
        private readonly RandomNumberGenerator randomNumberGenerator;
        private readonly TimeSpan ttl;

        /// <summary>
        /// Initializes a new instance of NonceGenerator
        /// </summary>
        /// <param name="cache">The cache where generated nonce values will be stored. The key of the cache is the Base64-encoded nonce and the value is the nonce expiry time.</param>
        /// <param name="randomNumberGenerator">The source of random bytes for the nonce.</param>
        /// <param name="ttl">Override default nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired.</param>
        public NonceGenerator(RandomNumberGenerator randomNumberGenerator, ICache<DateTime> cache, TimeSpan ttl)
        {
            this.randomNumberGenerator = randomNumberGenerator ?? throw new ArgumentNullException(nameof(randomNumberGenerator), "Secure random generator must not be null");
            this.cache = cache ?? throw new ArgumentNullException(nameof(cache), "Cache must not be null");

            if (ttl.IsNegativeOrZero())
            {
                throw new ArgumentOutOfRangeException(nameof(ttl), "Nonce time-to-live duration must be greater than zero");
            }
            this.ttl = ttl;
        }

        public string GenerateAndStoreNonce()
        {
            var nonceBytes = new byte[INonceGenerator.NonceLength];
            this.randomNumberGenerator.GetBytes(nonceBytes);
            var expirationTime = DateTime.UtcNow.Add(this.ttl);
            var base64StringNonce = Convert.ToBase64String(nonceBytes);
            this.cache.Put(base64StringNonce, expirationTime);
            return base64StringNonce;
        }
    }
}
