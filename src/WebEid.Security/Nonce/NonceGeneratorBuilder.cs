namespace WebEID.Security.Nonce
{
    using System;
    using System.Security.Cryptography;
    using Cache;

    public class NonceGeneratorBuilder
    {
        private ICache<DateTime> cache;
        private RandomNumberGenerator randomNumberGenerator;
        private TimeSpan ttl = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Sets the cache where generated nonce values will be stored.
        /// The key of the cache is the Base64-encoded nonce and the value is the nonce expiry time
        /// </summary>
        /// <param name="nonceCache">cache nonce cache</param>
        /// <returns></returns>
        public NonceGeneratorBuilder WithNonceCache(ICache<DateTime> nonceCache)
        {
            this.cache = nonceCache;
            return this;
        }

        /// <summary>
        /// Sets the source of random bytes for the nonce.
        /// </summary>
        /// <param name="rndGenerator">Secure random generator</param>
        /// <returns>current builder instance</returns>
        public NonceGeneratorBuilder WithSecureRandom(RandomNumberGenerator rndGenerator)
        {
            this.randomNumberGenerator = rndGenerator;
            return this;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="duration"></param>
        /// <returns>current builder instance</returns>
        public NonceGeneratorBuilder WithNonceTtl(TimeSpan duration)
        {
            this.ttl = duration;
            return this;
        }

        /// <summary>
        /// Builds the new nonce generator instance.
        /// </summary>
        /// <returns>New nonce generator instance</returns>
        public INonceGenerator Build()
        {
            return new NonceGenerator(this.randomNumberGenerator, this.cache, this.ttl);
        }
    }
}
