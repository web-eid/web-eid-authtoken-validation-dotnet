namespace WebEid.Security.Challenge
{
    using System;
    using System.Security.Cryptography;
    using Util;

    public sealed class ChallengeNonceGenerator : IChallengeNonceGenerator
    {
        private readonly IChallengeNonceStore store;
        private readonly RandomNumberGenerator randomNumberGenerator;

        /// <summary>
        /// Initializes a new instance of NonceGenerator
        /// </summary>
        /// <param name="store">The store where generated nonce values will be stored.</param>
        /// <param name="randomNumberGenerator">The source of random bytes for the nonce.</param>
        public ChallengeNonceGenerator(RandomNumberGenerator randomNumberGenerator, IChallengeNonceStore store)
        {
            this.randomNumberGenerator = randomNumberGenerator ?? throw new ArgumentNullException(nameof(randomNumberGenerator), "Secure random generator must not be null");
            this.store = store ?? throw new ArgumentNullException(nameof(store), "Challenge nonce store must not be null");
        }

        /// <summary>
        /// Generates a cryptographic nonce, a large random number that can be used only once,
        /// and stores it in a ChallengeNonceStore.
        /// </summary>
        /// <param name="ttl">Challenge nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired.</param>
        /// <returns>a ChallengeNonce that contains the Base64-encoded nonce and its expiry time</returns>
        public ChallengeNonce GenerateAndStoreNonce(TimeSpan ttl)
        {
            if (ttl.IsNegativeOrZero())
            {
                throw new ArgumentOutOfRangeException(nameof(ttl), "Nonce time-to-live duration must be greater than zero");
            }
            var nonceBytes = new byte[IChallengeNonceGenerator.NonceLength];
            this.randomNumberGenerator.GetBytes(nonceBytes);
            var base64StringNonce = Convert.ToBase64String(nonceBytes);
            var expirationTime = DateTimeProvider.UtcNow.Add(ttl);
            var challengeNonce = new ChallengeNonce(base64StringNonce, expirationTime);
            this.store.Put(challengeNonce);
            return challengeNonce;
        }
    }
}
