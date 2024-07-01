/*
 * Copyright © 2020-2024 Estonian Information System Authority
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
namespace WebEid.Security.Challenge
{
    using System;
    using System.Security.Cryptography;
    using Util;

    /// <summary>
    /// Generates and stores cryptographic nonces for the Web eID system.
    /// </summary>
    public sealed class ChallengeNonceGenerator : IChallengeNonceGenerator
    {
        private readonly IChallengeNonceStore store;
        private readonly RandomNumberGenerator randomNumberGenerator;

        /// <summary>
        /// Initializes a new instance of the <see cref="ChallengeNonceGenerator"/> class.
        /// </summary>
        /// <param name="randomNumberGenerator">The source of random bytes for generating nonces.</param>
        /// <param name="store">The store where generated nonce values will be stored.</param>
        /// <exception cref="ArgumentNullException">Thrown when either randomNumberGenerator or store is null.</exception>
        public ChallengeNonceGenerator(RandomNumberGenerator randomNumberGenerator, IChallengeNonceStore store)
        {
            this.randomNumberGenerator = randomNumberGenerator ?? throw new ArgumentNullException(nameof(randomNumberGenerator), "Secure random generator must not be null");
            this.store = store ?? throw new ArgumentNullException(nameof(store), "Challenge nonce store must not be null");
        }

        /// <summary>
        /// Generates a cryptographic nonce, a large random number that can be used only once,
        /// and stores it in the specified ChallengeNonceStore.
        /// </summary>
        /// <param name="ttl">The time-to-live duration for the nonce. When the time-to-live passes, the nonce is considered expired.</param>
        /// <returns>A ChallengeNonce that contains the Base64-encoded nonce and its expiry time.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the provided ttl is negative or zero.</exception>
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
