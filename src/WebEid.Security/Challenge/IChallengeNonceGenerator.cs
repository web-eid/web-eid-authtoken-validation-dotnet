namespace WebEid.Security.Challenge
{
    using System;

    /// <summary>
    /// Generates challenge nonces, cryptographically strong random bytestrings that must be used only once.
    /// </summary>
    public interface IChallengeNonceGenerator
    {
        const int NonceLength = 32;

        /// <summary>
        /// Generates a cryptographic nonce, a large random number that can be used only once,
        /// and stores it in a ChallengeNonceStore.
        /// </summary>
        /// <param name="ttl">Challenge nonce time-to-live duration. When the time-to-live passes, the nonce is considered to be expired.</param>
        /// <returns>a ChallengeNonce that contains the Base64-encoded nonce and its expiry time</returns>
        ChallengeNonce GenerateAndStoreNonce(TimeSpan ttl);
    }
}
