namespace WebEid.Security.Challenge
{
    using System;
    using WebEid.Security.Exceptions;
    using WebEid.Security.Util;

    /// <summary>
    /// Implementation of in-memory store for Challenge Nonce.
    /// </summary>
    public class InMemoryChallengeNonceStore : IChallengeNonceStore
    {
        private ChallengeNonce challengeNonce;

        /// <inheritdoc/>
        public ChallengeNonce GetAndRemove()
        {
            var tempChallengeNonce = this.challengeNonce;
            this.challengeNonce = null;

            if (tempChallengeNonce is null)
            {
                throw new ChallengeNonceNotFoundException();
            }
            if (DateTimeProvider.UtcNow >= tempChallengeNonce.ExpirationTime)
            {
                throw new ChallengeNonceExpiredException();
            }

            return tempChallengeNonce;
        }

        /// <inheritdoc/>
        [Obsolete]
        public ChallengeNonce GetAndRemoveImpl() => this.GetAndRemove();

        /// <inheritdoc/>
        public void Put(ChallengeNonce challengeNonce) => this.challengeNonce = challengeNonce;
    }
}
