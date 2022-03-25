namespace WebEid.Security.Tests.Nonce
{
    using WebEid.Security.Challenge;

    internal class InMemoryChallengeNonceStore : IChallengeNonceStore
    {
        private ChallengeNonce challengeNonce;

        public ChallengeNonce GetAndRemoveImpl()
        {
            var result = this.challengeNonce;
            this.challengeNonce = null;
            return result;
        }

        public void Put(ChallengeNonce challengeNonce) => this.challengeNonce = challengeNonce;
    }
}
