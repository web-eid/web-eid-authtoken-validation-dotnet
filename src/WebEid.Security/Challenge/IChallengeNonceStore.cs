namespace WebEid.Security.Challenge
{
    using WebEid.Security.Exceptions;
    using WebEid.Security.Util;

    public interface IChallengeNonceStore
    {
        void Put(ChallengeNonce challengeNonce);

        ChallengeNonce GetAndRemoveImpl();

        ChallengeNonce GetAndRemove()
        {
            var challengeNonce = this.GetAndRemoveImpl();
            if (challengeNonce == null)
            {
                throw new ChallengeNonceNotFoundException();
            }
            if (DateTimeProvider.UtcNow >= challengeNonce.ExpirationTime)
            {
                throw new ChallengeNonceExpiredException();
            }
            return challengeNonce;
        }
    }
}
