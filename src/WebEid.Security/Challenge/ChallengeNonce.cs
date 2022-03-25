namespace WebEid.Security.Challenge
{
    using System;

    public class ChallengeNonce
    {
        public string Base64EncodedNonce { get; private set; }
        public DateTime ExpirationTime { get; private set; }

        public ChallengeNonce(string base64EncodedNonce, DateTime expirationTime)
        {
            this.Base64EncodedNonce = base64EncodedNonce ?? throw new ArgumentNullException(nameof(base64EncodedNonce));
            this.ExpirationTime = expirationTime;
        }
    }
}
