namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the nonce was not found in the cache.
    /// </summary>
    [Serializable]
    public class ChallengeNonceNotFoundException : AuthTokenException
    {
        public ChallengeNonceNotFoundException() : base("Nonce was not found in cache")
        {
        }

        [ExcludeFromCodeCoverage]
        protected ChallengeNonceNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
