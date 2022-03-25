namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the nonce has expired.
    /// </summary>
    [Serializable]
    public class ChallengeNonceExpiredException : AuthTokenException
    {
        public ChallengeNonceExpiredException() : base("Nonce has expired")
        {
        }

        [ExcludeFromCodeCoverage]
        protected ChallengeNonceExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
