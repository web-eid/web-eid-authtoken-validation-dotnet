namespace WebEID.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the nonce has expired.
    /// </summary>
    [Serializable]
    public class NonceExpiredException : TokenValidationException
    {
        public NonceExpiredException() : base("Nonce has expired")
        {
        }


        protected NonceExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
