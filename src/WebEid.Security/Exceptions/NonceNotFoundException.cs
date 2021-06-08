namespace WebEID.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the nonce was not found in the cache.
    /// </summary>
    [Serializable]
    public class NonceNotFoundException : TokenValidationException
    {
        public NonceNotFoundException() : base("Nonce was not found in cache")
        {
        }

        protected NonceNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
