namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
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

        [ExcludeFromCodeCoverage]
        protected NonceExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
