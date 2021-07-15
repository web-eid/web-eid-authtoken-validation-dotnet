namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when authentication token signature validation fails.
    /// </summary>
    [Serializable]
    public class TokenSignatureValidationException : TokenValidationException
    {
        public TokenSignatureValidationException(Exception innerException) : base("Token signature validation has failed:", innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected TokenSignatureValidationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
