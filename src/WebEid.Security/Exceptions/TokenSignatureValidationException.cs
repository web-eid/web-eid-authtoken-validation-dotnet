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
        public const string ErrorMessage = "Token signature validation has failed";

        public TokenSignatureValidationException() : base(ErrorMessage)
        {
        }

        public TokenSignatureValidationException(Exception innerException) : base(ErrorMessage, innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected TokenSignatureValidationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
