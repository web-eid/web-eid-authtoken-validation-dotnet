namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when authentication token signature validation fails.
    /// </summary>
    [Serializable]
    public class AuthTokenSignatureValidationException : AuthTokenException
    {
        public const string ErrorMessage = "Token signature validation has failed";

        public AuthTokenSignatureValidationException() : base(ErrorMessage)
        {
        }

        public AuthTokenSignatureValidationException(Exception innerException) : base(ErrorMessage, innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected AuthTokenSignatureValidationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
