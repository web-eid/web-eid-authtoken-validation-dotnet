namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the authentication token has expired.
    /// </summary>
    [Serializable]
    public class TokenExpiredException : TokenValidationException
    {

        public TokenExpiredException(Exception innerException) : base("Token has expired", innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected TokenExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
