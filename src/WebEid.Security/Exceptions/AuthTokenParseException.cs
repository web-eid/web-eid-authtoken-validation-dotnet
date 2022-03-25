namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when authentication token parsing fails.
    /// </summary>
    [Serializable]
    public class AuthTokenParseException : AuthTokenException
    {
        public AuthTokenParseException(string message) : base(message)
        {
        }

        public AuthTokenParseException(Exception innerException) : this("Error parsing token", innerException)
        {
        }

        public AuthTokenParseException(string message, Exception innerException) : base(message, innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected AuthTokenParseException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
