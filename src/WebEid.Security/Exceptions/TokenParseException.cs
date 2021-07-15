namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when authentication token parsing fails.
    /// </summary>
    [Serializable]
    public class TokenParseException : TokenValidationException
    {
        public TokenParseException(string message) : base(message)
        {
        }
        public TokenParseException(Exception innerException) : base("Error parsing token", innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected TokenParseException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
