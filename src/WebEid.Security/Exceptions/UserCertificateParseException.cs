namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when user certificate parsing fails.
    /// </summary>
    [Serializable]
    public class UserCertificateParseException : TokenValidationException
    {
        public UserCertificateParseException(Exception innerException) : base("Error parsing certificate", innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected UserCertificateParseException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
