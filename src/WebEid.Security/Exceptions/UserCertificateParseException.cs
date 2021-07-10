namespace WebEID.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when user certificate parsing fails.
    /// </summary>
    [Serializable]
    public class UserCertificateParseException : TokenValidationException
    {
        public UserCertificateParseException() : this(null)
        {
        }

        public UserCertificateParseException(Exception innerException) : base("Error parsing certificate", innerException)
        {
        }

        protected UserCertificateParseException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
