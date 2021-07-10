namespace WebEID.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the user certificate valid until date is in the past.
    /// </summary>
    [Serializable]
    public class UserCertificateExpiredException : TokenValidationException
    {
        public UserCertificateExpiredException() : this(null)
        {
        }

        public UserCertificateExpiredException(Exception innerException) : base("User certificate has expired", innerException)
        {
        }

        protected UserCertificateExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
