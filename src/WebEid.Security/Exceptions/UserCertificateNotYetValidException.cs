namespace WebEID.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the user certificate valid from date is in the future.
    /// </summary>
    [Serializable]
    public class UserCertificateNotYetValidException : TokenValidationException
    {
        public UserCertificateNotYetValidException() : this(null)
        {
        }

        public UserCertificateNotYetValidException(Exception innerException) : base("User certificate is not yet valid", innerException)
        {
        }

        protected UserCertificateNotYetValidException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
