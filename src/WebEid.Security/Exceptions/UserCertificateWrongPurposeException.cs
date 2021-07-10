namespace WebEID.Security.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the user certificate purpose is not client authentication.
    /// </summary>
    [Serializable]
    public class UserCertificateWrongPurposeException : TokenValidationException
    {
        public UserCertificateWrongPurposeException() : this(null)
        {
        }

        public UserCertificateWrongPurposeException(Exception innerException) : base("User certificate is not meant to be used as an authentication certificate", innerException)
        {
        }

        protected UserCertificateWrongPurposeException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
