namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the user certificate purpose field is missing or empty.
    /// </summary>
    [Serializable]
    public class UserCertificateMissingPurposeException : TokenValidationException
    {
        public UserCertificateMissingPurposeException() : this(null)
        {
        }

        public UserCertificateMissingPurposeException(Exception innerException) : base("User certificate purpose is missing", innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected UserCertificateMissingPurposeException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
