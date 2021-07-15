namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when user certificate revocation check with OCSP fails.
    /// </summary>
    [Serializable]
    public class UserCertificateRevocationCheckFailedException : TokenValidationException
    {
        public UserCertificateRevocationCheckFailedException(string message) : base(
            $"User certificate revocation check has failed: {message}")
        {
        }

        public UserCertificateRevocationCheckFailedException(Exception innerException) : base(
            "User certificate revocation check has failed",
            innerException)
        {
        }

        [ExcludeFromCodeCoverage]
        protected UserCertificateRevocationCheckFailedException(SerializationInfo info, StreamingContext context) :
            base(info, context)
        {
        }
    }
}
