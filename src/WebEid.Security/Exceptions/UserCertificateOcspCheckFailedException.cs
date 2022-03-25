namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when user certificate revocation check with OCSP fails.
    /// </summary>
    [Serializable]
    public class UserCertificateOcspCheckFailedException : AuthTokenException
    {
        public UserCertificateOcspCheckFailedException(Exception innerException) : base(
            "User certificate revocation check has failed",
            innerException)
        {
        }

        public UserCertificateOcspCheckFailedException(string message) : base(
            $"User certificate revocation check has failed: {message}")
        {
        }

        [ExcludeFromCodeCoverage]
        protected UserCertificateOcspCheckFailedException(SerializationInfo info, StreamingContext context) :
            base(info, context)
        {
        }
    }
}
