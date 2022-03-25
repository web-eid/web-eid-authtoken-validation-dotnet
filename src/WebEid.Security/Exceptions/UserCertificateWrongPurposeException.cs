namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the user certificate purpose is not client authentication.
    /// </summary>
    [Serializable]
    public class UserCertificateWrongPurposeException : AuthTokenException
    {
        public UserCertificateWrongPurposeException() : base("User certificate is not meant to be used as an authentication certificate")
        {
        }

        [ExcludeFromCodeCoverage]
        protected UserCertificateWrongPurposeException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
