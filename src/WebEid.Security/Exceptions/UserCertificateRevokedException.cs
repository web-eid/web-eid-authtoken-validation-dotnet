namespace WebEid.Security.Exceptions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.Serialization;

    /// <summary>
    /// Thrown when the user certificate has been revoked.
    /// </summary>
    [Serializable]
    public class UserCertificateRevokedException : TokenValidationException
    {
        public UserCertificateRevokedException() : base("User certificate has been revoked")
        {
        }

        public UserCertificateRevokedException(string message) : base($"User certificate has been revoked: {message}")
        {
        }

        [ExcludeFromCodeCoverage]
        protected UserCertificateRevokedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }
}
